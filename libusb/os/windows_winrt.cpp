/*
 * winrt backend for libusb 1.0
 * Copyright © 2025 James Smith <jmsmith86@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "libusbi.h"
#include "windows_winrt.hpp"

#include <unordered_map>
#include <string>
#include <sstream>
#include <iomanip>
#include <functional>
#include <future>
#include <unordered_set>

#include <winrt/base.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Devices.Usb.h>
#include <winrt/Windows.Devices.Enumeration.h>
#include <winrt/Windows.Storage.Streams.h>

using namespace winrt;
using namespace winrt::Windows::Devices::Enumeration;
using namespace winrt::Windows::Foundation::Collections;
using namespace winrt::Windows::Devices::Usb;
using namespace winrt::Windows::Storage;

// The timeout used for all winrt async operations that need to be blocked on
static constexpr const uint64_t WINRT_STANDARD_TIMEOUT_MS = 5000;

// Constants needed to parse bmRequestType
static constexpr const uint8_t WINRT_BM_REQUEST_DIR_MASK = 0x80;
static constexpr const uint8_t WINRT_BM_REQUEST_TYPE_MASK = 0x60;
static constexpr const uint8_t WINRT_BM_REQUEST_TYPE_SHIFT = 5;
static constexpr const uint8_t WINRT_BM_REQUEST_RECIPIENT_MASK = 0x1F;

// Conversion macros
#define IS_BM_REQUEST_IN(bmRequestType) ((bmRequestType & WINRT_BM_REQUEST_DIR_MASK) != 0)
#define IS_IN_ENDPOINT(ep) ((ep & LIBUSB_ENDPOINT_DIR_MASK) != 0)
#define BM_REQUEST_TO_WINRT_DIR(bmRequestType) (IS_BM_REQUEST_IN(bmRequestType) ? UsbTransferDirection::In : UsbTransferDirection::Out)
#define BM_REQUEST_TO_WINRT_TRANSFER_TYPE(bmRequestType) (static_cast<UsbControlTransferType>((bmRequestType& WINRT_BM_REQUEST_TYPE_MASK) >> WINRT_BM_REQUEST_TYPE_SHIFT))
#define BM_REQUEST_TO_WINRT_RECIPIENT(bmRequestType) (static_cast<UsbControlRecipient>(bmRequestType & WINRT_BM_REQUEST_RECIPIENT_MASK))

// Forward declarations of static functions
static int winrt_init(libusb_context *ctx);
static void winrt_exit(libusb_context *ctx);
static int winrt_get_device_list(libusb_context *ctx, struct discovered_devs **_discdevs);
static int winrt_get_device_string(
    libusb_device *dev,
    enum libusb_device_string_type string_type,
    char *data,
    int length
);
static int winrt_open(libusb_device_handle* dev_handle);
static void winrt_close(libusb_device_handle *dev_handle);
static int winrt_request_descriptors(libusb_device *dev);
static int winrt_get_config_descriptor_by_value(
    libusb_device *dev,
    uint8_t bConfigurationValue,
    void **buffer
);
static int winrt_request_active_config(libusb_device *dev);
static int winrt_get_active_config_descriptor(libusb_device *dev, void *buffer, size_t len);
static int winrt_get_config_descriptor(libusb_device *dev, uint8_t config_index, void *buffer, size_t len);
static int winrt_get_configuration(libusb_device_handle *dev_handle, uint8_t *config);
static int winrt_set_configuration(libusb_device_handle *dev_handle, int config);
static void winrt_handle_interrupt(
    libusb_device_handle *dev_handle,
    uint8_t epNum,
    winrt::Windows::Storage::Streams::IBuffer data
);
static int winrt_claim_interface(libusb_device_handle *dev_handle, uint8_t iface);
static int winrt_release_interface(libusb_device_handle *dev_handle, uint8_t iface);
static int winrt_set_interface_altsetting(libusb_device_handle *dev_handle, uint8_t iface, uint8_t altsetting);
static int winrt_clear_halt(libusb_device_handle *dev_handle, unsigned char endpoint);
static int winrt_reset_device(libusb_device_handle *dev_handle);
static void winrt_destroy_device(libusb_device *dev);
static int winrt_submit_control_transfer(usbi_transfer *itransfer);
static int winrt_submit_bulk_transfer(usbi_transfer *itransfer);
static int winrt_submit_interrupt_transfer(usbi_transfer *itransfer);
static int winrt_submit_transfer(usbi_transfer *itransfer);
static int winrt_pop_transfer_from_queue(usbi_transfer *itransfer, winrt_transfer_queue& queue);
static int winrt_pop_transfer(usbi_transfer *itransfer);
static void winrt_transfer_completed(usbi_transfer *itransfer, libusb_transfer_status status, bool signal = true);
static int winrt_handle_transfer_completion(usbi_transfer *itransfer);
static int winrt_cancel_transfer_from_queue(usbi_transfer *itransfer, winrt_transfer_queue& queue);
static int winrt_cancel_transfer(usbi_transfer *itransfer);

//! Convert 16-bit little endian array of bytes to uint16 value
//! @param[in] p Array of 2 bytes
//! @return the equivalent uint16 value
static inline uint16_t ReadLittleEndian16(const uint8_t p[2])
{
    return (uint16_t)((uint16_t)p[1] << 8 | (uint16_t)p[0]);
}

//! Converts a container GUID to an arbitrary but unique session ID
//! @param[in] ctx Context to use for the lookup
//! @param[in] container_id The container ID to convert
//! @return an arbitrary but unique session ID linked to the given container ID
static unsigned long container_id_to_session_id(libusb_context *ctx, const guid& container_id)
{
    winrt_context_priv *priv = static_cast<winrt_context_priv*>(usbi_get_context_priv(ctx));

    std::lock_guard<std::mutex> lock(priv->container_id_to_session_id_mutex);

    auto iter = priv->container_id_to_session_id_map.find(container_id);
    if (iter == priv->container_id_to_session_id_map.end())
    {
        unsigned long new_session_id = ++priv->last_session_id;
        priv->container_id_to_session_id_map.insert(std::make_pair(container_id, new_session_id));
        return new_session_id;
    }

    return iter->second;
}

//! Safely retrieves the result of an winrt async get()
//! @tparam T The result type to be retrieved
//! @param[in] ctx libusb context, used for logging purposes
//! @param[in] getFn A function which both creates an async operation and calls get()
//! @param[in] defaultVal The default value to return on exception
//! @return The retrieved value
template <typename T>
static T winrt_async_get(libusb_context *ctx, const std::function<T()>& getFn, const T& defaultVal)
{
    try
    {
        // Synopsis:
        // winrt uses the UI message pump when current thread is UI thread. This will usually mean that the asynchronous
        // operation will rely on messaging. Blocking while on this thread would then cause a deadlock because messages
        // won't be handled. To avoid that particular case, the async operation will be executed in its own thread so
        // winrt-internal operations don't rely on the message pump.
        if (winrt::impl::is_sta_thread())
        {
            std::future<T> task = std::async(std::launch::async, getFn);
            return task.get();
        }
        else
        {
            return getFn();
        }
    }
    catch(const winrt::hresult_error& e)
    {
        // Execution error occurred
        usbi_warn(ctx, "winrt_async_get failed with exception: %s", winrt::to_string(e.message()).c_str());
        return defaultVal;
    }
}

//! Safely retrieves the result of an winrt async get(), returning nullptr on exception
//! @tparam T The result type to be retrieved
//! @param[in] ctx libusb context, used for logging purposes
//! @param[in] getFn A function which both creates an async operation and calls get()
//! @return The retrieved value
template <typename T>
static T winrt_async_get(libusb_context *ctx, const std::function<T()>& getFn)
{
    return winrt_async_get<T>(ctx, getFn, nullptr);
}

template <typename T>
struct winrt_handle_async_data
{
    //! libusb context, used for logging purposes
    libusb_context *ctx;
    //! The function which generates a IAsyncOperation<T>
    std::function<winrt::Windows::Foundation::IAsyncOperation<T>()> asyncFn;
    //! Duration to wait before timeout (statusOut will be set to Canceled on timeout)
    const winrt::Windows::Foundation::TimeSpan& timeout = std::chrono::milliseconds(WINRT_STANDARD_TIMEOUT_MS);
};

//! Safely handles a winrt async operation, blocking until complete and returning the result
//! @tparam T The result type to be retrieved
//! @param[out] statusOut The status of the operation
//! @param[in] data Async transfer data
//! @param[in] defaultVal The default value to return on exception
//! @return the resulting value of the operation or nullptr if operation fails
template <typename T>
static T winrt_handle_async(
    winrt::Windows::Foundation::AsyncStatus& statusOut,
    const winrt_handle_async_data<T>& data,
    const T& defaultVal
)
{
    statusOut = winrt::Windows::Foundation::AsyncStatus::Started;
    return winrt_async_get<T>(
        data.ctx,
        [&]() -> T
        {
            winrt::Windows::Foundation::IAsyncOperation<T> asyncOp;
            try
            {
                asyncOp = data.asyncFn();
                statusOut = asyncOp.wait_for(data.timeout);
                if (statusOut != winrt::Windows::Foundation::AsyncStatus::Completed)
                {
                    statusOut = winrt::Windows::Foundation::AsyncStatus::Canceled;
                    asyncOp.Cancel();
                    asyncOp.get();
                    return defaultVal;
                }
                return asyncOp.get();

            }
            catch(const winrt::hresult_error& e)
            {
                // Execution error occurred
                usbi_warn(data.ctx, "winrt_handle_async failed with exception: %s", winrt::to_string(e.message()).c_str());
                statusOut = winrt::Windows::Foundation::AsyncStatus::Error;
                if (asyncOp)
                {
                    asyncOp.Cancel();
                    asyncOp.get();
                }
                return defaultVal;
            }
        },
        defaultVal
    );
}

//! Safely handles a winrt async operation, blocking until complete and returning the result
//! @tparam T The result type to be retrieved
//! @param[out] statusOut The status of the operation
//! @param[in] data Async transfer data
//! @return the resulting value of the operation or nullptr if operation fails
template <typename T>
static T winrt_handle_async(
    winrt::Windows::Foundation::AsyncStatus& statusOut,
    const winrt_handle_async_data<T>& data
)
{
    return winrt_handle_async<T>(statusOut, data, nullptr);
}

//! Safely handles a winrt async operation, blocking until complete and returning the result
//! @tparam T The result type to be retrieved
//! @param[in] ctx libusb context, used for logging purposes
//! @param[in] asyncFn The function which generates a IAsyncOperation<T>
//! @param[in] timeout Duration to wait before timeout (statusOut will be set to Canceled on timeout)
//! @return the resulting value of the operation or nullptr if operation fails
template <typename T>
static T winrt_handle_async(const winrt_handle_async_data<T>& data)
{
    winrt::Windows::Foundation::AsyncStatus status;
    return winrt_handle_async<T>(status, data);
}

//! Safely handles a winrt async action operation, blocking until complete and returning the result
//! @param[in] ctx libusb context, used for logging purposes
//! @param[in] asyncActionFn The function which generates a IAsyncAction
//! @param[in] timeout Duration to wait before timeout (return value will be set to Canceled on timeout)
//! @return the status of the action
winrt::Windows::Foundation::AsyncStatus winrt_handle_async_action(
    libusb_context *ctx,
    const std::function<winrt::Windows::Foundation::IAsyncAction()>& asyncActionFn,
    const winrt::Windows::Foundation::TimeSpan& timeout = std::chrono::milliseconds(WINRT_STANDARD_TIMEOUT_MS)
)
{
    return winrt_async_get<winrt::Windows::Foundation::AsyncStatus>(
        ctx,
        [&]()
        {
            winrt::Windows::Foundation::IAsyncAction asyncOp;
            winrt::Windows::Foundation::AsyncStatus status;
            try
            {
                asyncOp = asyncActionFn();
                status = asyncOp.wait_for(timeout);
                if (status != winrt::Windows::Foundation::AsyncStatus::Completed)
                {
                    status = winrt::Windows::Foundation::AsyncStatus::Canceled;
                    asyncOp.Cancel();
                    asyncOp.get();
                }
                return status;

            }
            catch(const winrt::hresult_error&)
            {
                status = winrt::Windows::Foundation::AsyncStatus::Error;
                if (asyncOp)
                {
                    asyncOp.Cancel();
                    asyncOp.get();
                }
                return status;
            }
        },
        winrt::Windows::Foundation::AsyncStatus::Error
    );
}

//! Executes a control transfer IN, blocking until complete, timeout, or error
//! @param[in] ctx The libusb context executing this
//! @param[in] dev winrt UsbDevice to execute the control transfer on
//! @param[in] setupPacket Control transfer header data
//! @param[out] dat The retrieved data
//! @return a libusb error code if negative or size if positive
static int winrt_send_control_transfer_in(
    libusb_context *ctx,
    winrt::Windows::Devices::Usb::UsbDevice& dev,
    const UsbSetupPacket& setupPacket,
    winrt::array_view<uint8_t> dat
)
{
    if (!dev)
    {
        return LIBUSB_ERROR_NO_DEVICE;
    }

    if (setupPacket.RequestType().Direction() != UsbTransferDirection::In)
    {
        usbi_err(ctx, "winrt_send_control_transfer_in received setup packet with OUT direction (internal error)");
        return LIBUSB_ERROR_OTHER;
    }

    winrt::Windows::Foundation::AsyncStatus status;
    auto outputBuffer = Streams::Buffer(setupPacket.Length());
    auto buf = winrt_handle_async<Streams::IBuffer>(
        status,
        {
            ctx,
            [&]()
            {
                return dev.SendControlInTransferAsync(setupPacket, outputBuffer);
            }
        }
    );

    if (status == winrt::Windows::Foundation::AsyncStatus::Canceled)
    {
        usbi_warn(ctx, "winrt_send_control_transfer_in timeout");
        return LIBUSB_ERROR_TIMEOUT;
    }
    else if (status != winrt::Windows::Foundation::AsyncStatus::Completed || !buf)
    {
        usbi_warn(ctx, "winrt_send_control_transfer_in failed");
        return LIBUSB_ERROR_IO;
    }

    int len = 0;
    auto dataReader = winrt::Windows::Storage::Streams::DataReader::FromBuffer(buf);
    for (uint8_t& b : dat)
    {
        if (dataReader.UnconsumedBufferLength() <= 0)
        {
            break;
        }

        b = dataReader.ReadByte();
        ++len;
    }

    return len;
}

//! Executes a control transfer OUT, blocking until complete, timeout, or error
//! @param[in] ctx The libusb context executing this
//! @param[in] dev winrt UsbDevice to execute the control transfer on
//! @param[in] setupPacket Control transfer header data
//! @param[in] dat The data to send
//! @return a libusb error code
static int winrt_send_control_transfer_out(
    libusb_context *ctx,
    winrt::Windows::Devices::Usb::UsbDevice& dev,
    const UsbSetupPacket& setupPacket,
    winrt::array_view<uint8_t> dat = {}
)
{
    if (!dev)
    {
        return LIBUSB_ERROR_NO_DEVICE;
    }

    if (setupPacket.RequestType().Direction() != UsbTransferDirection::Out)
    {
        usbi_err(ctx, "winrt_send_control_transfer_out received setup packet with IN direction (internal error)");
        return LIBUSB_ERROR_OTHER;
    }

    winrt::Windows::Foundation::AsyncStatus status;
    auto dataWriter = Streams::DataWriter();
    dataWriter.WriteBytes(dat);
    auto inputBuffer = dataWriter.DetachBuffer();
    uint32_t result = winrt_handle_async<uint32_t>(
        status,
        {
            ctx,
            [&]()
            {
                return dev.SendControlOutTransferAsync(setupPacket, inputBuffer);
            }
        },
        0
    );

    if (status == winrt::Windows::Foundation::AsyncStatus::Canceled)
    {
        usbi_warn(ctx, "winrt_send_control_transfer_out timeout");
        return LIBUSB_ERROR_TIMEOUT;
    }
    else if (status != winrt::Windows::Foundation::AsyncStatus::Completed || result < dat.size())
    {
        usbi_warn(ctx, "winrt_send_control_transfer_out failed");
        return LIBUSB_ERROR_IO;
    }

    return LIBUSB_SUCCESS;
}

static int winrt_init(libusb_context *ctx)
{
    // Use placement new to properly construct the private structure
    winrt_context_priv *priv = new (usbi_get_context_priv(ctx)) winrt_context_priv();
    static_cast<void>(priv);
    return LIBUSB_SUCCESS;
}

static void winrt_exit(libusb_context *ctx)
{
    // Explicitly call destructor
    winrt_context_priv *priv = static_cast<winrt_context_priv*>(usbi_get_context_priv(ctx));
    priv->~winrt_context_priv();
}

static int winrt_get_device_list(libusb_context *ctx, struct discovered_devs **_discdevs)
{
    // Find all connected USB devices
    auto additionalProperties = winrt::single_threaded_vector<winrt::hstring>();
    additionalProperties.Append(L"System.Devices.ContainerId");
    additionalProperties.Append(L"System.Devices.DeviceInstanceId");
    winrt::Windows::Foundation::AsyncStatus status = winrt::Windows::Foundation::AsyncStatus::Started;
    DeviceInformationCollection deviceInfos = winrt_handle_async<DeviceInformationCollection>(
        status,
        {
            ctx,
            [&]()
            {
                return DeviceInformation::FindAllAsync(
                    L"System.Devices.InterfaceEnabled:=System.StructuredQueryType.Boolean#True"
                    L" AND (System.Devices.DeviceInstanceId:~<\"USB\\\" OR System.Devices.DeviceInstanceId:~<\"HID\\\")",
                    additionalProperties,
                    DeviceInformationKind::DeviceInterface
                );
            }
        }
    );

    if (status == winrt::Windows::Foundation::AsyncStatus::Canceled)
    {
        usbi_warn(ctx, "Timeout occurred querying for USB devices");
        return LIBUSB_ERROR_TIMEOUT;
    }
    else if (status != winrt::Windows::Foundation::AsyncStatus::Completed)
    {
        usbi_warn(ctx, "Error occurred while querying for USB devices");
        return LIBUSB_ERROR_IO;
    }

    std::unordered_set<guid> foundContainerIds;

    for (const DeviceInformation& deviceInfo : deviceInfos)
    {
        guid containerId;
        deviceInfo.Properties().Lookup(L"System.Devices.ContainerId").as(containerId);
        // Note: container ID of {00000000-0000-0000-ffff-ffffffffffff} is a system container ID
        //       container ID of {00000000-0000-0000-0000-000000000000} is invalid
        if (
            foundContainerIds.count(containerId) == 0 &&
            containerId != guid(L"{00000000-0000-0000-ffff-ffffffffffff}") &&
            containerId != guid(L"{00000000-0000-0000-0000-000000000000}")
        )
        {
            // New container ID
            unsigned long session_id = container_id_to_session_id(ctx, containerId);
            libusb_device *dev = usbi_get_device_by_session_id(ctx, session_id);

            if (dev == NULL) {
                dev = usbi_alloc_device(ctx, session_id);
                if (dev == NULL)
                {
                    usbi_err(ctx, "Failed to allocate memory for device");
                    return LIBUSB_ERROR_NO_MEM;
                }

                // These values are not provided by winrt, so they are faked
                dev->bus_number = (session_id >> 8) & 0xFF;
                dev->device_address = session_id & 0xFF;
                dev->speed = libusb_speed::LIBUSB_SPEED_UNKNOWN;

                // Use placement new to properly construct the private structure
                winrt_device_priv *dpriv = new (usbi_get_device_priv(dev)) winrt_device_priv();
                // Save the container ID to device priv data for later use
                dpriv->container_id = winrt::to_hstring(containerId);

                UsbDevice winrtDev = winrt_handle_async<UsbDevice>(
                    {
                        ctx,
                        [&deviceInfo]()
                        {
                            return UsbDevice::FromIdAsync(deviceInfo.Id());
                        }
                    }
                );

                if (!winrtDev)
                {
                    // Only 1 application may hold this device at one time, so it is likely in use - can't be parsed
                    libusb_unref_device(dev);
                    continue;
                }

                // winrtDev.DeviceDescriptor() does not contain all data of the device descriptor.
                // Instead, send control transfer to get device descriptor.
                auto setupPacket = UsbSetupPacket();
                setupPacket.RequestType().Direction(UsbTransferDirection::In);
                setupPacket.RequestType().ControlTransferType(UsbControlTransferType::Standard);
                setupPacket.RequestType().Recipient(UsbControlRecipient::Device);
                setupPacket.Request(LIBUSB_REQUEST_GET_DESCRIPTOR);
                setupPacket.Value((LIBUSB_DT_DEVICE << 8) | 0); // Device descriptor, index 0
                setupPacket.Index(0);
                setupPacket.Length(LIBUSB_DT_DEVICE_SIZE);

                std::vector<uint8_t> data(LIBUSB_DT_DEVICE_SIZE);
                int r = winrt_send_control_transfer_in(ctx, winrtDev, setupPacket, data);

                if (r < 0)
                {
                    libusb_unref_device(dev);
                    continue;
                }

                // Copy the raw descriptor data from buffer to device descriptor
                memcpy(&dev->device_descriptor, data.data(), LIBUSB_DT_DEVICE_SIZE);
                usbi_localize_device_descriptor(&dev->device_descriptor);

                int err = usbi_sanitize_device(dev);
                if (err)
                {
                    libusb_unref_device(dev);
                    return err;
                }
            }

            if (discovered_devs_append(*_discdevs, dev) == NULL)
            {
                usbi_err(ctx, "Failed to allocate memory for device listing");
                libusb_unref_device(dev);
                return LIBUSB_ERROR_NO_MEM;
            }

            libusb_unref_device(dev);

            foundContainerIds.insert(containerId);
        }
    }

    return LIBUSB_SUCCESS;
}

static int winrt_get_device_string(
    libusb_device *dev,
    enum libusb_device_string_type string_type,
    char *data,
    int length
)
{
    winrt_device_priv *priv = static_cast<winrt_device_priv*>(usbi_get_device_priv(dev));

    if ((NULL != data) && (length > 0))
    {
        *data = 0;
    }

    uint8_t string_descriptor_idx;
    switch (string_type)
    {
        case LIBUSB_DEVICE_STRING_MANUFACTURER: string_descriptor_idx = dev->device_descriptor.iManufacturer; break;
        case LIBUSB_DEVICE_STRING_PRODUCT: string_descriptor_idx = dev->device_descriptor.iProduct; break;
        case LIBUSB_DEVICE_STRING_SERIAL_NUMBER: string_descriptor_idx = dev->device_descriptor.iSerialNumber; break;
        default: return LIBUSB_ERROR_INVALID_PARAM;
    }

    if (0 == string_descriptor_idx)
    {
        return 0;
    }

    // Get the string
    uint8_t strBuf[255];
    auto setupPacket = UsbSetupPacket();
    setupPacket.RequestType().Direction(UsbTransferDirection::In);
    setupPacket.RequestType().ControlTransferType(UsbControlTransferType::Standard);
    setupPacket.RequestType().Recipient(UsbControlRecipient::Device);
    setupPacket.Request(LIBUSB_REQUEST_GET_DESCRIPTOR);
    setupPacket.Value((LIBUSB_DT_STRING << 8) | string_descriptor_idx);
    setupPacket.Index(0);
    setupPacket.Length(sizeof(strBuf));

    std::vector<std::uint8_t> dataVec(sizeof(strBuf));
    int r = winrt_send_control_transfer_in(
        dev->ctx,
        priv->default_device.device,
        setupPacket,
        dataVec
    );

    if (r < 0)
    {
        return r;
    }

    std::size_t rcvLen = static_cast<std::size_t>(r);
    if (rcvLen > sizeof(strBuf))
    {
        rcvLen = sizeof(strBuf);
    }
    memcpy(strBuf, dataVec.data(), rcvLen);

    if (rcvLen < 2 || strBuf[0] < 2 || strBuf[1] != LIBUSB_DT_STRING)
    {
        return LIBUSB_ERROR_IO;
    }

    // String descriptors contain UTF-16LE encoded strings
    // The first two bytes are bLength and bDescriptorType
    uint8_t bLength = strBuf[0];
    if (bLength > rcvLen)
    {
        bLength = static_cast<uint8_t>(rcvLen);
    }

    // Calculate the number of UTF-16 characters (excluding the header)
    int utf16_len = (bLength - 2) / 2;
    if (utf16_len <= 0)
    {
        return 0;
    }

    // Convert UTF-16LE to UTF-8
    const uint16_t* utf16_str = reinterpret_cast<const uint16_t*>(&strBuf[2]);
    std::wstring wide_str;
    wide_str.reserve(utf16_len);

    for (int i = 0; i < utf16_len; ++i)
    {
        wide_str.push_back(ReadLittleEndian16(reinterpret_cast<const uint8_t*>(&utf16_str[i])));
    }

    // Convert to UTF-8 using WinRT
    hstring hstr(wide_str);
    std::string utf8_str = winrt::to_string(hstr);

    // Copy to output buffer
    int copy_len = static_cast<int>(utf8_str.length());
    if (copy_len >= length)
    {
        copy_len = length - 1;
    }

    if (copy_len > 0)
    {
        memcpy(data, utf8_str.c_str(), copy_len);
    }
    data[copy_len] = '\0';

    return copy_len;
}

static int winrt_open(libusb_device_handle* dev_handle)
{
    // Use placement new to properly construct the private structure
    winrt_device_handle_priv *handle_priv = new (usbi_get_device_handle_priv(dev_handle)) winrt_device_handle_priv();
    static_cast<void>(handle_priv);
    winrt_device_priv *priv = static_cast<winrt_device_priv*>(usbi_get_device_priv(dev_handle->dev));

    usbi_dbg(dev_handle->dev->ctx, "Finding devices with container ID %s", priv->container_id.c_str());

    // One DeviceInterface must be open to perform any device operation
    auto additionalProperties = winrt::single_threaded_vector<winrt::hstring>();
    additionalProperties.Append(L"System.Devices.DeviceInstanceId");
    winrt::Windows::Foundation::AsyncStatus status = winrt::Windows::Foundation::AsyncStatus::Started;
    DeviceInformationCollection deviceInfos = winrt_handle_async<DeviceInformationCollection>(
        status,
        {
            dev_handle->dev->ctx,
            [&]()
            {
                return DeviceInformation::FindAllAsync(
                    L"System.Devices.ContainerId:=\"" + priv->container_id + L"\"",
                    additionalProperties,
                    DeviceInformationKind::DeviceInterface
                );
            }
        }
    );

    if (status == winrt::Windows::Foundation::AsyncStatus::Canceled)
    {
        usbi_warn(dev_handle->dev->ctx, "Timeout occurred while querying for USB device");
        return LIBUSB_ERROR_TIMEOUT;
    }
    else if (status != winrt::Windows::Foundation::AsyncStatus::Completed)
    {
        usbi_warn(dev_handle->dev->ctx, "Error occurred while querying for USB device");
        return LIBUSB_ERROR_IO;
    }
    else if (deviceInfos.Size() == 0)
    {
        return LIBUSB_ERROR_NOT_FOUND;
    }

    bool commFail = false;
    for (const DeviceInformation& deviceInfo : deviceInfos)
    {
        UsbDevice winrtDev = winrt_handle_async<UsbDevice>(
            {
                dev_handle->dev->ctx,
                [&deviceInfo]()
                {
                    return UsbDevice::FromIdAsync(deviceInfo.Id());
                }
            }
        );

        if (winrtDev)
        {
            priv->default_device.device = winrtDev;
            priv->default_device.device_id = deviceInfo.Id();
            priv->default_device.device_path =
                deviceInfo.Properties().Lookup(L"System.Devices.DeviceInstanceId").as<hstring>();

            return LIBUSB_SUCCESS;
        }
    }

    return commFail ? LIBUSB_ERROR_IO : LIBUSB_ERROR_BUSY;
}

static void winrt_close(libusb_device_handle *dev_handle)
{
    winrt_device_handle_priv *handle_priv = static_cast<winrt_device_handle_priv*>(usbi_get_device_handle_priv(dev_handle));
    // Ensure that interface objects are properly released
    while (!handle_priv->interfaces.empty())
    {
        winrt_release_interface(dev_handle, handle_priv->interfaces.begin()->first);
    }
    // Manually call destructor
    handle_priv->~winrt_device_handle_priv();
}

static int winrt_request_descriptors(libusb_device *dev)
{
    winrt_device_priv *priv = static_cast<winrt_device_priv*>(usbi_get_device_priv(dev));

    if (!priv->config_descriptors.empty())
    {
        // Already initialized
        return LIBUSB_SUCCESS;
    }

    priv->config_descriptors.resize(dev->device_descriptor.bNumConfigurations);
    for (uint8_t i = 0; i < dev->device_descriptor.bNumConfigurations; ++i)
    {
        // The data within winrtDev.Configuration().Descriptors() is often incorrect for some reason.
        // The best bet is to simply send a control transfer.
        auto setupPacket = UsbSetupPacket();
        setupPacket.RequestType().Direction(UsbTransferDirection::In);
        setupPacket.RequestType().ControlTransferType(UsbControlTransferType::Standard);
        setupPacket.RequestType().Recipient(UsbControlRecipient::Device);
        setupPacket.Request(LIBUSB_REQUEST_GET_DESCRIPTOR);
        setupPacket.Value((LIBUSB_DT_CONFIG << 8) | i); // configuration descriptor with index
        setupPacket.Index(0);
        setupPacket.Length(LIBUSB_DT_CONFIG_SIZE);

        priv->config_descriptors[i].resize(LIBUSB_DT_CONFIG_SIZE);
        int r = winrt_send_control_transfer_in(
            dev->ctx,
            priv->default_device.device,
            setupPacket,
            priv->config_descriptors[i]
        );

        if (r < 0)
        {
            usbi_warn(
                dev->ctx,
                "Failed to retrieve configuration descriptor header (%s) using device %s",
                libusb_error_name(r),
                priv->default_device.device_id.c_str()
            );

            // Clear so we know this structure is still invalid
            priv->config_descriptors.clear();

            return r;
        }

        // Get full length
        uint16_t realLen = ReadLittleEndian16(&priv->config_descriptors[i][2]);
        setupPacket.Length(realLen);
        priv->config_descriptors[i].resize(realLen);
        r = winrt_send_control_transfer_in(
            dev->ctx,
            priv->default_device.device,
            setupPacket,
            priv->config_descriptors[i]
        );

        if (r < 0)
        {
            usbi_warn(
                dev->ctx,
                "Failed to retrieve full configuration descriptor (%s) using device %s",
                libusb_error_name(r),
                priv->default_device.device_id.c_str()
            );

            // Clear so we know this structure is still invalid
            priv->config_descriptors.clear();

            return r;
        }
    }

    return LIBUSB_SUCCESS;
}

static int winrt_get_config_descriptor_by_value(
    libusb_device *dev,
    uint8_t bConfigurationValue,
    void **buffer
)
{
    winrt_device_priv *priv = static_cast<winrt_device_priv*>(usbi_get_device_priv(dev));

    int r = winrt_request_descriptors(dev);
    if (r != LIBUSB_SUCCESS)
    {
        return (r < 0) ? r : -1;
    }

    if (bConfigurationValue == 0 || static_cast<uint8_t>(bConfigurationValue - 1) >= priv->config_descriptors.size())
    {
        return -1;
    }

    *buffer = &priv->config_descriptors[bConfigurationValue - 1][0];
    return static_cast<int>(priv->config_descriptors[bConfigurationValue - 1].size());
}

static int winrt_request_active_config(libusb_device *dev)
{
    winrt_device_priv *priv = static_cast<winrt_device_priv*>(usbi_get_device_priv(dev));

    if (priv->active_config == 0)
    {
        // Get the active configuration number
        auto setupPacket = UsbSetupPacket();
        setupPacket.RequestType().Direction(UsbTransferDirection::In);
        setupPacket.RequestType().ControlTransferType(UsbControlTransferType::Standard);
        setupPacket.RequestType().Recipient(UsbControlRecipient::Device);
        setupPacket.Request(LIBUSB_REQUEST_GET_CONFIGURATION);
        setupPacket.Value(0);
        setupPacket.Index(0);
        setupPacket.Length(1);

        std::vector<uint8_t> activeConfigData(1);
        int r = winrt_send_control_transfer_in(dev->ctx, priv->default_device.device, setupPacket, activeConfigData);

        if (r < 0)
        {
            return r;
        }

        priv->active_config = activeConfigData[0];
    }

    return LIBUSB_SUCCESS;
}

static int winrt_get_active_config_descriptor(libusb_device *dev, void *buffer, size_t len)
{
    winrt_device_priv *priv = static_cast<winrt_device_priv*>(usbi_get_device_priv(dev));
    void *config_desc;

    int r = winrt_request_active_config(dev);
    if (r != LIBUSB_SUCCESS)
    {
        return r;
    }

    r = winrt_get_config_descriptor_by_value(dev, priv->active_config, &config_desc);
    if (r < 0)
    {
        return r;
    }

    len = MIN(len, (size_t)r);
    memcpy(buffer, config_desc, len);
    return (int)len;
}

static int winrt_get_config_descriptor(libusb_device *dev, uint8_t config_index, void *buffer, size_t len)
{
    winrt_device_priv *priv = static_cast<winrt_device_priv*>(usbi_get_device_priv(dev));

    int r = winrt_request_descriptors(dev);
    if (r != LIBUSB_SUCCESS)
    {
        return (r < 0) ? r : -1;
    }

    if (config_index >= priv->config_descriptors.size())
    {
        return -1;
    }

    const uint8_t *config_header = &priv->config_descriptors[config_index][0];
    const std::size_t totalLength = priv->config_descriptors[config_index].size();

    len = MIN(len, totalLength);
    memcpy(buffer, config_header, len);
    return (int)len;
}

static int winrt_get_configuration(libusb_device_handle *dev_handle, uint8_t *config)
{
    winrt_device_priv *priv = static_cast<winrt_device_priv*>(usbi_get_device_priv(dev_handle->dev));

    int r = winrt_request_active_config(dev_handle->dev);
    if (r != LIBUSB_SUCCESS)
    {
        return r;
    }

    *config = priv->active_config;
    return LIBUSB_SUCCESS;
}

static int winrt_set_configuration(libusb_device_handle *dev_handle, int config)
{
    winrt_device_priv *priv = static_cast<winrt_device_priv*>(usbi_get_device_priv(dev_handle->dev));

    int r = winrt_request_active_config(dev_handle->dev);
    if (r != LIBUSB_SUCCESS)
    {
        return r;
    }

    if (config == priv->active_config)
    {
        // Already the active configuration
        return LIBUSB_SUCCESS;
    }

    // Set the active configuration number
    // This will likely not succeed, but there is nothing else that can be attempted
    auto setupPacket = UsbSetupPacket();
    setupPacket.RequestType().Direction(UsbTransferDirection::Out);
    setupPacket.RequestType().ControlTransferType(UsbControlTransferType::Standard);
    setupPacket.RequestType().Recipient(UsbControlRecipient::Device);
    setupPacket.Request(LIBUSB_REQUEST_SET_CONFIGURATION);
    setupPacket.Value(config);
    setupPacket.Index(0);
    setupPacket.Length(0);

    r = winrt_send_control_transfer_out(dev_handle->dev->ctx, priv->default_device.device, setupPacket);

    if (r != LIBUSB_SUCCESS)
    {
        usbi_warn(dev_handle->dev->ctx, "Failed to set configuration to %i (%s)", config, libusb_error_name(r));
        return r;
    }

    return LIBUSB_SUCCESS;
}

static void winrt_handle_interrupt(
    libusb_device_handle *dev_handle,
    uint8_t epNum,
    winrt::Windows::Storage::Streams::IBuffer data
)
{
    winrt_device_handle_priv *handle_priv = static_cast<winrt_device_handle_priv*>(usbi_get_device_handle_priv(dev_handle));
    winrt_device_priv *priv = static_cast<winrt_device_priv*>(usbi_get_device_priv(dev_handle->dev));

    // Lock this function with the transfer mutex
    std::lock_guard<std::recursive_mutex> lock(priv->transfer_mutex);

    // Find the queue this data is destined for
    winrt_transfer_queue* queuePtr = nullptr;
    auto iter = handle_priv->transfers.find(epNum);
    if (iter != handle_priv->transfers.end())
    {
        queuePtr = &iter->second;
    }

    // If there is an active transfer, load this data into it
    if (queuePtr && queuePtr->active_transfer)
    {
        usbi_transfer* itransfer = queuePtr->active_transfer;

        libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
        libusb_transfer_status status = LIBUSB_TRANSFER_ERROR;
        if (data)
        {
            status = LIBUSB_TRANSFER_COMPLETED;
            auto dataReader = Streams::DataReader::FromBuffer(data);
            typename winrt::array_view<uint8_t>::size_type len = data.Length();
            if (transfer->length < 0)
            {
                len = 0;
            }
            else if (len > static_cast<typename winrt::array_view<uint8_t>::size_type>(transfer->length))
            {
                len = transfer->length;
            }
            dataReader.ReadBytes(winrt::array_view<uint8_t>(transfer->buffer, len));
            itransfer->transferred = data.Length();
        }

        winrt_transfer_completed(itransfer, status);
    }
}

static int winrt_claim_interface(libusb_device_handle *dev_handle, uint8_t iface)
{
    winrt_device_handle_priv *handle_priv = static_cast<winrt_device_handle_priv*>(usbi_get_device_handle_priv(dev_handle));
    winrt_device_priv *priv = static_cast<winrt_device_priv*>(usbi_get_device_priv(dev_handle->dev));

    // For any communication, the default_device must be set
    if (!priv->default_device.device)
    {
        return LIBUSB_ERROR_NO_DEVICE;
    }

    auto iter = handle_priv->interfaces.find(iface);
    if (iter != handle_priv->interfaces.end())
    {
        if (iter->second.device.device)
        {
            // Already claimed and valid
            return LIBUSB_SUCCESS;
        }
        else
        {
            // No longer valid, remove and retry
            handle_priv->interfaces.erase(iter);
        }
    }

    std::wstringstream ss;
    ss << std::setfill(L'0') << std::setw(2) << std::hex << static_cast<int>(iface);
    std::wstring ifaceStr = ss.str();

    auto additionalProperties = winrt::single_threaded_vector<winrt::hstring>();
    additionalProperties.Append(L"System.Devices.DeviceInstanceId");
    winrt::Windows::Foundation::AsyncStatus status = winrt::Windows::Foundation::AsyncStatus::Started;
    DeviceInformationCollection deviceInfos = winrt_handle_async<DeviceInformationCollection>(
        status,
        {
            dev_handle->dev->ctx,
            [&]()
            {
                // Looking for DeviceInstanceId which contains "MI_XX"
                return DeviceInformation::FindAllAsync(
                    L"System.Devices.ContainerId:=\"" + priv->container_id + L"\""
                    L" AND System.Devices.DeviceInstanceId:~~\"MI_" + ifaceStr + L"\"",
                    additionalProperties,
                    DeviceInformationKind::DeviceInterface
                );
            }
        }
    );

    if (status == winrt::Windows::Foundation::AsyncStatus::Canceled)
    {
        usbi_warn(dev_handle->dev->ctx, "Timeout occurred while querying for USB interface");
        return LIBUSB_ERROR_TIMEOUT;
    }
    else if (status != winrt::Windows::Foundation::AsyncStatus::Completed)
    {
        usbi_warn(dev_handle->dev->ctx, "Error occurred while querying for USB interface");
        return LIBUSB_ERROR_IO;
    }
    if (deviceInfos.Size() == 0)
    {
        return LIBUSB_ERROR_NOT_FOUND;
    }

    // There will usually only be 1 in the list unless the interface implements multiple DeviceInterfaceGUIDs.
    // Try connecting to each until one succeeds.
    for (const auto& deviceInfo : deviceInfos)
    {
        std::wstring id(deviceInfo.Id());
        UsbDevice winrtDev = nullptr;
        bool isDefaultDevice = false;

        if (id == priv->default_device.device_id)
        {
            winrtDev = priv->default_device.device;
            isDefaultDevice = true;
        }
        else
        {
            winrtDev = winrt_handle_async<UsbDevice>(
                {
                    dev_handle->dev->ctx,
                    [&deviceInfo]()
                    {
                        return UsbDevice::FromIdAsync(deviceInfo.Id());
                    }
                }
            );
        }

        if (winrtDev)
        {
            std::wstring path(deviceInfo.Properties().Lookup(L"System.Devices.DeviceInstanceId").as<hstring>());
            winrt_interface itfDef{winrt_device_data{winrtDev, id, path}};

            for (auto bulkEpIn: winrtDev.DefaultInterface().BulkInPipes())
            {
                itfDef.bulk_in_pipes.insert_or_assign(bulkEpIn.EndpointDescriptor().EndpointNumber() | LIBUSB_ENDPOINT_IN, std::move(bulkEpIn));
            }

            for (auto bulkEpOut: winrtDev.DefaultInterface().BulkOutPipes())
            {
                itfDef.bulk_out_pipes.insert_or_assign(bulkEpOut.EndpointDescriptor().EndpointNumber(), std::move(bulkEpOut));
            }

            for (auto intEpIn: winrtDev.DefaultInterface().InterruptInPipes())
            {
                const uint8_t epNum = intEpIn.EndpointDescriptor().EndpointNumber() | LIBUSB_ENDPOINT_IN;

                // Insert new interrupt data for this endpoint
                auto insertStatus = itfDef.interrupt_in_pipes.insert(std::make_pair(epNum, std::move(winrt_interrupt_in_data{std::move(intEpIn)})));

                // If a new insert took place, fill in the interrupt data
                if (insertStatus.second)
                {
                    winrt_interrupt_in_data *inData = &insertStatus.first->second;
                    inData->cb =
                        [dev_handle, epNum]
                        (
                            winrt::Windows::Devices::Usb::UsbInterruptInPipe,
                            winrt::Windows::Devices::Usb::UsbInterruptInEventArgs args
                        )
                        {
                            winrt_handle_interrupt(dev_handle, epNum, args.InterruptData());
                        };

                    try
                    {
                        inData->cb_token = inData->pipe.DataReceived(inData->cb);
                    }
                    catch (const winrt::hresult_error& e)
                    {
                        usbi_err(
                            dev_handle->dev->ctx,
                            "Exception occurred while trying to set IN interrupt callback: %s",
                            e.message().c_str()
                        );

                        return LIBUSB_ERROR_NO_DEVICE;
                    }
                }
            }

            for (auto intEpOut: winrtDev.DefaultInterface().InterruptOutPipes())
            {
                itfDef.interrupt_out_pipes.insert_or_assign(intEpOut.EndpointDescriptor().EndpointNumber(), std::move(intEpOut));
            }

            handle_priv->interfaces.insert(std::make_pair(iface, std::move(itfDef)));

            if (!isDefaultDevice)
            {
                // Save this as the default device if no control transfers are being processed
                std::lock_guard<std::recursive_mutex> lock(priv->transfer_mutex);
                if (!priv->control_transfers.active_transfer)
                {
                    priv->default_device.device = winrtDev;
                    priv->default_device.device_id = id;
                    priv->default_device.device_path = path;
                }
            }

            return LIBUSB_SUCCESS;
        }
    }

    // All found interfaces are busy
    return LIBUSB_ERROR_BUSY;
}

static int winrt_release_interface(libusb_device_handle *dev_handle, uint8_t iface)
{
    winrt_device_handle_priv *handle_priv = static_cast<winrt_device_handle_priv*>(usbi_get_device_handle_priv(dev_handle));
    winrt_device_priv *priv = static_cast<winrt_device_priv*>(usbi_get_device_priv(dev_handle->dev));

    auto iter = handle_priv->interfaces.find(iface);
    if (iter != handle_priv->interfaces.end())
    {
        bool updateDefaultDevice = (iter->second.device.device == priv->default_device.device);

        for (auto& inDataPair : iter->second.interrupt_in_pipes)
        {
            winrt_interrupt_in_data& inData = inDataPair.second;
            if (inData.cb_token)
            {
                // Clear the callback
                inData.pipe.DataReceived(inData.cb_token);
            }
        }

        // Remove this interface
        handle_priv->interfaces.erase(iter);

        if (updateDefaultDevice)
        {
            std::lock_guard<std::recursive_mutex> lock(priv->transfer_mutex);

            if (!priv->control_transfers.active_transfer)
            {
                // To avoid keeping an unused interface open just for basic operations, try to change the default device
                // to another used interface.
                for (const auto& claimedEntry : handle_priv->interfaces)
                {
                    if (claimedEntry.second.device.device)
                    {
                        priv->default_device = claimedEntry.second.device;
                        break;
                    }
                }
            }
        }

        return LIBUSB_SUCCESS;
    }

    return LIBUSB_ERROR_NOT_FOUND;
}

static int winrt_set_interface_altsetting(libusb_device_handle *dev_handle, uint8_t iface, uint8_t altsetting)
{
    winrt_device_priv *priv = static_cast<winrt_device_priv*>(usbi_get_device_priv(dev_handle->dev));

    if (!priv->default_device.device)
    {
        return LIBUSB_ERROR_NO_DEVICE;
    }

    const bool reclaim = (winrt_release_interface(dev_handle, iface) == LIBUSB_SUCCESS);

    try
    {
        for (auto itf : priv->default_device.device.Configuration().UsbInterfaces())
        {
            if (itf.InterfaceNumber() == iface)
            {
                if (altsetting >= itf.InterfaceSettings().Size())
                {
                    return LIBUSB_ERROR_NOT_FOUND;
                }

                winrt::Windows::Foundation::AsyncStatus status = winrt_handle_async_action(
                    dev_handle->dev->ctx,
                    [&]()
                    {
                        return itf.InterfaceSettings().GetAt(altsetting).SelectSettingAsync();
                    }
                );

                if (status == winrt::Windows::Foundation::AsyncStatus::Canceled)
                {
                    usbi_warn(
                        dev_handle->dev->ctx,
                        "Timeout occurred while selecting altsetting %i",
                        static_cast<int>(altsetting)
                    );
                    return LIBUSB_ERROR_TIMEOUT;
                }
                else if (status != winrt::Windows::Foundation::AsyncStatus::Completed)
                {
                    usbi_warn(
                        dev_handle->dev->ctx,
                        "Error occurred while selecting altsetting %i",
                        static_cast<int>(altsetting)
                    );
                    return LIBUSB_ERROR_IO;
                }

                if (reclaim)
                {
                    return winrt_claim_interface(dev_handle, iface);
                }

                return LIBUSB_SUCCESS;
            }
        }
    }
    catch(const winrt::hresult_error& e)
    {
        usbi_warn(
            dev_handle->dev->ctx,
            "Exception occurred while selecting altsetting %i: %s",
            static_cast<int>(altsetting),
            e.message().c_str()
        );
        return LIBUSB_ERROR_IO;
    }

    return LIBUSB_ERROR_NOT_FOUND;
}

static int winrt_clear_halt(libusb_device_handle *dev_handle, unsigned char endpoint)
{
    winrt_device_priv *priv = static_cast<winrt_device_priv*>(usbi_get_device_priv(dev_handle->dev));

    if (!priv->default_device.device)
    {
        return LIBUSB_ERROR_NO_DEVICE;
    }

    // It's easiest to just do a control transfer rather than try to use winrt objects
    auto setupPacket = UsbSetupPacket();
    setupPacket.RequestType().Direction(UsbTransferDirection::Out);
    setupPacket.RequestType().ControlTransferType(UsbControlTransferType::Standard);
    setupPacket.RequestType().Recipient(UsbControlRecipient::Endpoint);
    setupPacket.Request(LIBUSB_REQUEST_CLEAR_FEATURE);
    setupPacket.Value(0); // feature for ENDPOINT_HALT
    setupPacket.Index(endpoint);
    setupPacket.Length(0);

    int r = winrt_send_control_transfer_out(dev_handle->dev->ctx, priv->default_device.device, setupPacket);

    if (r != LIBUSB_SUCCESS)
    {
        usbi_warn(
            dev_handle->dev->ctx,
            "Failed to clear stall on endpoint %i (%s)",
            static_cast<int>(endpoint),
            libusb_error_name(r)
        );
        return r;
    }

    return LIBUSB_SUCCESS;
}

static int winrt_reset_device(libusb_device_handle *dev_handle)
{
    winrt_device_handle_priv *handle_priv = static_cast<winrt_device_handle_priv*>(usbi_get_device_handle_priv(dev_handle));

    for (std::pair<const uint8_t, winrt_interface>& itf : handle_priv->interfaces)
    {
        for (std::pair<const uint8_t, winrt::Windows::Devices::Usb::UsbBulkInPipe>& eps : itf.second.bulk_in_pipes)
        {
            eps.second.FlushBuffer();
        }

        for (std::pair<const uint8_t, winrt::Windows::Devices::Usb::UsbBulkOutPipe>& eps : itf.second.bulk_out_pipes)
        {
            winrt_handle_async<bool>(
                {
                    dev_handle->dev->ctx,
                    [&]()
                    {
                        return eps.second.OutputStream().FlushAsync();
                    }
                }
            );
        }

        for (std::pair<const uint8_t, winrt::Windows::Devices::Usb::UsbInterruptOutPipe>& eps : itf.second.interrupt_out_pipes)
        {
            winrt_handle_async<bool>(
                {
                    dev_handle->dev->ctx,
                    [&]()
                    {
                        return eps.second.OutputStream().FlushAsync();
                    }
                }
            );
        }
    }

    return LIBUSB_SUCCESS;
}

static void winrt_destroy_device(libusb_device *dev)
{
    winrt_device_priv *priv = static_cast<winrt_device_priv*>(usbi_get_device_priv(dev));
    if (priv->default_device.device)
    {
        priv->default_device.device.Close();
        priv->default_device.device = nullptr;
        priv->default_device.device_id.clear();
        priv->default_device.device_path.clear();
    }
    // Manually call destructor
    priv->~winrt_device_priv();
}

static int winrt_submit_control_transfer(usbi_transfer *itransfer)
{
    libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
    winrt_transfer_priv *tpriv = static_cast<winrt_transfer_priv*>(usbi_get_transfer_priv(itransfer));
    winrt_device_priv *priv = static_cast<winrt_device_priv*>(usbi_get_device_priv(transfer->dev_handle->dev));
    libusb_control_setup *setup = reinterpret_cast<libusb_control_setup*>(transfer->buffer);

    auto setupPacket = UsbSetupPacket();
    setupPacket.RequestType().Direction(BM_REQUEST_TO_WINRT_DIR(setup->bmRequestType));
    setupPacket.RequestType().ControlTransferType(BM_REQUEST_TO_WINRT_TRANSFER_TYPE(setup->bmRequestType));
    setupPacket.RequestType().Recipient(BM_REQUEST_TO_WINRT_RECIPIENT(setup->bmRequestType));
    setupPacket.Request(setup->bRequest);
    setupPacket.Value(setup->wValue);
    setupPacket.Index(setup->wIndex);
    setupPacket.Length(setup->wLength);

    if (IS_BM_REQUEST_IN(setup->bmRequestType))
    {
        // IN transfer
        auto outputBuffer = Streams::Buffer(setup->wLength);
        winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer> asyncOp;
        try
        {
            asyncOp = priv->default_device.device.SendControlInTransferAsync(setupPacket, outputBuffer);
        }
        catch (const winrt::hresult_error& e)
        {
            usbi_err(
                itransfer->dev->ctx,
                "Exception occurred while trying to submit an IN control transfer: %s",
                e.message().c_str()
            );

            return LIBUSB_ERROR_NO_DEVICE;
        }

        // This is capturing by value to keep the reference back to async operation
        tpriv->cancel_fn = [asyncOp](){asyncOp.Cancel();};

        asyncOp.Completed([itransfer](auto const& sender, auto const&) {
            libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
            libusb_transfer_status status = LIBUSB_TRANSFER_ERROR;
            if (sender.Status() == winrt::Windows::Foundation::AsyncStatus::Completed)
            {
                try {
                    auto buffer = sender.GetResults();
                    if (buffer && buffer.Length() <= transfer->length - LIBUSB_CONTROL_SETUP_SIZE) {
                        auto dataReader = Streams::DataReader::FromBuffer(buffer);
                        dataReader.ReadBytes(winrt::array_view<uint8_t>(transfer->buffer + LIBUSB_CONTROL_SETUP_SIZE, buffer.Length()));
                        itransfer->transferred = buffer.Length();
                        status = LIBUSB_TRANSFER_COMPLETED;
                    }
                }
                catch (...) {}
            }
            else if (sender.Status() == winrt::Windows::Foundation::AsyncStatus::Error)
            {
                // Assume stall
                status = LIBUSB_TRANSFER_STALL;
            }
            else if (sender.Status() == winrt::Windows::Foundation::AsyncStatus::Canceled)
            {
                status = LIBUSB_TRANSFER_CANCELLED;
            }

            winrt_transfer_completed(itransfer, status);
        });
    }
    else
    {
        // OUT transfer
        auto dataWriter = Streams::DataWriter();
        dataWriter.WriteBytes(winrt::array_view<const uint8_t>(transfer->buffer + LIBUSB_CONTROL_SETUP_SIZE, setup->wLength));
        auto inputBuffer = dataWriter.DetachBuffer();
        winrt::Windows::Foundation::IAsyncOperation<uint32_t> asyncOp;

        try
        {
            asyncOp = priv->default_device.device.SendControlOutTransferAsync(setupPacket, inputBuffer);
        }
        catch (const winrt::hresult_error& e)
        {
            usbi_err(
                itransfer->dev->ctx,
                "Exception occurred while trying to submit an OUT control transfer: %s",
                e.message().c_str()
            );

            return LIBUSB_ERROR_NO_DEVICE;
        }

        // This is capturing by value to keep the reference back to async operation
        tpriv->cancel_fn = [asyncOp](){asyncOp.Cancel();};

        asyncOp.Completed([itransfer](auto const& sender, auto const&) {
            libusb_transfer_status status = LIBUSB_TRANSFER_ERROR;
            if (sender.Status() == winrt::Windows::Foundation::AsyncStatus::Completed)
            {
                try {
                    auto bytesTransferred = sender.GetResults();
                    itransfer->transferred = bytesTransferred;
                    status = LIBUSB_TRANSFER_COMPLETED;
                }
                catch (...) {}
            }
            else if (sender.Status() == winrt::Windows::Foundation::AsyncStatus::Error)
            {
                // Assume stall
                status = LIBUSB_TRANSFER_STALL;
            }
            else if (sender.Status() == winrt::Windows::Foundation::AsyncStatus::Canceled)
            {
                status = LIBUSB_TRANSFER_CANCELLED;
            }

            winrt_transfer_completed(itransfer, status);
        });
    }

    return LIBUSB_SUCCESS;
}

static int winrt_submit_bulk_transfer(usbi_transfer *itransfer)
{
    libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
    winrt_transfer_priv *tpriv = static_cast<winrt_transfer_priv*>(usbi_get_transfer_priv(itransfer));
    winrt_device_handle_priv *handle_priv = static_cast<winrt_device_handle_priv*>(usbi_get_device_handle_priv(transfer->dev_handle));

    if (IS_IN_ENDPOINT(transfer->endpoint))
    {
        // IN transfer
        auto outputBuffer = Streams::Buffer(transfer->length);

        for (std::pair<const uint8_t, winrt_interface>& itf : handle_priv->interfaces)
        {
            for (std::pair<const uint8_t, winrt::Windows::Devices::Usb::UsbBulkInPipe>& eps : itf.second.bulk_in_pipes)
            {

                if (eps.first == transfer->endpoint)
                {
                    winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Storage::Streams::IBuffer, uint32_t> asyncOp;
                    try
                    {
                        asyncOp = eps.second.InputStream().ReadAsync(
                            outputBuffer,
                            transfer->length,
                            Streams::InputStreamOptions::Partial | Streams::InputStreamOptions::ReadAhead
                        );
                    }
                    catch (const winrt::hresult_error& e)
                    {
                        usbi_err(
                            itransfer->dev->ctx,
                            "Exception occurred while trying to submit an IN bulk transfer: %s",
                            e.message().c_str()
                        );

                        return LIBUSB_ERROR_NO_DEVICE;
                    }

                    // This is capturing by value to keep the reference back to async operation
                    tpriv->cancel_fn = [asyncOp](){asyncOp.Cancel();};

                    asyncOp.Completed([itransfer](auto const& sender, auto const&) {
                        libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
                        libusb_transfer_status status = LIBUSB_TRANSFER_ERROR;
                        if (sender.Status() == winrt::Windows::Foundation::AsyncStatus::Completed)
                        {
                            try {
                                auto buffer = sender.GetResults();
                                if (buffer && transfer->length >= 0 && buffer.Length() <= static_cast<std::size_t>(transfer->length))
                                {
                                    auto dataReader = Streams::DataReader::FromBuffer(buffer);
                                    dataReader.ReadBytes(winrt::array_view<uint8_t>(transfer->buffer, buffer.Length()));
                                    itransfer->transferred = buffer.Length();
                                    status = LIBUSB_TRANSFER_COMPLETED;
                                }
                            }
                            catch (...) {}
                        }
                        else if (sender.Status() == winrt::Windows::Foundation::AsyncStatus::Error)
                        {
                            // Assume stall
                            status = LIBUSB_TRANSFER_STALL;
                        }
                        else if (sender.Status() == winrt::Windows::Foundation::AsyncStatus::Canceled)
                        {
                            status = LIBUSB_TRANSFER_CANCELLED;
                        }

                        winrt_transfer_completed(itransfer, status);
                    });

                    return LIBUSB_SUCCESS;
                }
            }
        }
    }
    else
    {
        // OUT transfer
        auto dataWriter = Streams::DataWriter();
        dataWriter.WriteBytes(winrt::array_view<const uint8_t>(transfer->buffer, transfer->length));
        auto inputBuffer = dataWriter.DetachBuffer();

        for (std::pair<const uint8_t, winrt_interface>& itf : handle_priv->interfaces)
        {
            for (std::pair<const uint8_t, winrt::Windows::Devices::Usb::UsbBulkOutPipe>& eps : itf.second.bulk_out_pipes)
            {
                if (eps.first == transfer->endpoint)
                {
                    winrt::Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t> asyncOp;

                    try
                    {
                        asyncOp = eps.second.OutputStream().WriteAsync(inputBuffer);
                    }
                    catch (const winrt::hresult_error& e)
                    {
                        usbi_err(
                            itransfer->dev->ctx,
                            "Exception occurred while trying to submit an OUT bulk transfer: %s",
                            e.message().c_str()
                        );

                        return LIBUSB_ERROR_NO_DEVICE;
                    }

                    // This is capturing by value to keep the reference back to async operation
                    tpriv->cancel_fn = [asyncOp](){asyncOp.Cancel();};

                    asyncOp.Completed([itransfer](auto const& sender, auto const&) {
                        libusb_transfer_status status = LIBUSB_TRANSFER_ERROR;
                        if (sender.Status() == winrt::Windows::Foundation::AsyncStatus::Completed)
                        {
                            try {
                                auto bytesTransferred = sender.GetResults();
                                itransfer->transferred = bytesTransferred;
                                status = LIBUSB_TRANSFER_COMPLETED;
                            }
                            catch (...) {}
                        }
                        else if (sender.Status() == winrt::Windows::Foundation::AsyncStatus::Error)
                        {
                            // Assume stall
                            status = LIBUSB_TRANSFER_STALL;
                        }
                        else if (sender.Status() == winrt::Windows::Foundation::AsyncStatus::Canceled)
                        {
                            status = LIBUSB_TRANSFER_CANCELLED;
                        }

                        winrt_transfer_completed(itransfer, status);
                    });

                    return LIBUSB_SUCCESS;
                }
            }
        }
    }

    return LIBUSB_ERROR_NOT_FOUND;
}

static int winrt_submit_interrupt_transfer(usbi_transfer *itransfer)
{
    libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
    winrt_transfer_priv *tpriv = static_cast<winrt_transfer_priv*>(usbi_get_transfer_priv(itransfer));
    winrt_device_handle_priv *handle_priv = static_cast<winrt_device_handle_priv*>(usbi_get_device_handle_priv(transfer->dev_handle));

    if (IS_IN_ENDPOINT(transfer->endpoint))
    {
        // IN transfer
        auto outputBuffer = Streams::Buffer(transfer->length);

        for (std::pair<const uint8_t, winrt_interface>& itf : handle_priv->interfaces)
        {
            for (std::pair<const uint8_t, winrt_interrupt_in_data>& eps : itf.second.interrupt_in_pipes)
            {
                if (eps.first == transfer->endpoint)
                {
                    // All that needs to be done is set the cancel callback since this is handled automatically
                    tpriv->cancel_fn = [itransfer](){
                        winrt_transfer_completed(itransfer, LIBUSB_TRANSFER_CANCELLED);
                    };

                    return LIBUSB_SUCCESS;
                }
            }
        }
    }
    else
    {
        // OUT transfer
        auto dataWriter = Streams::DataWriter();
        dataWriter.WriteBytes(winrt::array_view<const uint8_t>(transfer->buffer, transfer->length));
        auto inputBuffer = dataWriter.DetachBuffer();

        for (std::pair<const uint8_t, winrt_interface>& itf : handle_priv->interfaces)
        {
            for (std::pair<const uint8_t, winrt::Windows::Devices::Usb::UsbInterruptOutPipe>& eps : itf.second.interrupt_out_pipes)
            {
                if (eps.first == transfer->endpoint)
                {
                    winrt::Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t> asyncOp;

                    try
                    {
                        asyncOp = eps.second.OutputStream().WriteAsync(inputBuffer);
                    }
                    catch (const winrt::hresult_error& e)
                    {
                        usbi_err(
                            itransfer->dev->ctx,
                            "Exception occurred while trying to submit an OUT interrupt transfer: %s",
                            e.message().c_str()
                        );

                        return LIBUSB_ERROR_NO_DEVICE;
                    }

                    // This is capturing by value to keep the reference back to async operation
                    tpriv->cancel_fn = [asyncOp](){asyncOp.Cancel();};

                    asyncOp.Completed([itransfer](auto const& sender, auto const&) {
                        libusb_transfer_status status = LIBUSB_TRANSFER_ERROR;
                        if (sender.Status() == winrt::Windows::Foundation::AsyncStatus::Completed)
                        {
                            try {
                                auto bytesTransferred = sender.GetResults();
                                itransfer->transferred = bytesTransferred;
                                status = LIBUSB_TRANSFER_COMPLETED;
                            }
                            catch (...) {}
                        }
                        else if (sender.Status() == winrt::Windows::Foundation::AsyncStatus::Error)
                        {
                            // Assume stall
                            status = LIBUSB_TRANSFER_STALL;
                        }
                        else if (sender.Status() == winrt::Windows::Foundation::AsyncStatus::Canceled)
                        {
                            status = LIBUSB_TRANSFER_CANCELLED;
                        }

                        winrt_transfer_completed(itransfer, status);
                    });

                    return LIBUSB_SUCCESS;
                }
            }
        }
    }

    return LIBUSB_ERROR_NOT_FOUND;
}

static int winrt_submit_transfer(usbi_transfer *itransfer)
{
    libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
    // Use placement new to properly construct the private structure
    winrt_transfer_priv *tpriv = new (usbi_get_transfer_priv(itransfer)) winrt_transfer_priv();
    static_cast<void>(tpriv);
    winrt_device_handle_priv *handle_priv = static_cast<winrt_device_handle_priv*>(usbi_get_device_handle_priv(transfer->dev_handle));
    winrt_device_priv *priv = static_cast<winrt_device_priv*>(usbi_get_device_priv(transfer->dev_handle->dev));

    // For any communication, the default_device must be set
    if (!priv->default_device.device)
    {
        winrt_transfer_completed(itransfer, libusb_transfer_status::LIBUSB_TRANSFER_ERROR);
        return LIBUSB_ERROR_NO_DEVICE;
    }

    int transferStatus = LIBUSB_ERROR_OTHER;

    switch (transfer->type)
    {
        case LIBUSB_TRANSFER_TYPE_CONTROL:
        {
            std::lock_guard<std::recursive_mutex> lock(priv->transfer_mutex);

            if (priv->control_transfers.active_transfer)
            {
                // Still working on a transfer - will get to this transfer later
                priv->control_transfers.transfer_queue.push_back(itransfer);
                return LIBUSB_SUCCESS;
            }

            // Begin transfer now
            priv->control_transfers.active_transfer = itransfer;
            transferStatus = winrt_submit_control_transfer(itransfer);
        }
        break;

        case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS: // Fall through
        case LIBUSB_TRANSFER_TYPE_BULK: // Fall through
        case LIBUSB_TRANSFER_TYPE_INTERRUPT: // Fall through
        case LIBUSB_TRANSFER_TYPE_BULK_STREAM:
        {
            std::lock_guard<std::recursive_mutex> lock(priv->transfer_mutex);

            auto iter = handle_priv->transfers.find(transfer->endpoint);
            if (iter != handle_priv->transfers.end())
            {
                if (iter->second.active_transfer)
                {
                    // Still working on a transfer - will get to this transfer later
                    iter->second.transfer_queue.push_back(itransfer);
                    return LIBUSB_SUCCESS;
                }
                else
                {
                    iter->second.active_transfer = itransfer;
                }
            }
            else
            {
                handle_priv->transfers[transfer->endpoint].active_transfer = itransfer;
            }

            if (transfer->type == LIBUSB_TRANSFER_TYPE_ISOCHRONOUS || transfer->type == LIBUSB_TRANSFER_TYPE_INTERRUPT)
            {
                transferStatus = winrt_submit_interrupt_transfer(itransfer);
            }
            else
            {
                transferStatus = winrt_submit_bulk_transfer(itransfer);
            }
        }
        break;

        default:
            // Should not get here since windows_submit_transfer() validates
            // the transfer->type field
            usbi_err(TRANSFER_CTX(transfer), "unknown endpoint type %d", transfer->type);
            transferStatus = LIBUSB_ERROR_INVALID_PARAM;
    }

    if (transferStatus != LIBUSB_SUCCESS)
    {
        winrt_transfer_completed(itransfer, libusb_transfer_status::LIBUSB_TRANSFER_ERROR);
    }
    return transferStatus;
}

static int winrt_pop_transfer_from_queue(usbi_transfer *itransfer, winrt_transfer_queue& queue)
{
    libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
    winrt_device_priv *priv = static_cast<winrt_device_priv*>(usbi_get_device_priv(itransfer->dev));

    std::lock_guard<std::recursive_mutex> lock(priv->transfer_mutex);

    if (queue.active_transfer == itransfer)
    {
        // This was a control transfer that just completed
        winrt_transfer_priv *tpriv = static_cast<winrt_transfer_priv*>(usbi_get_transfer_priv(itransfer));
        tpriv->cancel_fn = nullptr;
        queue.active_transfer = nullptr;

        if (queue.transfer_queue.empty())
        {
            // No more transfers to process
            return LIBUSB_SUCCESS;
        }

        int transferStatus = LIBUSB_ERROR_OTHER;
        do
        {
            // Submit the next transfer and return
            itransfer = queue.transfer_queue.front();
            transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
            queue.transfer_queue.pop_front();
            queue.active_transfer = itransfer;
            switch (transfer->type)
            {
                case LIBUSB_TRANSFER_TYPE_CONTROL:
                    transferStatus = winrt_submit_control_transfer(itransfer);
                    break;

                case LIBUSB_TRANSFER_TYPE_BULK: // Fall through
                case LIBUSB_TRANSFER_TYPE_BULK_STREAM:
                    transferStatus = winrt_submit_bulk_transfer(itransfer);
                    break;

                case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS: // Fall through
                case LIBUSB_TRANSFER_TYPE_INTERRUPT:
                    transferStatus = winrt_submit_interrupt_transfer(itransfer);
                    break;

                default:
                    usbi_err(TRANSFER_CTX(transfer), "unknown endpoint type %d", transfer->type);
                    transferStatus = LIBUSB_ERROR_INVALID_PARAM;
                    break;
            }

            if (transferStatus == LIBUSB_ERROR_NO_DEVICE)
            {
                tpriv = static_cast<winrt_transfer_priv*>(usbi_get_transfer_priv(itransfer));
                tpriv->status = libusb_transfer_status::LIBUSB_TRANSFER_NO_DEVICE;
                usbi_signal_transfer_completion(itransfer);

                // Cancel everything else in the queue because there is no device detected
                while (!queue.transfer_queue.empty())
                {
                    itransfer = queue.transfer_queue.front();
                    queue.transfer_queue.pop_front();
                    tpriv = static_cast<winrt_transfer_priv*>(usbi_get_transfer_priv(itransfer));
                    tpriv->status = libusb_transfer_status::LIBUSB_TRANSFER_NO_DEVICE;
                    usbi_signal_transfer_completion(itransfer);
                }
                return transferStatus;
            }
            else if (transferStatus != LIBUSB_SUCCESS)
            {
                // Other error: just complete this transfer and try the next one
                tpriv = static_cast<winrt_transfer_priv*>(usbi_get_transfer_priv(itransfer));
                tpriv->status = libusb_transfer_status::LIBUSB_TRANSFER_ERROR;
                usbi_signal_transfer_completion(itransfer);
            }
        } while (transferStatus != LIBUSB_SUCCESS && !queue.transfer_queue.empty());

        return transferStatus;
    }

    return LIBUSB_ERROR_NOT_FOUND;
}

static int winrt_pop_transfer(usbi_transfer *itransfer)
{
    libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
    winrt_device_priv *priv = static_cast<winrt_device_priv*>(usbi_get_device_priv(transfer->dev_handle->dev));

    int r = winrt_pop_transfer_from_queue(itransfer, priv->control_transfers);
    if (r != LIBUSB_ERROR_NOT_FOUND)
    {
        return r;
    }

    winrt_device_handle_priv *handle_priv = static_cast<winrt_device_handle_priv*>(usbi_get_device_handle_priv(transfer->dev_handle));
    auto iter = handle_priv->transfers.find(transfer->endpoint);
    if (iter != handle_priv->transfers.end())
    {
        return winrt_pop_transfer_from_queue(itransfer, iter->second);
    }

    return LIBUSB_ERROR_NOT_FOUND;
}

static void winrt_transfer_completed(usbi_transfer *itransfer, libusb_transfer_status status, bool signal)
{
    // Pop transfer and immediately start the next if it's available
    winrt_pop_transfer(itransfer);

    winrt_transfer_priv *tpriv = static_cast<winrt_transfer_priv*>(usbi_get_transfer_priv(itransfer));
    tpriv->status = status;

    if (signal)
    {
        usbi_signal_transfer_completion(itransfer);
    }
}

static int winrt_handle_transfer_completion(usbi_transfer *itransfer)
{
    winrt_transfer_priv *tpriv = static_cast<winrt_transfer_priv*>(usbi_get_transfer_priv(itransfer));

    // Save the status value before destruction
    libusb_transfer_status status = tpriv->status;

    // Explicitly call destructor for private data (if re-used, placement new will be called again later)
    tpriv->~winrt_transfer_priv();

    if (status == LIBUSB_TRANSFER_CANCELLED)
    {
        usbi_handle_transfer_cancellation(itransfer);
    }
    else
    {
        usbi_handle_transfer_completion(itransfer, status);
    }

    return LIBUSB_SUCCESS;
}

static int winrt_cancel_transfer_from_queue(usbi_transfer *itransfer, winrt_transfer_queue& queue)
{
    winrt_transfer_priv *tpriv = static_cast<winrt_transfer_priv*>(usbi_get_transfer_priv(itransfer));
    winrt_device_priv *priv = static_cast<winrt_device_priv*>(usbi_get_device_priv(itransfer->dev));

    std::unique_lock<std::recursive_mutex> lock(priv->transfer_mutex);

    if (queue.active_transfer == itransfer)
    {
        if (tpriv->cancel_fn)
        {
            tpriv->cancel_fn();
            // The callback function will complete the transfer once it's fully canceled
            return LIBUSB_SUCCESS;
        }
        else
        {
            // This isn't expected
            usbi_warn(itransfer->dev->ctx, "No cancel function specified in winrt_transfer_priv");
            return LIBUSB_ERROR_OTHER;
        }
    }

    for (auto iter = queue.transfer_queue.begin(); iter != queue.transfer_queue.end(); ++iter)
    {
        if ((*iter) == itransfer)
        {
            queue.transfer_queue.erase(iter);
            lock.unlock();

            tpriv->status = LIBUSB_TRANSFER_CANCELLED;
            usbi_signal_transfer_completion(itransfer);

            return LIBUSB_SUCCESS;
        }
    }

    return LIBUSB_ERROR_NOT_FOUND;
}

static int winrt_cancel_transfer(usbi_transfer *itransfer)
{
    libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
    winrt_device_priv *priv = static_cast<winrt_device_priv*>(usbi_get_device_priv(transfer->dev_handle->dev));

    int r = winrt_cancel_transfer_from_queue(itransfer, priv->control_transfers);
    if (r != LIBUSB_ERROR_NOT_FOUND)
    {
        return r;
    }

    winrt_device_handle_priv *handle_priv = static_cast<winrt_device_handle_priv*>(usbi_get_device_handle_priv(transfer->dev_handle));
    auto iter = handle_priv->transfers.find(transfer->endpoint);
    if (iter != handle_priv->transfers.end())
    {
        return winrt_cancel_transfer_from_queue(itransfer, iter->second);
    }

    return LIBUSB_ERROR_NOT_FOUND;
}

const usbi_os_backend usbi_backend = {
    "winrt", // name
    USBI_CAP_HAS_HID_ACCESS, // caps (but probably won't be able to open any of them)
    winrt_init, // init
    winrt_exit, // exit
    NULL, // set_option
    winrt_get_device_list, // get_device_list
    winrt_get_device_string, // get_device_string
    NULL, // hotplug_poll
    NULL, // wrap_sys_device
    winrt_open, // open
    winrt_close, // close
    winrt_get_active_config_descriptor, // get_active_config_descriptor
    winrt_get_config_descriptor, // get_config_descriptor
    winrt_get_config_descriptor_by_value, // get_config_descriptor_by_value
    winrt_get_configuration, // get_configuration
    winrt_set_configuration, // set_configuration

    winrt_claim_interface, // claim_interface
    winrt_release_interface, // release_interface

    winrt_set_interface_altsetting, // set_interface_altsetting
    winrt_clear_halt, // clear_halt
    winrt_reset_device, // reset_device

    NULL, // alloc_streams
    NULL, // free_streams
    NULL, // dev_mem_alloc
    NULL, // dev_mem_free
    NULL, // kernel_driver_active

    NULL, // detach_kernel_driver
    NULL, // attach_kernel_driver

    NULL, // endpoint_supports_raw_io
    NULL, // endpoint_set_raw_io
    NULL, // get_max_raw_io_transfer_size

    winrt_destroy_device, // destroy_device

    winrt_submit_transfer, // submit_transfer
    winrt_cancel_transfer, // cancel_transfer
    NULL, // clear_transfer_priv
    NULL, // handle_events
    winrt_handle_transfer_completion, // handle_transfer_completion

    sizeof(winrt_context_priv), // context_priv_size
    sizeof(winrt_device_priv), // device_priv_size
    sizeof(winrt_device_handle_priv), // device_handle_priv_size
    sizeof(winrt_transfer_priv), // transfer_priv_size
};
