/*
 * Copyright © 2021 Ingvar Stepanyan <rreverser@google.com>
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

#include <emscripten.h>
#include <emscripten/val.h>

#include <optional>

#include "libusbi.h"

using namespace emscripten;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-prototypes"
#pragma clang diagnostic ignored "-Wunused-parameter"
namespace {
// In order to handle promise errors, we need a JS snippet to wrap value
// or error to a {value, error} object that can be handled by Embind.
//
// Unfortunately, EM_JS / EM_ASM is currently not integrated at all with Embind,
// which makes it impossible to officially manipulate same JS values from both
// custom JS snippets and Embind-based C++.
//
// So we have to reach into Embind internals unofficially instead...
EM_VAL em_value_to_raw_handle(val &value) {
  return *reinterpret_cast<EM_VAL *>(&value);
}

// clang-format off
	EM_JS(void, em_promise_catch_impl, (EM_VAL handle), {
		handle = emval_handle_array[handle];
		if (handle.refcount !== 1)
		{
			throw new Error("Must be an owned promise");
		}
		handle.value = handle.value.then(
			value => ({error : 0, value}),
			error => {
				const ERROR_CODES = {
					// LIBUSB_ERROR_IO
					NetworkError : -1,
					// LIBUSB_ERROR_INVALID_PARAM
					DataError : -2,
					TypeMismatchError : -2,
					IndexSizeError : -2,
					// LIBUSB_ERROR_ACCESS
					SecurityError : -3,
					// LIBUSB_ERROR_NOT_FOUND
					NotFoundError : -5,
					// LIBUSB_ERROR_BUSY
					InvalidStateError : -6,
					// LIBUSB_ERROR_TIMEOUT
					TimeoutError : -7,
					// LIBUSB_ERROR_INTERRUPTED
					AbortError : -10,
					// LIBUSB_ERROR_NOT_SUPPORTED
					NotSupportedError : -12,
				};
				console.error(error);
				if (error instanceof DOMException)
				{
					error = ERROR_CODES[error.name] || result;
				}
				else if ((error instanceof RangeError) || (error instanceof TypeError))
				{
					error = -2; // LIBUSB_ERROR_INVALID_PARAM
				}
				else
				{
					error = -99; // LIBUSB_ERROR_OTHER
				}
				return {error, value: undefined};
			});
	});
// clang-format on

// C++ struct representation for {value, error} object from above
// (performs conversion in the constructor).
struct promise_result {
  libusb_error error;
  val value;

  promise_result(val &&result)
      : error(static_cast<libusb_error>(result["error"].as<int>())),
        value(result["value"]) {}

  // C++ counterpart of the promise helper above that takes a promise, catches
  // its error, converts to a libusb status and returns the whole thing as
  // `promise_result` struct for easier handling.
  static promise_result await(val &&promise) {
    em_promise_catch_impl(em_value_to_raw_handle(promise));
    return {promise.await()};
  }
};

// We store an Embind handle to WebUSB USBDevice in "priv" metadata of
// libusb device, this helper returns a pointer to it.
val *get_web_usb_device(libusb_device *dev) {
  return static_cast<val *>(usbi_get_device_priv(dev));
}

// Same for transfer results.
val *get_web_usb_transfer_result(usbi_transfer *itransfer) {
  return static_cast<val *>(usbi_get_transfer_priv(itransfer));
}

// Store the global `navigator.usb` once upon initialisation.
thread_local const val web_usb = val::global("navigator")["usb"];

int em_get_device_list(libusb_context *ctx, discovered_devs **devs) {
  // C++ equivalent of `await navigator.usb.getDevices()`.
  // Note: at this point we must already have some devices exposed -
  // caller must have called `await navigator.usb.requestDevice(...)`
  // in response to user interaction before going to LibUSB.
  // Otherwise this list will be empty.
  auto result = promise_result::await(web_usb.call<val>("getDevices"));
  if (result.error) {
    return result.error;
  }
  auto &web_usb_devices = result.value;
  // Iterate over the exposed devices.
  uint8_t devices_num = web_usb_devices["length"].as<uint8_t>();
  for (uint8_t i = 0; i < devices_num; i++) {
    auto web_usb_device = web_usb_devices[i];
    auto vendor_id = web_usb_device["vendorId"].as<uint16_t>();
    auto product_id = web_usb_device["productId"].as<uint16_t>();
    // TODO: this has to be a unique ID for the device in libusb structs.
    // We can't really rely on the index in the list, and otherwise
    // I can't think of a good way to assign permanent IDs to those
    // devices, so here goes best-effort attempt...
    unsigned long session_id = (vendor_id << 16) | product_id;
    // LibUSB uses that ID to check if this device is already in its own
    // list. As long as there are no two instances of same device
    // connected and exposed to the page, we should be fine...
    auto dev = usbi_get_device_by_session_id(ctx, session_id);
    if (dev == NULL) {
      dev = usbi_alloc_device(ctx, session_id);
      if (dev == NULL) {
        usbi_err(ctx, "failed to allocate a new device structure");
        continue;
      }

      dev->device_descriptor = {
          .bLength = LIBUSB_DT_DEVICE_SIZE,
          .bDescriptorType = LIBUSB_DT_DEVICE,
          .bcdUSB = static_cast<uint16_t>(
              (web_usb_device["usbVersionMajor"].as<uint8_t>() << 8) |
              (web_usb_device["usbVersionMinor"].as<uint8_t>() << 4) |
              web_usb_device["usbVersionSubminor"].as<uint8_t>()),
          .bDeviceClass = web_usb_device["deviceClass"].as<uint8_t>(),
          .bDeviceSubClass = web_usb_device["deviceSubclass"].as<uint8_t>(),
          .bDeviceProtocol = web_usb_device["deviceProtocol"].as<uint8_t>(),
          .bMaxPacketSize0 = 64,  // yolo
          .idVendor = vendor_id,
          .idProduct = product_id,
          .bcdDevice = static_cast<uint16_t>(
              (web_usb_device["deviceVersionMajor"].as<uint8_t>() << 8) |
              (web_usb_device["deviceVersionMinor"].as<uint8_t>() << 4) |
              web_usb_device["deviceVersionSubminor"].as<uint8_t>()),
          // Those are supposed to be indices for USB string descriptors.
          // Normally they're part of the raw USB descriptor structure, but in
          // our case we don't have it. Luckily, libusb provides hooks for that
          // (to accomodate for other systems in similar position) so we can
          // just assign constant IDs we can recognise later and then handle
          // them in `em_submit_transfer` when there is a request to get string
          // descriptor value.
          .iManufacturer = 1,
          .iProduct = 2,
          .iSerialNumber = 3,
          .bNumConfigurations =
              web_usb_device["configurations"]["length"].as<uint8_t>(),
      };

      if (usbi_sanitize_device(dev) < 0) {
        libusb_unref_device(dev);
        continue;
      }

      new (get_web_usb_device(dev)) val(std::move(web_usb_device));
    }
    *devs = discovered_devs_append(*devs, dev);
  }
  return LIBUSB_SUCCESS;
}

int em_open(libusb_device_handle *handle) {
  auto web_usb_device = get_web_usb_device(handle->dev);
  return promise_result::await(web_usb_device->call<val>("open")).error;
}

void em_close(libusb_device_handle *handle) {
  // LibUSB API doesn't allow us to handle an error here, so ignore the Promise
  // altogether.
  return get_web_usb_device(handle->dev)->call<void>("close");
}

int em_get_config_descriptor_impl(val &&web_usb_config, void *buf, size_t len) {
  const auto buf_start = static_cast<uint8_t *>(buf);
  auto web_usb_interfaces = web_usb_config["interfaces"];
  auto num_interfaces = web_usb_interfaces["length"].as<uint8_t>();
  auto config = static_cast<usbi_configuration_descriptor *>(buf);
  *config = {
      .bLength = LIBUSB_DT_CONFIG_SIZE,
      .bDescriptorType = LIBUSB_DT_CONFIG,
      .wTotalLength = LIBUSB_DT_CONFIG_SIZE,
      .bNumInterfaces = num_interfaces,
      .bConfigurationValue = web_usb_config["configurationValue"].as<uint8_t>(),
      .iConfiguration =
          0,  // TODO: assign some index and handle `configurationName`
      .bmAttributes =
          1 << 7,      // bus powered (should be always set according to docs)
      .bMaxPower = 0,  // yolo
  };
  buf = static_cast<uint8_t *>(buf) + LIBUSB_DT_CONFIG_SIZE;
  for (uint8_t i = 0; i < num_interfaces; i++) {
    auto web_usb_interface = web_usb_interfaces[i];
    auto web_usb_alternate = web_usb_interface["alternates"][0];
    auto web_usb_endpoints = web_usb_alternate["endpoints"];
    auto num_endpoints = web_usb_endpoints["length"].as<uint8_t>();
    config->wTotalLength +=
        LIBUSB_DT_INTERFACE_SIZE + num_endpoints * LIBUSB_DT_ENDPOINT_SIZE;
    if (config->wTotalLength > len) {
      continue;
    }
    auto interface = static_cast<usbi_interface_descriptor *>(buf);
    *interface = {
        .bLength = LIBUSB_DT_INTERFACE_SIZE,
        .bDescriptorType = LIBUSB_DT_INTERFACE,
        .bInterfaceNumber = web_usb_interface["interfaceNumber"].as<uint8_t>(),
        .bAlternateSetting =
            web_usb_alternate["alternateSetting"].as<uint8_t>(),
        .bNumEndpoints = web_usb_endpoints["length"].as<uint8_t>(),
        .bInterfaceClass = web_usb_alternate["interfaceClass"].as<uint8_t>(),
        .bInterfaceSubClass =
            web_usb_alternate["interfaceSubclass"].as<uint8_t>(),
        .bInterfaceProtocol =
            web_usb_alternate["interfaceProtocol"].as<uint8_t>(),
        .iInterface = 0,  // Not exposed in WebUSB, don't assign any string.
    };
    buf = static_cast<uint8_t *>(buf) + LIBUSB_DT_INTERFACE_SIZE;
    for (uint8_t j = 0; j < num_endpoints; j++) {
      auto web_usb_endpoint = web_usb_endpoints[j];
      auto endpoint = static_cast<libusb_endpoint_descriptor *>(buf);

      thread_local const val web_usb_direction_in("in");
      thread_local const val web_usb_endpoint_type_bulk("bulk");
      thread_local const val web_usb_endpoint_type_interrupt("interrupt");
      thread_local const val web_usb_endpoint_type_isochronous("isochronous");

      auto web_usb_endpoint_type = web_usb_endpoint["type"];
      auto transfer_type = LIBUSB_ENDPOINT_TRANSFER_TYPE_CONTROL;

      if (web_usb_endpoint_type == web_usb_endpoint_type_bulk) {
        transfer_type = LIBUSB_ENDPOINT_TRANSFER_TYPE_BULK;
      } else if (web_usb_endpoint_type == web_usb_endpoint_type_interrupt) {
        transfer_type = LIBUSB_ENDPOINT_TRANSFER_TYPE_INTERRUPT;
      } else if (web_usb_endpoint_type == web_usb_endpoint_type_isochronous) {
        transfer_type = LIBUSB_ENDPOINT_TRANSFER_TYPE_ISOCHRONOUS;
      }

      // Can't use struct-init syntax here because there is no
      // `usbi_endpoint_descriptor` unlike for other descriptors, so we use
      // `libusb_endpoint_descriptor` instead which has extra libusb-specific
      // fields and might overflow the provided buffer.
      endpoint->bLength = LIBUSB_DT_ENDPOINT_SIZE;
      endpoint->bDescriptorType = LIBUSB_DT_ENDPOINT;
      endpoint->bEndpointAddress =
          ((web_usb_endpoint["direction"] == web_usb_direction_in) << 7) |
          web_usb_endpoint["endpointNumber"].as<uint8_t>();
      endpoint->bmAttributes = transfer_type;
      endpoint->wMaxPacketSize = web_usb_endpoint["packetSize"].as<uint16_t>();
      endpoint->bInterval = 1;

      buf = static_cast<uint8_t *>(buf) + LIBUSB_DT_ENDPOINT_SIZE;
    }
  }
  return static_cast<uint8_t *>(buf) - buf_start;
}

int em_get_active_config_descriptor(libusb_device *dev, void *buf, size_t len) {
  auto web_usb_config = (*get_web_usb_device(dev))["configuration"];
  if (web_usb_config.isNull()) {
    return LIBUSB_ERROR_NOT_FOUND;
  }
  return em_get_config_descriptor_impl(std::move(web_usb_config), buf, len);
}

int em_get_config_descriptor(libusb_device *dev, uint8_t idx, void *buf,
                             size_t len) {
  return em_get_config_descriptor_impl(
      (*get_web_usb_device(dev))["configurations"][idx], buf, len);
}

int em_get_configuration(libusb_device_handle *dev_handle, uint8_t *config) {
  auto web_usb_config = (*get_web_usb_device(dev_handle->dev))["configuration"];
  if (!web_usb_config.isNull()) {
    *config = web_usb_config["configurationValue"].as<uint8_t>();
  }
  return LIBUSB_SUCCESS;
}

int em_set_configuration(libusb_device_handle *handle, int config) {
  return promise_result::await(get_web_usb_device(handle->dev)
                                   ->call<val>("selectConfiguration", config))
      .error;
}

int em_claim_interface(libusb_device_handle *handle, uint8_t iface) {
  return promise_result::await(get_web_usb_device(handle->dev)
                                   ->call<val>("claimInterface", iface))
      .error;
}

int em_release_interface(libusb_device_handle *handle, uint8_t iface) {
  return promise_result::await(get_web_usb_device(handle->dev)
                                   ->call<val>("releaseInterface", iface))
      .error;
}

int em_set_interface_altsetting(libusb_device_handle *handle, uint8_t iface,
                                uint8_t altsetting) {
  return promise_result::await(
             get_web_usb_device(handle->dev)
                 ->call<val>("selectAlternateInterface", iface, altsetting))
      .error;
}

int em_clear_halt(libusb_device_handle *handle, unsigned char endpoint) {
  thread_local const val web_usb_direction_in("in");
  thread_local const val web_usb_direction_out("out");

  auto direction = endpoint & LIBUSB_ENDPOINT_IN ? web_usb_direction_in
                                                 : web_usb_direction_out;
  endpoint &= LIBUSB_ENDPOINT_ADDRESS_MASK;

  return promise_result::await(
             get_web_usb_device(handle->dev)
                 ->call<val>("clearHalt", direction, endpoint))
      .error;
}

int em_reset_device(libusb_device_handle *handle) {
  return promise_result::await(
             get_web_usb_device(handle->dev)->call<val>("reset"))
      .error;
}

void em_destroy_device(libusb_device *dev) {
  std::move(*get_web_usb_device(dev));
}

thread_local const val Uint8Array = val::global("Uint8Array");

EM_JS(void, em_start_transfer_impl, (usbi_transfer * transfer, EM_VAL handle), {
  handle = emval_handle_array[handle];
  if (handle.refcount != = 1) {
    throw new Error("Must be an owned promise");
  }
  // Right now the transfer value should be a `Promise<{value, error}>`
  // for the actual WebUSB transfer op. Subscribe to its result to unwrap
  // the promise to `{value, error}` and signal transfer completion.
  handle.value.then(result = > {
    handle.value = result;
    Module._em_signal_transfer_completion(transfer);
  });
});

void em_start_transfer(usbi_transfer *itransfer, val promise) {
  auto promise_ptr =
      new (get_web_usb_transfer_result(itransfer)) val(std::move(promise));
  auto handle = em_value_to_raw_handle(*promise_ptr);
  // Catch the error to transform promise of `value` into promise of `{value,
  // error}`.
  em_promise_catch_impl(handle);
  em_start_transfer_impl(itransfer, handle);
}

int em_submit_transfer(usbi_transfer *itransfer) {
  auto transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
  auto web_usb_device = get_web_usb_device(transfer->dev_handle->dev);
  switch (transfer->type) {
    case LIBUSB_TRANSFER_TYPE_CONTROL: {
      auto setup = libusb_control_transfer_get_setup(transfer);
      auto web_usb_control_transfer_params = val::object();

      const char *web_usb_request_type = "unknown";
      // See LIBUSB_REQ_TYPE in windows_winusb.h (or docs for `bmRequestType`).
      switch (setup->bmRequestType & (0x03 << 5)) {
        case LIBUSB_REQUEST_TYPE_STANDARD:
          if (setup->bRequest == LIBUSB_REQUEST_GET_DESCRIPTOR &&
              setup->wValue >> 8 == LIBUSB_DT_STRING) {
            // For string descriptors we provide custom implementation that
            // doesn't require an actual transfer, but just retrieves the value
            // from JS, stores that string handle as transfer data (instead of a
            // Promise) and immediately signals completion.
            const char *propName = nullptr;
            switch (setup->wValue & 0xFF) {
              case 1:
                propName = "manufacturerName";
                break;
              case 2:
                propName = "productName";
                break;
              case 3:
                propName = "serialNumber";
                break;
            }
            if (propName != nullptr) {
              val str = (*web_usb_device)[propName];
              if (str.isNull()) {
                str = val("");
              }
              new (get_web_usb_transfer_result(itransfer)) val(std::move(str));
              usbi_signal_transfer_completion(itransfer);
              return LIBUSB_SUCCESS;
            }
          }
          web_usb_request_type = "standard";
          break;
        case LIBUSB_REQUEST_TYPE_CLASS:
          web_usb_request_type = "class";
          break;
        case LIBUSB_REQUEST_TYPE_VENDOR:
          web_usb_request_type = "vendor";
          break;
      }
      web_usb_control_transfer_params.set("requestType", web_usb_request_type);

      const char *recipient = "other";
      switch (setup->bmRequestType & 0x0f) {
        case LIBUSB_RECIPIENT_DEVICE:
          recipient = "device";
          break;
        case LIBUSB_RECIPIENT_INTERFACE:
          recipient = "interface";
          break;
        case LIBUSB_RECIPIENT_ENDPOINT:
          recipient = "endpoint";
          break;
      }
      web_usb_control_transfer_params.set("recipient", recipient);

      web_usb_control_transfer_params.set("request", setup->bRequest);
      web_usb_control_transfer_params.set("value", setup->wValue);
      web_usb_control_transfer_params.set("index", setup->wIndex);

      if (setup->bmRequestType & LIBUSB_ENDPOINT_IN) {
        em_start_transfer(
            itransfer,
            web_usb_device->call<val>(
                "controlTransferIn", std::move(web_usb_control_transfer_params),
                setup->wLength));
      } else {
        auto data =
            val(typed_memory_view(setup->wLength,
                                  libusb_control_transfer_get_data(transfer)))
                .call<val>("slice");
        em_start_transfer(
            itransfer, web_usb_device->call<val>(
                           "controlTransferOut",
                           std::move(web_usb_control_transfer_params), data));
      }

      break;
    }
    case LIBUSB_TRANSFER_TYPE_BULK:
    case LIBUSB_TRANSFER_TYPE_INTERRUPT: {
      auto endpoint = transfer->endpoint & LIBUSB_ENDPOINT_ADDRESS_MASK;

      if (IS_XFERIN(transfer)) {
        em_start_transfer(itransfer,
                          web_usb_device->call<val>("transferIn", endpoint,
                                                    transfer->length));
      } else {
        auto data = val(typed_memory_view(transfer->length, transfer->buffer))
                        .call<val>("slice");
        em_start_transfer(itransfer, web_usb_device->call<val>("transferOut",
                                                               endpoint, data));
      }

      break;
    }
    // TODO: finalize implementation for isochronous transfers too.
    // case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS: {
    // 	if (setup->bmRequestType & LIBUSB_ENDPOINT_IN) {
    // 		// todo: read result
    // 		auto web_usb_packet_lengths = val::array();
    // 		for (int i = 0; i < transfer->num_iso_packets; i++) {
    // 			web_usb_packet_lengths.call<void>("push",
    // transfer->iso_packet_desc[i].length);
    // 		}
    // 		await_int(web_usb_device->call<val>("isochronousTransferIn",
    // transfer->endpoint, std::move(web_usb_packet_lengths))); 	} else {
    // 		// todo: read result
    // 		await_int(web_usb_device->call<val>("isochronousTransferOut"));
    // 	}
    // 	break;
    // }
    default:
      return LIBUSB_ERROR_NOT_SUPPORTED;
  }
  return LIBUSB_SUCCESS;
}

void em_clear_transfer_priv(usbi_transfer *itransfer) {
  std::move(*get_web_usb_transfer_result(itransfer));
}

int em_cancel_transfer(usbi_transfer *itransfer) { return LIBUSB_SUCCESS; }

int em_handle_transfer_completion(usbi_transfer *itransfer) {
  auto transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);

  // Take ownership of the transfer result, as `em_clear_transfer_priv`
  // is not called automatically for completed transfers and we must
  // free it to avoid leaks.
  // std::unique_ptr<val> result_val(get_web_usb_transfer_result(itransfer));

  auto result_val = std::move(*get_web_usb_transfer_result(itransfer));

  if (itransfer->state_flags & USBI_TRANSFER_CANCELLING) {
    return usbi_handle_transfer_cancellation(itransfer);
  }

  libusb_transfer_status status = LIBUSB_TRANSFER_ERROR;

  // If this was a LIBUSB_DT_STRING request, then the value will be a string
  // handle instead of a promise.
  if (result_val.isString()) {
    int written = EM_ASM_INT(
        {
          // There's no good way to get UTF-16 output directly from JS string,
          // so again reach out to internals via JS snippet.
          return stringToUTF16(requireHandle($0), $1, $2);
        },
        em_value_to_raw_handle(result_val),
        transfer->buffer + LIBUSB_CONTROL_SETUP_SIZE + 2,
        transfer->length - LIBUSB_CONTROL_SETUP_SIZE - 2);
    itransfer->transferred = transfer->buffer[LIBUSB_CONTROL_SETUP_SIZE] =
        2 + written;
    transfer->buffer[LIBUSB_CONTROL_SETUP_SIZE + 1] = LIBUSB_DT_STRING;
    status = LIBUSB_TRANSFER_COMPLETED;
  } else {
    // Otherwise we should have a `{value, error}` object by now (see
    // `em_start_transfer_impl` callback).
    promise_result result(std::move(result_val));

    thread_local const val web_usb_transfer_status_ok("ok");
    thread_local const val web_usb_transfer_status_stall("stall");
    thread_local const val web_usb_transfer_status_babble("babble");

    if (!result.error) {
      auto web_usb_transfer_status = result.value["status"];
      if (web_usb_transfer_status == web_usb_transfer_status_ok) {
        status = LIBUSB_TRANSFER_COMPLETED;
      } else if (web_usb_transfer_status == web_usb_transfer_status_stall) {
        status = LIBUSB_TRANSFER_STALL;
      } else if (web_usb_transfer_status == web_usb_transfer_status_babble) {
        status = LIBUSB_TRANSFER_OVERFLOW;
      }

      int skip;
      unsigned char endpointDir;

      if (transfer->type == LIBUSB_TRANSFER_TYPE_CONTROL) {
        skip = LIBUSB_CONTROL_SETUP_SIZE;
        endpointDir =
            libusb_control_transfer_get_setup(transfer)->bmRequestType;
      } else {
        skip = 0;
        endpointDir = transfer->endpoint;
      }

      if (endpointDir & LIBUSB_ENDPOINT_IN) {
        auto data = result.value["data"];
        if (!data.isNull()) {
          itransfer->transferred = data["byteLength"].as<int>();
          val(typed_memory_view(transfer->length - skip,
                                transfer->buffer + skip))
              .call<void>("set", Uint8Array.new_(data["buffer"]));
        }
      } else {
        itransfer->transferred = result.value["bytesWritten"].as<int>();
      }
    }
  }

  return usbi_handle_transfer_completion(itransfer, status);
}
}  // namespace

extern "C" {
const usbi_os_backend usbi_backend = {
    .name = "Emscripten + WebUSB backend",
    .caps = LIBUSB_CAP_HAS_CAPABILITY,
    .get_device_list = em_get_device_list,
    .open = em_open,
    .close = em_close,
    .get_active_config_descriptor = em_get_active_config_descriptor,
    .get_config_descriptor = em_get_config_descriptor,
    .get_configuration = em_get_configuration,
    .set_configuration = em_set_configuration,
    .claim_interface = em_claim_interface,
    .release_interface = em_release_interface,
    .set_interface_altsetting = em_set_interface_altsetting,
    .clear_halt = em_clear_halt,
    .reset_device = em_reset_device,
    .destroy_device = em_destroy_device,
    .submit_transfer = em_submit_transfer,
    .cancel_transfer = em_cancel_transfer,
    .clear_transfer_priv = em_clear_transfer_priv,
    .handle_transfer_completion = em_handle_transfer_completion,
    .device_priv_size = sizeof(val),
    .transfer_priv_size = sizeof(val),
};

EMSCRIPTEN_KEEPALIVE
void em_signal_transfer_completion(usbi_transfer *itransfer) {
  usbi_signal_transfer_completion(itransfer);
}
}
#pragma clang diagnostic pop