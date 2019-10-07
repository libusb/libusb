/*
 * windows UsbDk backend for libusb 1.0
 * Copyright © 2014 Red Hat, Inc.

 * Authors:
 * Dmitry Fleytman <dmitry@daynix.com>
 * Pavel Gurvich <pavel@daynix.com>
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

#include <config.h>

#include <windows.h>
#include <stdio.h>
#include <setupapi.h>
#include <wctype.h>
#include <wchar.h>

#include "libusbi.h"
#include "windows_common.h"
#include "windows_nt_common.h"
#include "windows_usbdk.h"

#define MAX_PATH_LENGTH		128
// Missing from MSVC6 setupapi.h
#ifndef SPDRP_ADDRESS
#define SPDRP_ADDRESS		28
#endif

#if !defined(STATUS_SUCCESS)
typedef LONG NTSTATUS;
#define STATUS_SUCCESS			((NTSTATUS)0x00000000L)
#endif

#if !defined(STATUS_CANCELLED)
#define STATUS_CANCELLED		((NTSTATUS)0xC0000120L)
#endif

#if !defined(STATUS_REQUEST_CANCELED)
#define STATUS_REQUEST_CANCELED		((NTSTATUS)0xC0000703L)
#endif

#if !defined(USBD_SUCCESS)
typedef LONG USBD_STATUS;
#define USBD_SUCCESS(Status)		((USBD_STATUS) (Status) >= 0)
#define USBD_PENDING(Status)		((ULONG) (Status) >> 30 == 1)
#define USBD_ERROR(Status)		((USBD_STATUS) (Status) < 0)
#define USBD_STATUS_STALL_PID		((USBD_STATUS) 0xc0000004)
#define USBD_STATUS_ENDPOINT_HALTED	((USBD_STATUS) 0xc0000030)
#define USBD_STATUS_BAD_START_FRAME	((USBD_STATUS) 0xc0000a00)
#define USBD_STATUS_TIMEOUT		((USBD_STATUS) 0xc0006000)
#define USBD_STATUS_CANCELED		((USBD_STATUS) 0xc0010000)
#endif

static inline struct usbdk_device_priv *_usbdk_device_priv(struct libusb_device *dev)
{
	return (struct usbdk_device_priv *)dev->os_priv;
}

static inline struct usbdk_transfer_priv *_usbdk_transfer_priv(struct usbi_transfer *itransfer)
{
	return (struct usbdk_transfer_priv *)usbi_transfer_get_os_priv(itransfer);
}

static struct {
	HMODULE module;

	USBDK_GET_DEVICES_LIST			GetDevicesList;
	USBDK_RELEASE_DEVICES_LIST		ReleaseDevicesList;
	USBDK_START_REDIRECT			StartRedirect;
	USBDK_STOP_REDIRECT			StopRedirect;
	USBDK_GET_CONFIGURATION_DESCRIPTOR	GetConfigurationDescriptor;
	USBDK_RELEASE_CONFIGURATION_DESCRIPTOR	ReleaseConfigurationDescriptor;
	USBDK_READ_PIPE				ReadPipe;
	USBDK_WRITE_PIPE			WritePipe;
	USBDK_ABORT_PIPE			AbortPipe;
	USBDK_RESET_PIPE			ResetPipe;
	USBDK_SET_ALTSETTING			SetAltsetting;
	USBDK_RESET_DEVICE			ResetDevice;
	USBDK_GET_REDIRECTOR_SYSTEM_HANDLE	GetRedirectorSystemHandle;
} usbdk_helper;

static FARPROC get_usbdk_proc_addr(struct libusb_context *ctx, LPCSTR api_name)
{
	FARPROC api_ptr = GetProcAddress(usbdk_helper.module, api_name);

	if (api_ptr == NULL)
		usbi_err(ctx, "UsbDkHelper API %s not found: %s", api_name, windows_error_str(0));

	return api_ptr;
}

static void unload_usbdk_helper_dll(void)
{
	if (usbdk_helper.module != NULL) {
		FreeLibrary(usbdk_helper.module);
		usbdk_helper.module = NULL;
	}
}

static int load_usbdk_helper_dll(struct libusb_context *ctx)
{
	usbdk_helper.module = LoadLibraryA("UsbDkHelper");
	if (usbdk_helper.module == NULL) {
		usbi_err(ctx, "Failed to load UsbDkHelper.dll: %s", windows_error_str(0));
		return LIBUSB_ERROR_NOT_FOUND;
	}

	usbdk_helper.GetDevicesList = (USBDK_GET_DEVICES_LIST)get_usbdk_proc_addr(ctx, "UsbDk_GetDevicesList");
	if (usbdk_helper.GetDevicesList == NULL)
		goto error_unload;

	usbdk_helper.ReleaseDevicesList = (USBDK_RELEASE_DEVICES_LIST)get_usbdk_proc_addr(ctx, "UsbDk_ReleaseDevicesList");
	if (usbdk_helper.ReleaseDevicesList == NULL)
		goto error_unload;

	usbdk_helper.StartRedirect = (USBDK_START_REDIRECT)get_usbdk_proc_addr(ctx, "UsbDk_StartRedirect");
	if (usbdk_helper.StartRedirect == NULL)
		goto error_unload;

	usbdk_helper.StopRedirect = (USBDK_STOP_REDIRECT)get_usbdk_proc_addr(ctx, "UsbDk_StopRedirect");
	if (usbdk_helper.StopRedirect == NULL)
		goto error_unload;

	usbdk_helper.GetConfigurationDescriptor = (USBDK_GET_CONFIGURATION_DESCRIPTOR)get_usbdk_proc_addr(ctx, "UsbDk_GetConfigurationDescriptor");
	if (usbdk_helper.GetConfigurationDescriptor == NULL)
		goto error_unload;

	usbdk_helper.ReleaseConfigurationDescriptor = (USBDK_RELEASE_CONFIGURATION_DESCRIPTOR)get_usbdk_proc_addr(ctx, "UsbDk_ReleaseConfigurationDescriptor");
	if (usbdk_helper.ReleaseConfigurationDescriptor == NULL)
		goto error_unload;

	usbdk_helper.ReadPipe = (USBDK_READ_PIPE)get_usbdk_proc_addr(ctx, "UsbDk_ReadPipe");
	if (usbdk_helper.ReadPipe == NULL)
		goto error_unload;

	usbdk_helper.WritePipe = (USBDK_WRITE_PIPE)get_usbdk_proc_addr(ctx, "UsbDk_WritePipe");
	if (usbdk_helper.WritePipe == NULL)
		goto error_unload;

	usbdk_helper.AbortPipe = (USBDK_ABORT_PIPE)get_usbdk_proc_addr(ctx, "UsbDk_AbortPipe");
	if (usbdk_helper.AbortPipe == NULL)
		goto error_unload;

	usbdk_helper.ResetPipe = (USBDK_RESET_PIPE)get_usbdk_proc_addr(ctx, "UsbDk_ResetPipe");
	if (usbdk_helper.ResetPipe == NULL)
		goto error_unload;

	usbdk_helper.SetAltsetting = (USBDK_SET_ALTSETTING)get_usbdk_proc_addr(ctx, "UsbDk_SetAltsetting");
	if (usbdk_helper.SetAltsetting == NULL)
		goto error_unload;

	usbdk_helper.ResetDevice = (USBDK_RESET_DEVICE)get_usbdk_proc_addr(ctx, "UsbDk_ResetDevice");
	if (usbdk_helper.ResetDevice == NULL)
		goto error_unload;

	usbdk_helper.GetRedirectorSystemHandle = (USBDK_GET_REDIRECTOR_SYSTEM_HANDLE)get_usbdk_proc_addr(ctx, "UsbDk_GetRedirectorSystemHandle");
	if (usbdk_helper.GetRedirectorSystemHandle == NULL)
		goto error_unload;

	return LIBUSB_SUCCESS;

error_unload:
	FreeLibrary(usbdk_helper.module);
	usbdk_helper.module = NULL;
	return LIBUSB_ERROR_NOT_FOUND;
}

/*
 * SetupAPI DLL functions
 */
static BOOL init_dlls(void)
{
	// Needed to get the driver name
	DLL_GET_HANDLE(SetupAPI);
	DLL_LOAD_FUNC_PREFIXED(SetupAPI, p, SetupDiEnumDeviceInfo, TRUE);
	DLL_LOAD_FUNC_PREFIXED(SetupAPI, p, SetupDiGetDeviceInstanceIdW, TRUE);
	DLL_LOAD_FUNC_PREFIXED(SetupAPI, p, SetupDiDestroyDeviceInfoList, TRUE);
	DLL_LOAD_FUNC_PREFIXED(SetupAPI, p, SetupDiGetClassDevsW, TRUE);
	DLL_LOAD_FUNC_PREFIXED(SetupAPI, p, SetupDiGetDeviceRegistryPropertyA, TRUE);

	return TRUE;
}

static void exit_dlls(void)
{
	DLL_FREE_HANDLE(SetupAPI);
}

static int usbdk_init(struct libusb_context *ctx)
{
	SC_HANDLE managerHandle;
	SC_HANDLE serviceHandle;

	// Load DLL imports
	if (!init_dlls()) {
		usbi_err(ctx, "could not resolve DLL functions");
		return LIBUSB_ERROR_OTHER;
	}

	managerHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (managerHandle == NULL) {
		usbi_warn(ctx, "failed to open service control manager: %s", windows_error_str(0));
		return LIBUSB_ERROR_OTHER;
	}

	serviceHandle = OpenServiceA(managerHandle, "UsbDk", GENERIC_READ);
	CloseServiceHandle(managerHandle);

	if (serviceHandle == NULL) {
		if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST)
			usbi_warn(ctx, "failed to open UsbDk service: %s", windows_error_str(0));
		return LIBUSB_ERROR_NOT_FOUND;
	}

	CloseServiceHandle(serviceHandle);

	return load_usbdk_helper_dll(ctx);
}

static void usbdk_exit(struct libusb_context *ctx)
{
	UNUSED(ctx);
	exit_dlls();
	unload_usbdk_helper_dll();
}

static int usbdk_get_session_id_for_device(struct libusb_context *ctx,
	PUSB_DK_DEVICE_ID id, unsigned long *session_id)
{
	// NOTE change usbdk_get_session_id_from_path too

	char dev_identity[ARRAYSIZE(id->DeviceID) + ARRAYSIZE(id->InstanceID) + 1];

	if (snprintf(dev_identity, sizeof(dev_identity), "%S%S", id->DeviceID, id->InstanceID) == -1) {
		usbi_warn(ctx, "cannot form device identity");
		return LIBUSB_ERROR_NOT_SUPPORTED;
	}

	*session_id = htab_hash(dev_identity);

	return LIBUSB_SUCCESS;
}

static int usbdk_get_session_id_from_path(TCHAR const *const path,
																					unsigned long *session_id)
{
	TCHAR const *pos = path;
	unsigned i = 0;
	unsigned sep = 0;
	char dev_identity[ARRAYSIZE(((PUSB_DK_DEVICE_ID)NULL)->DeviceID) +
										ARRAYSIZE(((PUSB_DK_DEVICE_ID)NULL)->InstanceID) + 1];

	// \\\\?\\USB#VID_1409&PID_8000#4102997464#{a5dcbf10-6530-11d2-901f-00c04fb951ed}
	// to
	//        USB\\VID_8087&PID_80084102997464

	if ('\\' == pos[0] && '\\' == pos[1]) {
		pos += 4;
	}
	for (;; ++pos, ++i) {
		if (*pos == '#' || *pos == '\\') {
			if (sep == 2) {
				dev_identity[i] = '\0';
				break;
			}
			if (sep == 1) {
				--i;
			} else {
				dev_identity[i] = '\\';
			}
			++sep;
		} else {
			dev_identity[i] = (char)*pos;
		}

		if (*pos == '\0') {
			break;
		}
	}
	usbi_dbg("%s<>%s", path, dev_identity);
	*session_id = htab_hash(dev_identity);
	return LIBUSB_SUCCESS;
}

/* First examine the given list for a device with the session id, then fall
 * back to the contexts device list */
static struct libusb_device *usbdk_get_recent_device_by_session_id(
	struct libusb_context *const ctx,
	struct	discovered_devs  *const  disc_devs, unsigned long const session_id)
{
	unsigned long long i;
	for (i = 0; disc_devs && i < disc_devs->len; ++i) {
		if (session_id == disc_devs->devices[i]->session_data) {
			return libusb_ref_device(disc_devs->devices[i]);
		}
	}
	return usbi_get_device_by_session_id(ctx, session_id);
}


static void usbdk_release_config_descriptors(struct usbdk_device_priv *p, uint8_t count)
{
	uint8_t i;

	for (i = 0; i < count; i++)
		usbdk_helper.ReleaseConfigurationDescriptor(p->config_descriptors[i]);

	free(p->config_descriptors);
	p->config_descriptors = NULL;
}

static int usbdk_cache_config_descriptors(struct libusb_context *ctx,
	struct usbdk_device_priv *p, PUSB_DK_DEVICE_INFO info)
{
	uint8_t i;
	USB_DK_CONFIG_DESCRIPTOR_REQUEST Request;
	Request.ID = info->ID;

	p->config_descriptors = calloc(info->DeviceDescriptor.bNumConfigurations, sizeof(PUSB_CONFIGURATION_DESCRIPTOR));
	if (p->config_descriptors == NULL) {
		usbi_err(ctx, "failed to allocate configuration descriptors holder");
		return LIBUSB_ERROR_NO_MEM;
	}

	for (i = 0; i < info->DeviceDescriptor.bNumConfigurations; i++) {
		ULONG Length;

		Request.Index = i;
		if (!usbdk_helper.GetConfigurationDescriptor(&Request, &p->config_descriptors[i], &Length)) {
			usbi_err(ctx, "failed to retrieve configuration descriptors");
			usbdk_release_config_descriptors(p, i);
			return LIBUSB_ERROR_OTHER;
		}
	}

	return LIBUSB_SUCCESS;
}

char *device_driver(struct libusb_context *ctx, HDEVINFO devInfo,
										SP_DEVINFO_DATA devInfoData)
{
	DWORD size;
	char *tmp;

	if (!pSetupDiGetDeviceRegistryPropertyA(devInfo, &devInfoData, SPDRP_SERVICE,
																					NULL, NULL, 0, &size)) {
		// NOTE we do not care - we only want to know the size
	}
	tmp = (char *)malloc(size);
	if (NULL != tmp) {
		if (!pSetupDiGetDeviceRegistryPropertyA(devInfo, &devInfoData,
																						SPDRP_SERVICE, NULL, (BYTE *)tmp,
																						size, &size)) {
			free(tmp);
			usbi_err(ctx, "Failed to obtain driver");
			return NULL;
		}
	}
	return tmp;
}

char *obtain_device_driver(struct libusb_context *ctx,
													 wchar_t const *const device_id)
{
	wchar_t *instance_id = NULL;
	SP_DEVINFO_DATA devInfoData;
	HDEVINFO devInfo = INVALID_HANDLE_VALUE;
	DWORD size = 0;
	char *ret = NULL;
	int n;

	usbi_dbg("Obtaining driver for %S", device_id);

	devInfo = pSetupDiGetClassDevsW(&GUID_DEVINTERFACE_USB_DEVICE, device_id, NULL,
																	DIGCF_DEVICEINTERFACE);
	if (devInfo == INVALID_HANDLE_VALUE) {
		usbi_err(ctx, "Failed to get DEVINFO for %S", device_id);
		return NULL;
	}

	for (n = 0;; n++) {
		safe_free(instance_id);

		if (NULL != ret) {
			break;
		}

		devInfoData.cbSize = sizeof(devInfoData);
		if (!pSetupDiEnumDeviceInfo(devInfo, n, &devInfoData)) {
			break;
		}

		if (!pSetupDiGetDeviceInstanceIdW(devInfo, &devInfoData, NULL, 0, &size)) {
			// NOTE we do not care - we only want to know the size
		}
		instance_id = (wchar_t *)malloc(sizeof(wchar_t) * size);
		if (instance_id == NULL) {
			goto cleanup;
		}
		if (!pSetupDiGetDeviceInstanceIdW(devInfo, &devInfoData, instance_id, size,
																			NULL)) {
			usbi_err(ctx, "Failed to get instance ID");
			continue;
		} else if (0 == wcscmp(device_id, instance_id)) {
			ret = device_driver(ctx, devInfo, devInfoData);
			continue;
		}
	}

cleanup:
	pSetupDiDestroyDeviceInfoList(devInfo);
	return ret;
}

void copy_sanitized(wchar_t *to, wchar_t const *const from)
{
	int i;

	for (i = 0; from[i] != L'\0'; ++i) {
		if (from[i] == L'#') {
			to[i] = L'\\';
		} else {
			to[i] = (wchar_t)towupper((wint_t)from[i]);
		}
	}
}

static inline int usbdk_device_priv_init(struct libusb_context *ctx,
																				 struct libusb_device *dev,
																				 PUSB_DK_DEVICE_INFO info)
{
	unsigned long long dev_id_len, ins_id_len, path_len;
	wchar_t *path;
	struct usbdk_device_priv *p = _usbdk_device_priv(dev);

	p->info = *info;
	p->active_configuration = 0;

	dev_id_len = wcslen(info->ID.DeviceID);
	ins_id_len = wcslen(info->ID.InstanceID);
	path_len = dev_id_len + 1 /* # */ + ins_id_len + 1 /* \0 */;
	assert(path_len < SIZE_MAX);
	path = (wchar_t *)malloc((size_t)(sizeof(wchar_t) * path_len));

	copy_sanitized(path, info->ID.DeviceID);
	path[dev_id_len] = L'\\';
	copy_sanitized(path + dev_id_len + 1, info->ID.InstanceID);
	path[path_len - 1] = L'\0';

	p->driver = obtain_device_driver(ctx, path);

	free(path);

	return usbdk_cache_config_descriptors(ctx, p, info);
}

static void usbdk_device_init(libusb_device *dev, PUSB_DK_DEVICE_INFO info)
{
	dev->bus_number = (uint8_t)info->FilterID;
	dev->port_number = (uint8_t)info->Port;
	dev->parent_dev = NULL;

	// Addresses in libusb are 1-based
	dev->device_address = (uint8_t)(info->Port + 1);

	dev->num_configurations = info->DeviceDescriptor.bNumConfigurations;
	memcpy(&dev->device_descriptor, &info->DeviceDescriptor, LIBUSB_DT_DEVICE_SIZE);

	switch (info->Speed) {
	case LowSpeed:
		dev->speed = LIBUSB_SPEED_LOW;
		break;
	case FullSpeed:
		dev->speed = LIBUSB_SPEED_FULL;
		break;
	case HighSpeed:
		dev->speed = LIBUSB_SPEED_HIGH;
		break;
	case SuperSpeed:
		dev->speed = LIBUSB_SPEED_SUPER;
		break;
	case NoSpeed:
	default:
		dev->speed = LIBUSB_SPEED_UNKNOWN;
		break;
	}
}

static int usbdk_get_device_list(struct libusb_context *ctx, struct discovered_devs **_discdevs)
{
	int r = LIBUSB_SUCCESS;
	ULONG i;
	struct discovered_devs *discdevs = NULL;
	ULONG dev_number;
	PUSB_DK_DEVICE_INFO devices;

	if (!usbdk_helper.GetDevicesList(&devices, &dev_number))
		return LIBUSB_ERROR_OTHER;

	for (i = 0; i < dev_number; i++) {
		unsigned long session_id;
		struct libusb_device *dev = NULL;

		if (usbdk_get_session_id_for_device(ctx, &devices[i].ID, &session_id))
			continue;

		dev = usbdk_get_recent_device_by_session_id(ctx, discdevs, session_id);
		if (dev == NULL) {
			dev = usbi_alloc_device(ctx, session_id);
			if (dev == NULL) {
				usbi_err(ctx, "failed to allocate a new device structure");
				continue;
			}

			usbdk_device_init(dev, &devices[i]);
			if (usbdk_device_priv_init(ctx, dev, &devices[i]) != LIBUSB_SUCCESS) {
				libusb_unref_device(dev);
				continue;
			}
		}

		discdevs = discovered_devs_append(*_discdevs, dev);
		libusb_unref_device(dev);
		if (!discdevs) {
			usbi_err(ctx, "cannot append new device to list");
			r = LIBUSB_ERROR_NO_MEM;
			goto func_exit;
		}

		*_discdevs = discdevs;
	}

func_exit:
	usbdk_helper.ReleaseDevicesList(devices);
	return r;
}

static int usbdk_get_device_descriptor(struct libusb_device *dev, unsigned char *buffer)
{
	struct usbdk_device_priv *priv = _usbdk_device_priv(dev);

	memcpy(buffer, &priv->info.DeviceDescriptor, DEVICE_DESC_LENGTH);

	return LIBUSB_SUCCESS;
}

static int usbdk_get_config_descriptor(struct libusb_device *dev, uint8_t config_index, unsigned char *buffer, size_t len)
{
	struct usbdk_device_priv *priv = _usbdk_device_priv(dev);
	PUSB_CONFIGURATION_DESCRIPTOR config_header;
	size_t size;

	if (config_index >= dev->num_configurations)
		return LIBUSB_ERROR_INVALID_PARAM;

	config_header = (PUSB_CONFIGURATION_DESCRIPTOR)priv->config_descriptors[config_index];

	size = min(config_header->wTotalLength, len);
	memcpy(buffer, config_header, size);
	return (int)size;
}

static int usbdk_get_config_descriptor_by_value(struct libusb_device *dev, uint8_t bConfigurationValue,
	unsigned char **buffer)
{
	struct usbdk_device_priv *priv = _usbdk_device_priv(dev);
	PUSB_CONFIGURATION_DESCRIPTOR config_header;
	uint8_t index;

	for (index = 0; index < dev->num_configurations; index++) {
		config_header = priv->config_descriptors[index];
		if (config_header->bConfigurationValue == bConfigurationValue) {
			*buffer = (unsigned char *)priv->config_descriptors[index];
			return (int)config_header->wTotalLength;
		}
	}

	return LIBUSB_ERROR_NOT_FOUND;
}

static int usbdk_get_active_config_descriptor(struct libusb_device *dev, unsigned char *buffer, size_t len)
{
	return usbdk_get_config_descriptor(dev, _usbdk_device_priv(dev)->active_configuration,
			buffer, len);
}

static int usbdk_open(struct libusb_device_handle *dev_handle)
{
	struct usbdk_device_priv *priv = _usbdk_device_priv(dev_handle->dev);

	priv->redirector_handle = usbdk_helper.StartRedirect(&priv->info.ID);
	if (priv->redirector_handle == INVALID_HANDLE_VALUE) {
		usbi_err(DEVICE_CTX(dev_handle->dev), "Redirector startup failed");
		return LIBUSB_ERROR_OTHER;
	}

	priv->system_handle = usbdk_helper.GetRedirectorSystemHandle(priv->redirector_handle);

	return LIBUSB_SUCCESS;
}

static void usbdk_close(struct libusb_device_handle *dev_handle)
{
	struct usbdk_device_priv *priv = _usbdk_device_priv(dev_handle->dev);

	if (!usbdk_helper.StopRedirect(priv->redirector_handle))
		usbi_err(HANDLE_CTX(dev_handle), "Redirector shutdown failed");
}

static int usbdk_get_configuration(struct libusb_device_handle *dev_handle, int *config)
{
	*config = _usbdk_device_priv(dev_handle->dev)->active_configuration;

	return LIBUSB_SUCCESS;
}

static int usbdk_set_configuration(struct libusb_device_handle *dev_handle, int config)
{
	UNUSED(dev_handle);
	UNUSED(config);
	return LIBUSB_SUCCESS;
}

static int usbdk_claim_interface(struct libusb_device_handle *dev_handle, int iface)
{
	UNUSED(dev_handle);
	UNUSED(iface);
	return LIBUSB_SUCCESS;
}

static int usbdk_set_interface_altsetting(struct libusb_device_handle *dev_handle, int iface, int altsetting)
{
	struct libusb_context *ctx = HANDLE_CTX(dev_handle);
	struct usbdk_device_priv *priv = _usbdk_device_priv(dev_handle->dev);

	if (!usbdk_helper.SetAltsetting(priv->redirector_handle, iface, altsetting)) {
		usbi_err(ctx, "SetAltsetting failed: %s", windows_error_str(0));
		return LIBUSB_ERROR_NO_DEVICE;
	}

	return LIBUSB_SUCCESS;
}

static int usbdk_release_interface(struct libusb_device_handle *dev_handle, int iface)
{
	UNUSED(dev_handle);
	UNUSED(iface);
	return LIBUSB_SUCCESS;
}

static int usbdk_clear_halt(struct libusb_device_handle *dev_handle, unsigned char endpoint)
{
	struct libusb_context *ctx = HANDLE_CTX(dev_handle);
	struct usbdk_device_priv *priv = _usbdk_device_priv(dev_handle->dev);

	if (!usbdk_helper.ResetPipe(priv->redirector_handle, endpoint)) {
		usbi_err(ctx, "ResetPipe failed: %s", windows_error_str(0));
		return LIBUSB_ERROR_NO_DEVICE;
	}

	return LIBUSB_SUCCESS;
}

static int usbdk_reset_device(struct libusb_device_handle *dev_handle)
{
	struct libusb_context *ctx = HANDLE_CTX(dev_handle);
	struct usbdk_device_priv *priv = _usbdk_device_priv(dev_handle->dev);

	if (!usbdk_helper.ResetDevice(priv->redirector_handle)) {
		usbi_err(ctx, "ResetDevice failed: %s", windows_error_str(0));
		return LIBUSB_ERROR_NO_DEVICE;
	}

	return LIBUSB_SUCCESS;
}

static void usbdk_destroy_device(struct libusb_device *dev)
{
	struct usbdk_device_priv* p = _usbdk_device_priv(dev);

	if (p->config_descriptors != NULL)
		usbdk_release_config_descriptors(p, p->info.DeviceDescriptor.bNumConfigurations);
    if (p->driver != NULL)
        free(p->driver);
}

static void usbdk_clear_transfer_priv(struct usbi_transfer *itransfer)
{
	struct usbdk_transfer_priv *transfer_priv = _usbdk_transfer_priv(itransfer);
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);

	usbi_close(transfer_priv->pollable_fd.fd);
	transfer_priv->pollable_fd = INVALID_WINFD;
	transfer_priv->system_handle = NULL;

	if (transfer->type == LIBUSB_TRANSFER_TYPE_ISOCHRONOUS) {
		safe_free(transfer_priv->IsochronousPacketsArray);
		safe_free(transfer_priv->IsochronousResultsArray);
	}
}

static int usbdk_do_control_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct usbdk_device_priv *priv = _usbdk_device_priv(transfer->dev_handle->dev);
	struct usbdk_transfer_priv *transfer_priv = _usbdk_transfer_priv(itransfer);
	struct libusb_context *ctx = TRANSFER_CTX(transfer);
	OVERLAPPED *overlapped = transfer_priv->pollable_fd.overlapped;
	TransferResult transResult;

	transfer_priv->request.Buffer = (PVOID64)transfer->buffer;
	transfer_priv->request.BufferLength = transfer->length;
	transfer_priv->request.TransferType = ControlTransferType;

	if (transfer->buffer[0] & LIBUSB_ENDPOINT_IN)
		transResult = usbdk_helper.ReadPipe(priv->redirector_handle, &transfer_priv->request, overlapped);
	else
		transResult = usbdk_helper.WritePipe(priv->redirector_handle, &transfer_priv->request, overlapped);

	switch (transResult) {
	case TransferSuccess:
		windows_force_sync_completion(overlapped, (ULONG)transfer_priv->request.Result.GenResult.BytesTransferred);
		break;
	case TransferSuccessAsync:
		break;
	case TransferFailure:
		usbi_err(ctx, "ControlTransfer failed: %s", windows_error_str(0));
		return LIBUSB_ERROR_IO;
	}

	return LIBUSB_SUCCESS;
}

static int usbdk_do_bulk_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct usbdk_device_priv *priv = _usbdk_device_priv(transfer->dev_handle->dev);
	struct usbdk_transfer_priv *transfer_priv = _usbdk_transfer_priv(itransfer);
	struct libusb_context *ctx = TRANSFER_CTX(transfer);
	OVERLAPPED *overlapped = transfer_priv->pollable_fd.overlapped;
	TransferResult transferRes;

	transfer_priv->request.Buffer = (PVOID64)transfer->buffer;
	transfer_priv->request.BufferLength = transfer->length;
	transfer_priv->request.EndpointAddress = transfer->endpoint;

	switch (transfer->type) {
	case LIBUSB_TRANSFER_TYPE_BULK:
		transfer_priv->request.TransferType = BulkTransferType;
		break;
	case LIBUSB_TRANSFER_TYPE_INTERRUPT:
		transfer_priv->request.TransferType = InterruptTransferType;
		break;
	default:
		usbi_err(ctx, "Wrong transfer type (%d) in usbdk_do_bulk_transfer", transfer->type);
		return LIBUSB_ERROR_INVALID_PARAM;
	}

	if (IS_XFERIN(transfer))
		transferRes = usbdk_helper.ReadPipe(priv->redirector_handle, &transfer_priv->request, overlapped);
	else
		transferRes = usbdk_helper.WritePipe(priv->redirector_handle, &transfer_priv->request, overlapped);

	switch (transferRes) {
	case TransferSuccess:
		windows_force_sync_completion(overlapped, (ULONG)transfer_priv->request.Result.GenResult.BytesTransferred);
		break;
	case TransferSuccessAsync:
		break;
	case TransferFailure:
		usbi_err(ctx, "ReadPipe/WritePipe failed: %s", windows_error_str(0));
		return LIBUSB_ERROR_IO;
	}

	return LIBUSB_SUCCESS;
}

static int usbdk_do_iso_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct usbdk_device_priv *priv = _usbdk_device_priv(transfer->dev_handle->dev);
	struct usbdk_transfer_priv *transfer_priv = _usbdk_transfer_priv(itransfer);
	struct libusb_context *ctx = TRANSFER_CTX(transfer);
	OVERLAPPED *overlapped = transfer_priv->pollable_fd.overlapped;
	TransferResult transferRes;
	int i;

	transfer_priv->request.Buffer = (PVOID64)transfer->buffer;
	transfer_priv->request.BufferLength = transfer->length;
	transfer_priv->request.EndpointAddress = transfer->endpoint;
	transfer_priv->request.TransferType = IsochronousTransferType;
	transfer_priv->request.IsochronousPacketsArraySize = transfer->num_iso_packets;
	transfer_priv->IsochronousPacketsArray = malloc(transfer->num_iso_packets * sizeof(ULONG64));
	transfer_priv->request.IsochronousPacketsArray = (PVOID64)transfer_priv->IsochronousPacketsArray;
	if (!transfer_priv->IsochronousPacketsArray) {
		usbi_err(ctx, "Allocation of IsochronousPacketsArray failed");
		return LIBUSB_ERROR_NO_MEM;
	}

	transfer_priv->IsochronousResultsArray = malloc(transfer->num_iso_packets * sizeof(USB_DK_ISO_TRANSFER_RESULT));
	transfer_priv->request.Result.IsochronousResultsArray = (PVOID64)transfer_priv->IsochronousResultsArray;
	if (!transfer_priv->IsochronousResultsArray) {
		usbi_err(ctx, "Allocation of isochronousResultsArray failed");
		return LIBUSB_ERROR_NO_MEM;
	}

	for (i = 0; i < transfer->num_iso_packets; i++)
		transfer_priv->IsochronousPacketsArray[i] = transfer->iso_packet_desc[i].length;

	if (IS_XFERIN(transfer))
		transferRes = usbdk_helper.ReadPipe(priv->redirector_handle, &transfer_priv->request, overlapped);
	else
		transferRes = usbdk_helper.WritePipe(priv->redirector_handle, &transfer_priv->request, overlapped);

	switch (transferRes) {
	case TransferSuccess:
		windows_force_sync_completion(overlapped, (ULONG)transfer_priv->request.Result.GenResult.BytesTransferred);
		break;
	case TransferSuccessAsync:
		break;
	case TransferFailure:
		return LIBUSB_ERROR_IO;
	}

	return LIBUSB_SUCCESS;
}

static int usbdk_do_submit_transfer(struct usbi_transfer *itransfer,
	short events, int (*transfer_fn)(struct usbi_transfer *))
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = TRANSFER_CTX(transfer);
	struct usbdk_device_priv *priv = _usbdk_device_priv(transfer->dev_handle->dev);
	struct usbdk_transfer_priv *transfer_priv = _usbdk_transfer_priv(itransfer);
	struct winfd wfd;
	int r;

	wfd = usbi_create_fd();
	if (wfd.fd < 0)
		return LIBUSB_ERROR_NO_MEM;

	r = usbi_add_pollfd(ctx, wfd.fd, events);
	if (r) {
		usbi_close(wfd.fd);
		return r;
	}

	// Use transfer_priv to store data needed for async polling
	transfer_priv->pollable_fd = wfd;
	transfer_priv->system_handle = priv->system_handle;

	r = transfer_fn(itransfer);
	if (r != LIBUSB_SUCCESS) {
		usbi_remove_pollfd(ctx, wfd.fd);
		usbdk_clear_transfer_priv(itransfer);
		return r;
	}

	return LIBUSB_SUCCESS;
}

static int usbdk_submit_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	int (*transfer_fn)(struct usbi_transfer *);
	short events;

	switch (transfer->type) {
	case LIBUSB_TRANSFER_TYPE_CONTROL:
		events = (transfer->buffer[0] & LIBUSB_ENDPOINT_IN) ? POLLIN : POLLOUT;
		transfer_fn = usbdk_do_control_transfer;
		break;
	case LIBUSB_TRANSFER_TYPE_BULK:
	case LIBUSB_TRANSFER_TYPE_INTERRUPT:
		if (IS_XFEROUT(transfer) && (transfer->flags & LIBUSB_TRANSFER_ADD_ZERO_PACKET))
			return LIBUSB_ERROR_NOT_SUPPORTED; //TODO: Check whether we can support this in UsbDk
		events = IS_XFERIN(transfer) ? POLLIN : POLLOUT;
		transfer_fn = usbdk_do_bulk_transfer;
		break;
	case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
		events = IS_XFERIN(transfer) ? POLLIN : POLLOUT;
		transfer_fn = usbdk_do_iso_transfer;
		break;
	default:
		usbi_err(TRANSFER_CTX(transfer), "unknown endpoint type %d", transfer->type);
		return LIBUSB_ERROR_INVALID_PARAM;
	}

	return usbdk_do_submit_transfer(itransfer, events, transfer_fn);
}

static int usbdk_abort_transfers(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = TRANSFER_CTX(transfer);
	struct usbdk_device_priv *priv = _usbdk_device_priv(transfer->dev_handle->dev);
	struct usbdk_transfer_priv *transfer_priv = _usbdk_transfer_priv(itransfer);
	struct winfd *pollable_fd = &transfer_priv->pollable_fd;

	if (pCancelIoEx != NULL) {
		// Use CancelIoEx if available to cancel just a single transfer
		if (!pCancelIoEx(priv->system_handle, pollable_fd->overlapped)) {
			usbi_err(ctx, "CancelIoEx failed: %s", windows_error_str(0));
			return LIBUSB_ERROR_NO_DEVICE;
		}
	} else {
		if (!usbdk_helper.AbortPipe(priv->redirector_handle, transfer->endpoint)) {
			usbi_err(ctx, "AbortPipe failed: %s", windows_error_str(0));
			return LIBUSB_ERROR_NO_DEVICE;
		}
	}

	return LIBUSB_SUCCESS;
}

static int usbdk_cancel_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);

	switch (transfer->type) {
	case LIBUSB_TRANSFER_TYPE_CONTROL:
		// Control transfers cancelled by IoCancelXXX() API
		// No special treatment needed
		return LIBUSB_SUCCESS;
	case LIBUSB_TRANSFER_TYPE_BULK:
	case LIBUSB_TRANSFER_TYPE_INTERRUPT:
	case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
		return usbdk_abort_transfers(itransfer);
	default:
		usbi_err(ITRANSFER_CTX(itransfer), "unknown endpoint type %d", transfer->type);
		return LIBUSB_ERROR_INVALID_PARAM;
	}
}

static int usbdk_copy_transfer_data(struct usbi_transfer *itransfer, uint32_t io_size)
{
	itransfer->transferred += io_size;
	return LIBUSB_TRANSFER_COMPLETED;
}

static int usbdk_get_transfer_fd(struct usbi_transfer *itransfer)
{
	struct usbdk_transfer_priv *transfer_priv = _usbdk_transfer_priv(itransfer);
	return transfer_priv->pollable_fd.fd;
}

static DWORD usbdk_translate_usbd_status(USBD_STATUS UsbdStatus)
{
	if (USBD_SUCCESS(UsbdStatus))
		return NO_ERROR;

	switch (UsbdStatus) {
	case USBD_STATUS_TIMEOUT:
		return ERROR_SEM_TIMEOUT;
	case USBD_STATUS_CANCELED:
		return ERROR_OPERATION_ABORTED;
	default:
		return ERROR_GEN_FAILURE;
	}
}

static void usbdk_get_overlapped_result(struct usbi_transfer *itransfer, DWORD *io_result, DWORD *io_size)
{
	struct usbdk_transfer_priv *transfer_priv = _usbdk_transfer_priv(itransfer);
	struct winfd *pollable_fd = &transfer_priv->pollable_fd;

	if (HasOverlappedIoCompletedSync(pollable_fd->overlapped) // Handle async requests that completed synchronously first
			|| GetOverlappedResult(transfer_priv->system_handle, pollable_fd->overlapped, io_size, FALSE)) { // Regular async overlapped
		struct libusb_transfer *transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);

		if (transfer->type == LIBUSB_TRANSFER_TYPE_ISOCHRONOUS) {
			ULONG64 i;
			for (i = 0; i < transfer_priv->request.IsochronousPacketsArraySize; i++) {
				struct libusb_iso_packet_descriptor *lib_desc = &transfer->iso_packet_desc[i];

				switch (transfer_priv->IsochronousResultsArray[i].TransferResult) {
				case STATUS_SUCCESS:
				case STATUS_CANCELLED:
				case STATUS_REQUEST_CANCELED:
					lib_desc->status = LIBUSB_TRANSFER_COMPLETED; // == ERROR_SUCCESS
					break;
				default:
					lib_desc->status = LIBUSB_TRANSFER_ERROR; // ERROR_UNKNOWN_EXCEPTION;
					break;
				}

				lib_desc->actual_length = (unsigned int)transfer_priv->IsochronousResultsArray[i].ActualLength;
			}
		}

		*io_size = (DWORD)transfer_priv->request.Result.GenResult.BytesTransferred;
		*io_result = usbdk_translate_usbd_status((USBD_STATUS)transfer_priv->request.Result.GenResult.UsbdStatus);
	} else {
		*io_result = GetLastError();
	}
}

static int usbdk_get_device_driver(struct libusb_device *device, char *driver,
																	 int size)
{
	char const *const drv = _usbdk_device_priv(device)->driver;
	if (size > 0 && driver) {
		driver[0] = '\0';
		if (drv) {
			strncat(driver, drv, size - 1);
		}
	}
	return drv ? (int)strnlen(drv, MAX_PATH_LENGTH) : 0;
}

static void usbdk_enumerate_device(struct libusb_context *ctx,
																	 TCHAR const *const device_path)
{
	unsigned long new_device_id;
	unsigned long device_id=0;
	ULONG i, dev_number;
	PUSB_DK_DEVICE_INFO devices;
	struct libusb_device *dev = NULL;

	usbdk_get_session_id_from_path(device_path, &new_device_id);

	// NOTE In case that the device is already known do not try to reenumerate it - this can happen in combination with
	//      windows_scan_devices
	usbi_mutex_lock(&ctx->usb_devs_lock);
	list_for_each_entry(dev, &ctx->usb_devs, list, struct libusb_device)
		if (dev->session_data == new_device_id) {
			usbi_mutex_unlock(&ctx->usb_devs_lock);
			return;
		}

	if (!usbdk_helper.GetDevicesList(&devices, &dev_number)) {
		usbi_mutex_unlock(&ctx->usb_devs_lock);
		return;
	}

	for (i = 0; i < dev_number; ++i) {
		usbdk_get_session_id_for_device(ctx, &devices[i].ID, &device_id);
		if (new_device_id == device_id) {
			break;
		}
	}

	dev = usbi_alloc_device(ctx, device_id);
	if (dev == NULL) {
		usbi_err(ctx, "failed to allocate a new device structure");
		usbi_mutex_unlock(&ctx->usb_devs_lock);
		return;
	}

	usbdk_device_init(dev, &devices[i]);
	if (usbdk_device_priv_init(ctx, dev, &devices[i]) != LIBUSB_SUCCESS) {
		libusb_unref_device(dev);
		usbi_mutex_unlock(&ctx->usb_devs_lock);
		return;
	}

	usbi_connect_device(dev);
	usbi_mutex_unlock(&ctx->usb_devs_lock);
}

static void usbdk_disconnect_device(struct libusb_context *ctx,
																		TCHAR const *const device_path)
{
	unsigned long new_device_id;
	struct libusb_device *dev = NULL;

	usbdk_get_session_id_from_path(device_path, &new_device_id);

	usbi_mutex_lock(&ctx->usb_devs_lock);
	list_for_each_entry (dev, &ctx->usb_devs, list, struct libusb_device)
		if (dev->session_data == new_device_id) {
			libusb_ref_device(dev);
			usbi_disconnect_device(dev);
			libusb_unref_device(dev);
			break;
		}
	usbi_mutex_unlock(&ctx->usb_devs_lock);
}

const struct windows_backend usbdk_backend = {
	usbdk_init,
	usbdk_exit,
	usbdk_get_device_list,
	usbdk_open,
	usbdk_close,
	usbdk_enumerate_device,
	usbdk_disconnect_device,
	usbdk_get_device_driver,
	usbdk_get_device_descriptor,
	usbdk_get_active_config_descriptor,
	usbdk_get_config_descriptor,
	usbdk_get_config_descriptor_by_value,
	usbdk_get_configuration,
	usbdk_set_configuration,
	usbdk_claim_interface,
	usbdk_release_interface,
	usbdk_set_interface_altsetting,
	usbdk_clear_halt,
	usbdk_reset_device,
	usbdk_destroy_device,
	usbdk_submit_transfer,
	usbdk_cancel_transfer,
	usbdk_clear_transfer_priv,
	usbdk_copy_transfer_data,
	usbdk_get_transfer_fd,
	usbdk_get_overlapped_result,
};
