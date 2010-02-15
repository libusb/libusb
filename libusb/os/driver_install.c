#if defined(_MSC_VER)
#include <config_msvc.h>
#else
#include <config.h>
#endif
#include <windows.h>
#include <setupapi.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <process.h>
#include <stdio.h>
#include <inttypes.h>
#include <objbase.h>  // for GUID ops. requires libole32.a

#include "libusbi.h"
#include "windows_usb.h"
#include "driver_install.h"

char* guid_to_string(const GUID guid)
{
	static char guid_string[MAX_GUID_STRING_LENGTH];
	
	sprintf(guid_string, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		(unsigned int)guid.Data1, guid.Data2, guid.Data3, 
		guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
	return guid_string;
}

void free_di(struct driver_info *start)
{
	struct driver_info *tmp;
	while(start != NULL) {
		tmp = start;
		start = start->next;
		free(tmp);
	}
}

struct driver_info* list_driverless(void)
{
	unsigned i, j;
	struct libusb_context *ctx = NULL;
	DWORD size, reg_type, install_state;
	CONFIGRET r;
	HDEVINFO dev_info;
	SP_DEVINFO_DATA dev_info_data;
	SP_DEVICE_INTERFACE_DETAIL_DATA *dev_interface_details = NULL;
	char *sanitized_short = NULL;
	char *prefix[3] = {"VID_", "PID_", "MI_"};
//	char *designation[3] = {"VendorID", "ProductID", "InterfaceID"};
	char *token;
	char path[MAX_PATH_LENGTH];
	char desc[MAX_DESC_LENGTH];
	struct driver_info *ret = NULL, *cur = NULL, *drv_info;

	// List all connected USB devices
	dev_info = SetupDiGetClassDevs(NULL, "USB", NULL, DIGCF_PRESENT|DIGCF_ALLCLASSES);
	if (dev_info == INVALID_HANDLE_VALUE) {
		return NULL;
	}

	// Find the ones that are driverless
	for (i = 0; ; i++)
	{
		safe_free(sanitized_short);

		dev_info_data.cbSize = sizeof(dev_info_data);
		if (!SetupDiEnumDeviceInfo(dev_info, i, &dev_info_data)) {
			break;
		}

		if ( (!SetupDiGetDeviceRegistryProperty(dev_info, &dev_info_data, SPDRP_INSTALL_STATE, 
			&reg_type, (BYTE*)&install_state, 4, &size)) 
		  && (size != 4) ) {
			usbi_warn(ctx, "could not detect installation state of driver for %d: %s", 
				i, windows_error_str(0));
			continue;
		} 
		if (install_state != InstallStateFailedInstall) {
			continue;
		}

		if ( (!SetupDiGetDeviceRegistryProperty(dev_info, &dev_info_data, SPDRP_DEVICEDESC, 
			&reg_type, (BYTE*)desc, MAX_KEY_LENGTH, &size)) ) {
			usbi_warn(ctx, "could not read device description for %d: %s", 
				i, windows_error_str(0));
			continue;
		}

		r = CM_Get_Device_ID(dev_info_data.DevInst, path, MAX_PATH_LENGTH, 0);
		if (r != CR_SUCCESS) {
			usbi_err(ctx, "could not retrieve simple path for device %d: CR error %d", 
				i, r);
			continue;
		}
		sanitized_short = sanitize_path(path);
		if (sanitized_short == NULL) {
			usbi_err(ctx, "could not sanitize path for device %d", i);
			continue;
		}
		usbi_dbg("Driverless USB device (%d): %s", i, sanitized_short);
//		usbi_dbg("  DeviceName = \"%s\"", desc);

		drv_info = calloc(1, sizeof(struct driver_info));
		if (drv_info == NULL) {
			free_di(ret);
			return NULL;
		}
		if (cur == NULL) {
			ret = drv_info;
		} else {
			cur->next = drv_info;
		}
		cur = drv_info;

		safe_strcpy(drv_info->desc, sizeof(drv_info->desc), desc);

		token = strtok (sanitized_short, "#&");
		while(token != NULL) {
			for (j = 0; j < 3; j++) {
				if (safe_strncmp(token, prefix[j], strlen(prefix[j])) == 0) {
					switch(j) {
					case 0:
						safe_strcpy(drv_info->vid, sizeof(drv_info->vid), token);
						break;
					case 1:
						safe_strcpy(drv_info->pid, sizeof(drv_info->pid), token);
						break;
					case 2:
						safe_strcpy(drv_info->mi, sizeof(drv_info->mi), token);
						break;
					default:
						usbi_err(ctx, "unexpected case");
						break;
					}
				}
			}
			token = strtok (NULL, "#&");
		}
		CoCreateGuid(&drv_info->dev_guid);

//		usbi_dbg("  DeviceGUID = \"%s\"", guid_to_string(drv_info->dev_guid));
	}
	return ret;
}