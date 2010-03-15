#include <config.h>
#include <windows.h>
#include <setupapi.h>
#include <io.h>
#include <stdio.h>
#include <inttypes.h>
#include <objbase.h>  // for GUID ops. requires libole32.a
#include <api/difxapi.h>
#include <api/shellapi.h>

#include "libusbi.h"
#include "windows_usb.h"
#include "driver_install.h"
#include "driver_installer.h"

#define INF_NAME "libusb-device.inf"

const char inf[] = "Date = \"03/08/2010\"\n\n" \
	"ProviderName = \"libusb 1.0\"\n" \
	"WinUSB_SvcDesc = \"WinUSB Driver Service\"\n" \
	"DiskName = \"libusb (WinUSB) Device Install Disk\"\n" \
	"ClassName = \"libusb (WinUSB) devices\"\n\n" \
	"[Version]\n" \
	"DriverVer = %Date%,1\n" \
	"Signature = \"$Windows NT$\"\n" \
	"Class = %ClassName%\n" \
	"ClassGuid = {78a1c341-4539-11d3-b88d-00c04fad5171}\n" \
	"Provider = %ProviderName%\n" \
	"CatalogFile = libusb_device.cat\n\n" \
	"[ClassInstall32]\n" \
	"Addreg = WinUSBDeviceClassReg\n\n" \
	"[WinUSBDeviceClassReg]\n" \
	"HKR,,,0,%ClassName%\n" \
	"HKR,,Icon,,-20\n\n" \
	"[Manufacturer]\n" \
	"%ProviderName% = libusbDevice_WinUSB,NTx86,NTamd64\n\n" \
	"[libusbDevice_WinUSB.NTx86]\n" \
	"%DeviceName% = USB_Install, USB\\%DeviceID%\n\n" \
	"[libusbDevice_WinUSB.NTamd64]\n" \
	"%DeviceName% = USB_Install, USB\\%DeviceID%\n\n" \
	"[USB_Install]\n" \
	"Include=winusb.inf\n" \
	"Needs=WINUSB.NT\n\n" \
	"[USB_Install.Services]\n" \
	"Include=winusb.inf\n" \
	"AddService=WinUSB,0x00000002,WinUSB_ServiceInstall\n\n" \
	"[WinUSB_ServiceInstall]\n" \
	"DisplayName     = %WinUSB_SvcDesc%\n" \
	"ServiceType     = 1\n" \
	"StartType       = 3\n" \
	"ErrorControl    = 1\n" \
	"ServiceBinary   = %12%\\WinUSB.sys\n\n" \
	"[USB_Install.Wdf]\n" \
	"KmdfService=WINUSB, WinUsb_Install\n\n" \
	"[WinUSB_Install]\n" \
	"KmdfLibraryVersion=1.9\n\n" \
	"[USB_Install.HW]\n" \
	"AddReg=Dev_AddReg\n\n" \
	"[Dev_AddReg]\n" \
	"HKR,,DeviceInterfaceGUIDs,0x10000,%DeviceGUID%\n\n" \
	"[USB_Install.CoInstallers]\n" \
	"AddReg=CoInstallers_AddReg\n" \
	"CopyFiles=CoInstallers_CopyFiles\n\n" \
	"[CoInstallers_AddReg]\n" \
	"HKR,,CoInstallers32,0x00010000,\"WdfCoInstaller01009.dll,WdfCoInstaller\",\"WinUSBCoInstaller2.dll\"\n\n" \
	"[CoInstallers_CopyFiles]\n" \
	"WinUSBCoInstaller2.dll\n" \
	"WdfCoInstaller01009.dll\n\n" \
	"[DestinationDirs]\n" \
	"CoInstallers_CopyFiles=11\n\n" \
	"[SourceDisksNames]\n" \
	"1 = %DiskName%,,,\\x86\n" \
	"2 = %DiskName%,,,\\amd64\n" \
	"3 = %DiskName%,,,\\ia64\n\n" \
	"[SourceDisksFiles.x86]\n" \
	"WinUSBCoInstaller2.dll=1\n" \
	"WdfCoInstaller01009.dll=1\n\n" \
	"[SourceDisksFiles.amd64]\n" \
	"WinUSBCoInstaller2.dll=2\n" \
	"WdfCoInstaller01009.dll=2\n\n" \
	"[SourceDisksFiles.ia64]\n";

struct res {
	char* id;
	char* subdir;
	char* name;
};

const struct res resource[] = { {"AMD64_DLL1" , "amd64", "WdfCoInstaller01009.dll"},
								{"AMD64_DLL2" , "amd64", "winusbcoinstaller2.dll"},
								{"X86_DLL1", "x86", "WdfCoInstaller01009.dll"},
								{"X86_DLL2", "x86", "winusbcoinstaller2.dll"},
								{"AMD64_INSTALLER", ".", "installer_x64.exe"},
								{"X86_INSTALLER", ".", "installer_x86.exe"} };
const int nb_resources = sizeof(resource)/sizeof(resource[0]);
extern char *windows_error_str(uint32_t retval);

HANDLE pipe = INVALID_HANDLE_VALUE;
char* req_device_id;

// for 64 bit platforms detection
static BOOL (__stdcall *pIsWow64Process)(HANDLE, PBOOL) = NULL;


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

bool cfgmgr32_available = false;

static int init_cfgmgr32(void)
{
	DLL_LOAD(Cfgmgr32.dll, CM_Get_Parent, TRUE);
	DLL_LOAD(Cfgmgr32.dll, CM_Get_Child, TRUE);
	DLL_LOAD(Cfgmgr32.dll, CM_Get_Sibling, TRUE);
	DLL_LOAD(Cfgmgr32.dll, CM_Get_Device_IDA, TRUE); 
	DLL_LOAD(Cfgmgr32.dll, CM_Get_Device_IDW, TRUE);
	return LIBUSB_SUCCESS;
}

struct driver_info* list_driverless(void)
{
	unsigned i, j;
	DWORD size, reg_type;
	CONFIGRET r;
	HDEVINFO dev_info;
	SP_DEVINFO_DATA dev_info_data;
	SP_DEVICE_INTERFACE_DETAIL_DATA *dev_interface_details = NULL;
	char *sanitized_short = NULL;
	char *prefix[3] = {"VID_", "PID_", "MI_"};
	char *token;
	char path[MAX_PATH_LENGTH];
	char desc[MAX_DESC_LENGTH];
	char driver[MAX_DESC_LENGTH];
	struct driver_info *ret = NULL, *cur = NULL, *drv_info;
	bool driverless;

	if (!cfgmgr32_available) {
		init_cfgmgr32();
	}

	// List all connected USB devices
	dev_info = SetupDiGetClassDevs(NULL, "USB", NULL, DIGCF_PRESENT|DIGCF_ALLCLASSES);
	if (dev_info == INVALID_HANDLE_VALUE) {
		return NULL;
	}

	// Find the ones that are driverless
	for (i = 0; ; i++)
	{
		driverless = false;

		dev_info_data.cbSize = sizeof(dev_info_data);
		if (!SetupDiEnumDeviceInfo(dev_info, i, &dev_info_data)) {
			break;
		}

		// SPDRP_DRIVER seems to do a better job at detecting driverless devices than
		// SPDRP_INSTALL_STATE
		if ( SetupDiGetDeviceRegistryProperty(dev_info, &dev_info_data, SPDRP_DRIVER, 
			&reg_type, (BYTE*)driver, MAX_KEY_LENGTH, &size)) {
			// Driverless devices should return an error
			continue;
		}
//		usbi_dbg("driver: %s", driver);
/*
		if ( (!SetupDiGetDeviceRegistryProperty(dev_info, &dev_info_data, SPDRP_INSTALL_STATE, 
			&reg_type, (BYTE*)&install_state, 4, &size)) 
		  && (size != 4) ) {
			usbi_warn(NULL, "could not detect installation state of driver for %d: %s", 
				i, windows_error_str(0));
			continue;
		} 
		usbi_dbg("install state: %d", install_state);
		if ( (install_state != InstallStateFailedInstall)
		  && (SetupDiGetDeviceRegistryProperty(dev_info, &dev_info_data, SPDRP_DRIVER, 
			&reg_type, (BYTE*)driver, MAX_KEY_LENGTH, &size) != ERROR_INVALID_DATA) ) {
			continue;
		}
*/

		// TODO: can't always get a device desc => provide one
		if ( (!SetupDiGetDeviceRegistryProperty(dev_info, &dev_info_data, SPDRP_DEVICEDESC, 
			&reg_type, (BYTE*)desc, MAX_KEY_LENGTH, &size)) ) {
			usbi_warn(NULL, "could not read device description for %d: %s", 
				i, windows_error_str(0));
//			continue;
		}

		r = CM_Get_Device_ID(dev_info_data.DevInst, path, MAX_PATH_LENGTH, 0);
		if (r != CR_SUCCESS) {
			usbi_err(NULL, "could not retrieve simple path for device %d: CR error %d", 
				i, r);
			continue;
		}

		usbi_dbg("Driverless USB device (%d): %s", i, path);

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

		// duplicate for device id
		drv_info->device_id = _strdup(path);

		safe_strcpy(drv_info->desc, sizeof(drv_info->desc), desc);

		token = strtok (path, "\\#&");
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
						usbi_err(NULL, "unexpected case");
						break;
					}
				}
			}
			token = strtok (NULL, "\\#&");
		}
	}

	return ret;
}

int extract_binaries(char* path)
{
	HANDLE h;
	HGLOBAL h_load;
	void *data;
	DWORD size;
	char filename[MAX_PATH_LENGTH];
	FILE* fd;
	int i;

	for (i=0; i< nb_resources; i++) {
		h = FindResource(NULL, resource[i].id, "BIN");
		if (h == NULL) {
			usbi_dbg("could not find resource %s", resource[i].id);
			return -1;
		}
		h_load = LoadResource(NULL, h);
		if (h_load == NULL) {
			usbi_dbg("could not load resource %s", resource[i].id);
			return -1;
		}
		data = LockResource(h_load);
		if (data == NULL) {
			usbi_dbg("could not access data for %s", resource[i].id);
			return -1;
		}
		size = SizeofResource(NULL, h);
		if (size == 0) {
			usbi_dbg("could not access size of %s", resource[i].id);
			return -1;
		}

		safe_strcpy(filename, MAX_PATH_LENGTH, path);
		safe_strcat(filename, MAX_PATH_LENGTH, "\\");
		safe_strcat(filename, MAX_PATH_LENGTH, resource[i].subdir);

		if ( (_access(filename, 02) != 0) && (CreateDirectory(filename, 0) == 0) ) {
			usbi_err(NULL, "could not access directory: %s", filename);
			return -1;
		}
		safe_strcat(filename, MAX_PATH_LENGTH, "\\");
		safe_strcat(filename, MAX_PATH_LENGTH, resource[i].name);
		
	
		fd = fopen(filename, "wb");
		if (fd == NULL) {
			usbi_err(NULL, "failed to create file: %s", filename);
			return -1;
		}

		fwrite(data, size, 1, fd);
		fclose(fd);
	}

	usbi_dbg("successfully extracted files to %s", path);
	return 0;

}

// Create an inf and extract coinstallers in the directory pointed by path
// TODO: optional directory deletion
int create_inf(struct driver_info* drv_info, char* path)
{
	char filename[MAX_PATH_LENGTH];
	FILE* fd;
	GUID guid;

	// TODO? create a reusable temp dir if path is NULL?
	if ((path == NULL) || (drv_info == NULL))
		return -1;

	// Try to create directory if it doesn't exist
	if ( (_access(path, 02) != 0) && (CreateDirectory(path, 0) == 0) ) {
		usbi_err(NULL, "could not access directory: %s", path);
		return -1;
	}

	extract_binaries(path);

	safe_strcpy(filename, MAX_PATH_LENGTH, path);
	safe_strcat(filename, MAX_PATH_LENGTH, "\\");
	safe_strcat(filename, MAX_PATH_LENGTH, INF_NAME);

	fd = fopen(filename, "w");
	if (fd == NULL) {
		usbi_err(NULL, "failed to create file: %s", filename);
		return -1;
	}

	fprintf(fd, "; libusb_device.inf\n");
	fprintf(fd, "; Copyright (c) 2010 libusb (GNU LGPL)\n");
	fprintf(fd, "[Strings]\n");
	fprintf(fd, "DeviceName = \"%s\"\n", drv_info->desc);
	fprintf(fd, "DeviceID = \"%s&%s", drv_info->vid, drv_info->pid);
	if (drv_info->mi[0] != 0) {
		fprintf(fd, "&%s\"\n", drv_info->mi);
	} else {
		fprintf(fd, "\"\n");
	}
	CoCreateGuid(&guid);
	fprintf(fd, "DeviceGUID = \"%s\"\n", guid_to_string(guid));
	fwrite(inf, sizeof(inf)-1, 1, fd);
	fclose(fd);

	usbi_dbg("succesfully created %s", filename);
	return 0;
}

int process_message(char* buffer, DWORD size)
{
	DWORD junk;

	if (size <= 0)
		return -1;

	switch(buffer[0])
	{
	case IC_GET_DEVICE_ID:
		usbi_dbg("got request for device_id");
		WriteFile(pipe, req_device_id, strlen(req_device_id), &junk, NULL);
		break;
	case IC_PRINT_MESSAGE:
		if (size < 2) {
			usbi_err(NULL, "print_message: no data");
			return -1;
		}
		usbi_dbg("[installer process] %s", buffer+1);
		break;
	default:
		usbi_err(NULL, "unrecognized installer message");
		return -1;
	}
	return 0;
}

int run_installer(char* path, char* device_id)
{
	SHELLEXECUTEINFO shExecInfo;
	char exename[MAX_PATH_LENGTH];
	HANDLE handle[2] = {INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE};
	OVERLAPPED overlapped;
	int r;
	DWORD rd_count;
	BOOL is_x64 = false;
#define BUFSIZE 256
	char buffer[BUFSIZE];

	req_device_id = device_id;

	// Detect whether if we should run the 64 bit installer, without
	// relying on external libs
	if (sizeof(uintptr_t) < 8) {
		// This application is not 64 bit, but it might be 32 bit
		// running in WOW64
		pIsWow64Process = (BOOL (__stdcall *)(HANDLE, PBOOL))
			GetProcAddress(GetModuleHandle("KERNEL32"), "IsWow64Process");
		if (pIsWow64Process != NULL) {
			(*pIsWow64Process)(GetCurrentProcess(), &is_x64);
		} 
	} else {
		is_x64 = true;
	}

	// Use a pipe to communicate with our installer
	pipe = CreateNamedPipe("\\\\.\\pipe\\libusb-installer", PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE, 1, 4096, 4096, 0, NULL);
	if (pipe == INVALID_HANDLE_VALUE) {
		usbi_err(NULL, "could not create read pipe: errcode %d", (int)GetLastError());
		r = -1; goto out;
	}

	// Set the overlapped for messaging
	memset(&overlapped, 0, sizeof(OVERLAPPED));
	handle[0] = CreateEvent(NULL, TRUE, FALSE, NULL);
	if(handle[0] == NULL) {
		r = -1; goto out;
	}
	overlapped.hEvent = handle[0];

	safe_strcpy(exename, MAX_PATH_LENGTH, path);
	// TODO: fallback to x86 if x64 unavailable
	if (is_x64) {
		safe_strcat(exename, MAX_PATH_LENGTH, "\\installer_x64.exe");
	} else {
		safe_strcat(exename, MAX_PATH_LENGTH, "\\installer_x86.exe");
	}

	shExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);

	shExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	shExecInfo.hwnd = NULL;
	shExecInfo.lpVerb = "runas";
	shExecInfo.lpFile = exename;
	// if INF_NAME ever has a space, it will be seen as multiple parameters
	shExecInfo.lpParameters = INF_NAME;
	shExecInfo.lpDirectory = path;
	// TODO: hide
//	shExecInfo.nShow = SW_NORMAL;
	shExecInfo.nShow = SW_HIDE;
	shExecInfo.hInstApp = NULL;

	ShellExecuteEx(&shExecInfo);

	if (shExecInfo.hProcess == NULL) {
		usbi_dbg("Installer did not run");
		r = -1; goto out;
	}
	handle[1] = shExecInfo.hProcess;

	while (1) {
		if (ReadFile(pipe, buffer, 256, &rd_count, &overlapped)) {
			// Message was read synchronously
			process_message(buffer, rd_count);
		} else {
			switch(GetLastError()) {
			case ERROR_BROKEN_PIPE: 
				// The pipe has been ended - wait for installer to finish
				WaitForSingleObject(handle[1], INFINITE);
				r = 0; goto out;
			case ERROR_PIPE_LISTENING:
				// Wait for installer to open the pipe 
				Sleep(100);
				continue;
			case ERROR_IO_PENDING:
				switch(WaitForMultipleObjects(2, handle, FALSE, INFINITE)) {
				case WAIT_OBJECT_0: // Pipe event
					if (GetOverlappedResult(pipe, &overlapped, &rd_count, FALSE)) {
						// Message was read asynchronously
						process_message(buffer, rd_count);
					} else {
						switch(GetLastError()) {
						case ERROR_BROKEN_PIPE: 
							// The pipe has been ended - wait for installer to finish
							WaitForSingleObject(handle[1], INFINITE);
							r = 0; goto out;
						case ERROR_MORE_DATA:
							usbi_warn(NULL, "program assertion failed: message overflow");
							process_message(buffer, rd_count);
							break;
						default:
							usbi_err(NULL, "could not read from pipe (async): %d", (int)GetLastError());
							break;
						}
					}
					break;
				case WAIT_OBJECT_0+1:
					// installer process terminated
					r = 0; goto out;
				default:
					usbi_err(NULL, "could not read from pipe (wait): %d", (int)GetLastError());
					break;
				}
				break;
			default:
				usbi_err(NULL, "could not read from pipe (sync): %d", (int)GetLastError());
				break;
			}
		}
	}
out:
	safe_closehandle(handle[0]);
	safe_closehandle(handle[1]);
	safe_closehandle(pipe);
	return r;
}

//TODO: add a call to free strings & list