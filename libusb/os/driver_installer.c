// This standalone installer is a separate exe, as it needs to be run
// through ShellExecuteEx() for UAC elevation

#include <config.h>
#include <windows.h>
#include <setupapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <direct.h>
#include <setupapi.h>
#include <api/difxapi.h>
#include <fcntl.h>
#include <io.h>
#include <stdarg.h>
#include "driver_installer.h"

/*
 * API macros - from libusb-win32 1.x
 */
#define DLL_DECLARE(api, ret, name, args)                    \
  typedef ret (api * __dll_##name##_t)args; __dll_##name##_t name

#define DLL_LOAD(dll, name, ret_on_failure)                   \
	do {                                                      \
		HMODULE h = GetModuleHandle(#dll);                    \
	if (!h)                                                   \
		h = LoadLibrary(#dll);                                \
	if (!h) {                                                 \
		if (ret_on_failure) { return -1; }                    \
		else { break; }                                       \
	}                                                         \
	name = (__dll_##name##_t)GetProcAddress(h, #name);        \
	if (name) break;                                          \
	name = (__dll_##name##_t)GetProcAddress(h, #name "A");    \
	if (name) break;                                          \
	name = (__dll_##name##_t)GetProcAddress(h, #name "W");    \
	if (name) break;                                          \
	if(ret_on_failure)                                        \
		return -1;                                            \
	} while(0)

/*
 * Cfgmgr32.dll interface
 */
typedef DWORD DEVNODE, DEVINST;
typedef DEVNODE *PDEVNODE, *PDEVINST;
typedef DWORD RETURN_TYPE;
typedef RETURN_TYPE	CONFIGRET;

#define CR_SUCCESS                  	  0x00000000

#define CM_REENUMERATE_NORMAL             0x00000000
#define CM_REENUMERATE_SYNCHRONOUS        0x00000001
#define CM_REENUMERATE_RETRY_INSTALLATION 0x00000002
#define CM_REENUMERATE_ASYNCHRONOUS       0x00000004
#define CM_REENUMERATE_BITS               0x00000007

typedef CHAR *DEVNODEID_A, *DEVINSTID_A;
typedef WCHAR *DEVNODEID_W, *DEVINSTID_W;
#ifdef UNICODE
typedef DEVNODEID_W DEVNODEID;
typedef DEVINSTID_W DEVINSTID;
#else
typedef DEVNODEID_A DEVNODEID;
typedef DEVINSTID_A DEVINSTID;
#endif

DLL_DECLARE(WINAPI, CONFIGRET, CM_Locate_DevNode, (PDEVINST, DEVINSTID, ULONG));
DLL_DECLARE(WINAPI, CONFIGRET, CM_Reenumerate_DevNode, (DEVINST, ULONG));


#define INF_NAME "libusb-device.inf"
#define MAX_PATH_LENGTH 128
#define REQUEST_TIMEOUT 5000
#define safe_strncpy(dst, dst_max, src, count) strncpy(dst, src, min(count, dst_max - 1))
#define safe_strcpy(dst, dst_max, src) safe_strncpy(dst, dst_max, src, strlen(src)+1)
#define safe_strncat(dst, dst_max, src, count) strncat(dst, src, min(count, dst_max - strlen(dst) - 1))
#define safe_strcat(dst, dst_max, src) safe_strncat(dst, dst_max, src, strlen(src)+1)

HANDLE pipe = INVALID_HANDLE_VALUE;

static int init_cfgmgr32(void)
{
	DLL_LOAD(Cfgmgr32.dll, CM_Locate_DevNode, TRUE);
	DLL_LOAD(Cfgmgr32.dll, CM_Reenumerate_DevNode, TRUE);
	return 0;
}

// TODO: return a status byte along with the message
void plog_v(const char *format, va_list args)
{
	char buffer[256];
	int size;

	if (pipe == INVALID_HANDLE_VALUE)
		return;

	buffer[0] = IC_PRINT_MESSAGE;
	size = vsnprintf_s(buffer+1, 255, _TRUNCATE, format, args);
	if (size < 0) {
		buffer[255] = 0;
		size = 254;
	}
	WriteFile(pipe, buffer, size+2, &size, NULL);
}

void plog(const char *format, ...)
{
	va_list args;

	va_start (args, format);
	plog_v(format, args);
	va_end (args);
}

int request_data(unsigned char req, void *buffer, int size)
{
	OVERLAPPED overlapped;
	DWORD rd_count;
	DWORD r, count = (DWORD)size;

	if ((buffer == NULL) || (size <= 0)) {
		return -1;
	}

	// Set the overlapped for messaging
	memset(&overlapped, 0, sizeof(OVERLAPPED));
	overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (overlapped.hEvent == NULL) {
		plog("failed to create overlapped");
		return -1;
	}

	if (ReadFile(pipe, buffer, count, &rd_count, &overlapped)) {
		// Message was read synchronously
		plog("received unexpected data");
		CloseHandle(overlapped.hEvent);
		return -1;
	} 

	if (GetLastError() != ERROR_IO_PENDING) {
		plog("failure to initiate read (%d)", (int)GetLastError());
		CloseHandle(overlapped.hEvent);
		return -1;
	}

	// Now that we're set to receive data, let's send our request
	WriteFile(pipe, &req, 1, &r, NULL);

	// Wait for the response
	r = WaitForSingleObject(overlapped.hEvent, REQUEST_TIMEOUT);
	if ( (r == WAIT_OBJECT_0) && (GetOverlappedResult(pipe, &overlapped, &rd_count, FALSE)) ) {
		CloseHandle(overlapped.hEvent);
		return (int)rd_count;
	}

	if (r == WAIT_TIMEOUT) {
		plog("message request: timed out");
	} else {
		plog("read error: %d", (int)GetLastError());
	}
	CloseHandle(overlapped.hEvent);
	return -1;
}

char* req_device_id(void)
{
	int size;
	static char device_id[MAX_PATH_LENGTH];

	memset(device_id, 0, MAX_PATH_LENGTH);
	size = request_data(IC_GET_DEVICE_ID, (void*)device_id, sizeof(device_id));
	if (size > 0) {
		plog("got device_id: %s", device_id);
		return device_id;
	}

	plog("failed to read device_id");
	return NULL;
}

void __cdecl log_callback(DIFXAPI_LOG Event, DWORD Error, const TCHAR * pEventDescription, PVOID CallbackContext)
{
	if (Error == 0){
		plog("(%u) %s", Event, pEventDescription);
	} else {
		plog("(%u) Error:%u - %s", Event, Error, pEventDescription);
	}
}

// TODO: allow root re-enum
int update_driver(char* device_id)
{
	DEVINST     dev_inst;
	CONFIGRET   status;

	plog("updating driver node %s...", device_id);
	status = CM_Locate_DevNode(&dev_inst, device_id, 0);
	if (status != CR_SUCCESS) {
		plog("failed to locate device_id %s: %x\n", device_id, status);
		return -1;
	}

	status = CM_Reenumerate_DevNode(dev_inst, CM_REENUMERATE_RETRY_INSTALLATION);
	if (status != CR_SUCCESS) {
		plog("failed to re-enumerate device node: CR code %X", status);
		return -1;
	}

	plog("final installation succeeded...");
	return 0;
}

int main(int argc, char** argv)
{
	DWORD r;
	char* device_id;
	BOOL reboot_needed = FALSE;
	char path[MAX_PATH_LENGTH];
	char log[MAX_PATH_LENGTH];
	FILE *fd;

	// Connect to the messaging pipe
	pipe = CreateFile("\\\\.\\pipe\\libusb-installer", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OVERLAPPED, NULL);
	if (pipe == INVALID_HANDLE_VALUE) {
		printf("could not open pipe for writing: errcode %d\n", (int)GetLastError());
		return -1;
	}

	if (init_cfgmgr32()) {
		plog("could not access dfmgr32 DLL");
		return -1;
	}

	safe_strcpy(log, MAX_PATH_LENGTH, argv[0]);
	// TODO - seek for terminal '.exe' and change extension if needed
	safe_strcat(log, MAX_PATH_LENGTH, ".log");

	fd = fopen(log, "w");
	if (fd == NULL) {
		plog("could not open logfile");
		goto out;
	}

	if (argc >= 2) {
		plog("got parameter %s", argv[1]);
		printf("got param %s", argv[1]);
	}

	// TODO: use GetFullPathName() to get full inf path
	_getcwd(path, MAX_PATH_LENGTH);
	safe_strcat(path, MAX_PATH_LENGTH, "\\");
	safe_strcat(path, MAX_PATH_LENGTH, INF_NAME);

	device_id = req_device_id();

	plog("Installing driver - please wait...");
	DIFXAPISetLogCallback(log_callback, NULL);
	// TODO: set app dependency?
	r = DriverPackageInstall(path, DRIVER_PACKAGE_LEGACY_MODE|DRIVER_PACKAGE_REPAIR|DRIVER_PACKAGE_FORCE,
		NULL, &reboot_needed);
	DIFXAPISetLogCallback(NULL, NULL);
	// Will fail if inf not signed, unless DRIVER_PACKAGE_LEGACY_MODE is specified.
	// r = 87 ERROR_INVALID_PARAMETER on path == NULL
	// r = 2 ERROR_FILE_NOT_FOUND if no inf in path
	// r = 5 ERROR_ACCESS_DENIED if needs admin elevation
	// r = 0xE0000003 ERROR_GENERAL_SYNTAX the syntax of the inf is invalid or the inf is empty
	// r = 0xE0000304 ERROR_INVALID_CATALOG_DATA => no cat
	// r = 0xE000023F ERROR_NO_AUTHENTICODE_CATALOG => user cancelled on warnings
	// r = 0xE0000247 if user decided not to install on warnings
	// r = 0x800B0100 ERROR_WRONG_INF_STYLE => missing cat entry in inf
	// r = 0xB7 => missing DRIVER_PACKAGE_REPAIR flag
	switch(r) {
	case 0:
		plog("  completed");
		plog("reboot %s needed", reboot_needed?"":"not");
		break;
	case ERROR_NO_MORE_ITEMS:
		plog("more recent driver was found (DRIVER_PACKAGE_FORCE option required)");
		goto out;
	case ERROR_NO_SUCH_DEVINST:
		plog("device not detected (DRIVER_PACKAGE_ONLY_IF_DEVICE_PRESENT needs to be disabled)");
		goto out;
	case ERROR_INVALID_PARAMETER:
		plog("invalid path");
		goto out;
	case ERROR_FILE_NOT_FOUND:
		plog("unable to find inf file on %s", path);
		goto out;
	case ERROR_ACCESS_DENIED:
		plog("this process needs to be run with administrative privileges");
		goto out;
	case ERROR_WRONG_INF_STYLE:
	case ERROR_GENERAL_SYNTAX:
		plog("the syntax of the inf is invalid");
		goto out;
	case ERROR_INVALID_CATALOG_DATA:
		plog("unable to locate cat file");
		goto out;
	case ERROR_NO_AUTHENTICODE_CATALOG:
	case ERROR_DRIVER_STORE_ADD_FAILED:
		plog("cancelled by user");
		goto out;
	// TODO: make DRIVER_PACKAGE_REPAIR optional
	case ERROR_ALREADY_EXISTS:
		plog("driver already exists");
		goto out;
	default:
		plog("unhandled error %X", r);
		goto out;
	}

	update_driver(device_id);

out:
	CloseHandle(pipe);
	return 0;
}