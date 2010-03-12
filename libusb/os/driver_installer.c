// This standalone installer is a separate exe, as it needs to be run
// through ShellExecuteEx() for UAC elevation

#include <config.h>
#include <windows.h>
#include <setupapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <direct.h>
#include <api/difxapi.h>
#include <fcntl.h>
#include <io.h>
#include <stdarg.h>

#define INF_NAME "libusb-device.inf"
#define MAX_PATH_LENGTH 128
#define safe_strncpy(dst, dst_max, src, count) strncpy(dst, src, min(count, dst_max - 1))
#define safe_strcpy(dst, dst_max, src) safe_strncpy(dst, dst_max, src, strlen(src)+1)
#define safe_strncat(dst, dst_max, src, count) strncat(dst, src, min(count, dst_max - strlen(dst) - 1))
#define safe_strcat(dst, dst_max, src) safe_strncat(dst, dst_max, src, strlen(src)+1)

HANDLE pipe = INVALID_HANDLE_VALUE;

// TODO: return a status byte along with the message
void plog_v(const char *format, va_list args)
{
	char buffer[256];
	int size;

	if (pipe == INVALID_HANDLE_VALUE)
		return;

	size = vsnprintf_s(buffer, 256, _TRUNCATE, format, args);
	if (size < 0) {
		buffer[255] = 0;
		size = 255;
	}
	WriteFile(pipe, buffer, size+1, &size, NULL);
}

void plog(const char *format, ...)
{
	va_list args;

	va_start (args, format);
	plog_v(format, args);
	va_end (args);
}

void __cdecl log_callback(DIFXAPI_LOG Event, DWORD Error, const TCHAR * pEventDescription, PVOID CallbackContext)
{
	if (Error == 0){
		plog("(%u) %s", Event, pEventDescription);
	} else {
		plog("(%u) Error:%u - %s", Event, Error, pEventDescription);
	}
}


int main(int argc, char** argv)
{
	DWORD r;
	BOOL reboot_needed;
	char path[MAX_PATH_LENGTH];
	char log[MAX_PATH_LENGTH];
	FILE *fd;

	// Connect to the messaging pipe
	pipe = CreateFile("\\\\.\\pipe\\libusb-installer", GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OVERLAPPED, NULL);
	if (pipe == INVALID_HANDLE_VALUE) {
		// Try to write on console
		printf("could not open pipe for writing: errcode %d\n", (int)GetLastError());
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

out:
	CloseHandle(pipe);
	return 0;
}