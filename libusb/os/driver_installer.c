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


#define MAX_PATH_LENGTH             128
#define safe_strncat(dst, dst_max, src, count) strncat(dst, src, min(count, dst_max - strlen(dst) - 1))
#define safe_strcat(dst, dst_max, src) safe_strncat(dst, dst_max, src, strlen(src)+1)


int main(int argc, char** argv)
{
	DWORD r;
	BOOL reboot_needed;
	char path[MAX_PATH_LENGTH];
//	INSTALLERINFO installer_info;

	_getcwd(path, MAX_PATH_LENGTH);
	safe_strcat(path, MAX_PATH_LENGTH, "\\libusb_device.inf");


	r = DriverPackagePreinstall(path, DRIVER_PACKAGE_LEGACY_MODE|DRIVER_PACKAGE_REPAIR);
	// Will fail if inf not signed, unless DRIVER_PACKAGE_LEGACY_MODE is specified.
	// r = 87 ERROR_INVALID_PARAMETER on path == NULL
	// r = 2 ERROR_FILE_NOT_FOUND if no inf in path
	// r = 5 ERROR_ACCESS_DENIED if needs admin elevation
	// r = 0xE0000003 ERROR_GENERAL_SYNTAX the syntax of the inf is invalid
	// r = 0xE0000304 ERROR_INVALID_CATALOG_DATA => no cat
	// r = 0xE0000247 if user decided not to install on warnings
	// r = 0x800B0100 ERROR_WRONG_INF_STYLE => missing cat entry in inf
	// r = 0xB7 => missing DRIVER_PACKAGE_REPAIR flag
	switch(r) {
	case ERROR_INVALID_PARAMETER:
		printf("invalid path\n");
		return -1;
	case ERROR_FILE_NOT_FOUND:
		printf("unable to find inf file on %s\n", path);
		return -1;
	case ERROR_ACCESS_DENIED:
		printf("this process needs to be run with administrative privileges\n");
		return -1;
	case ERROR_WRONG_INF_STYLE:
	case ERROR_GENERAL_SYNTAX:
		printf("the syntax of the inf is invalid\n");
		return -1;
	case ERROR_INVALID_CATALOG_DATA:
		printf("unable to locate cat file\n");
		return -1;
	case ERROR_DRIVER_STORE_ADD_FAILED:
		printf("cancelled by user\n");
		return -1;
	// TODO: make DRIVER_PACKAGE_REPAIR optional
	case ERROR_ALREADY_EXISTS:
		printf("driver already exists\n");
		return -1;
	default:
		printf("unhandled error %X\n", r);
		return -1;
	}

	// TODO: use 
	r = DriverPackageInstall(path, DRIVER_PACKAGE_LEGACY_MODE|DRIVER_PACKAGE_REPAIR,
		NULL, &reboot_needed);
	printf("ret = %X\n", r);

	return 0;
}