#pragma once

#include <windows.h>
#define MAX_DESC_LENGTH 128
#define USE_WINUSB 0
#define USE_LIBUSB 1

struct driver_info {
	struct driver_info *next;
	char* device_id;
	char* desc;
	char vid[9];
	char pid[9];
	char mi[6];
};

struct driver_info *list_driverless(void);
char* guid_to_string(const GUID guid);
int create_inf(struct driver_info* drv_info, char* path, int type);
int run_installer(char *path, char *dev_inst);
int update_drivers(void);



