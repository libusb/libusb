#pragma once

#include <windows.h>
#define MAX_DESC_LENGTH 128

struct driver_info {
	struct driver_info *next;
	char desc[MAX_DESC_LENGTH];
	char vid[9];
	char pid[9];
	char mi[6];
	GUID dev_guid;
};

struct driver_info *list_driverless(void);
char* guid_to_string(const GUID guid);

