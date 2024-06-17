#ifndef WINDOWS_HOTPLUG_H
#define WINDOWS_HOTPLUG_H

int windows_start_event_monitor(void);
int windows_stop_event_monitor(void);

void windows_initial_scan_devices(struct libusb_context *ctx);

#endif