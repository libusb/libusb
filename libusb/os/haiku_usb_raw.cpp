#include "usb_raw.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <USBKit.h>
#include <stdlib.h>
#include <Locker.h>
#include <Autolock.h>
#include <new>
#include "libusbi.h"

class USBDevice{
public:
	USBDevice(const char * path);
	const char* Location() const;
	uint32 CountConfigurations() const;
private:
	int								Initialise();
	usb_device_descriptor			fDeviceDescriptor;
	usb_configuration_descriptor*	fConfigurationDescriptors;
	int								fActiveConfiguration;
	char*							fPath;
	int								fRawFD;
};

USBDevice::USBDevice(const char * path) 
	:
	fPath(NULL),
	fRawFD(-1),
	fActiveConfiguration(-1),	//0?
	fConfigurationDescriptors(NULL)
{
	fPath=strdup(path);
	Initialise();
}

inline const char*
USBDevice::Location() const
{
	return fPath;
}

inline uint32
USBDevice::CountConfigurations() const
{
	return fDeviceDescriptor.num_configurations;
}

int 
USBDevice::Initialise()
{
	fRawFD=open(fPath, O_RDWR | O_CLOEXEC);
	if(fRawFD < 0)
		return B_ERROR;
		
	usb_raw_command command;
	command.device.descriptor = &fDeviceDescriptor;
	if(ioctl(fRawFD, B_USB_RAW_COMMAND_GET_DEVICE_DESCRIPTOR, &command,
		sizeof(command)) || command.device.status != B_USB_RAW_STATUS_SUCCESS) {
		return B_ERROR;
	}
	
	fConfigurationDescriptors = new(std::nothrow) usb_configuration_descriptor[
		fDeviceDescriptor.num_configurations];
	for( int i=0; i<fDeviceDescriptor.num_configurations; i++)
	{
		command.config.descriptor = &fConfigurationDescriptors[i];
		command.config.config_index = i;
		if(ioctl(fRawFD, B_USB_RAW_COMMAND_GET_CONFIGURATION_DESCRIPTOR, &command,
			sizeof(command)) || command.config.status != B_USB_RAW_STATUS_SUCCESS) {
			return B_ERROR;		
		}
	}
}


//  #pragma mark - UsbRoster class

class UsbRoster : public BUSBRoster {
public:
                   UsbRoster()  {}

	virtual status_t    DeviceAdded(BUSBDevice* device);
	virtual void        DeviceRemoved(BUSBDevice* device);

private:
	status_t			_AddNewDevice(struct libusb_context* ctx, USBDevice* info);
	
	BLocker	fDevicesLock;
	BList	fDevices;
};


status_t
UsbRoster::_AddNewDevice(struct libusb_context* ctx, USBDevice* deviceInfo)
{
	struct libusb_device* dev = usbi_get_device_by_session_id(ctx, (unsigned long)deviceInfo);
	if (dev) {
		usbi_info (ctx, "using existing device for location ID 0x%08x", deviceInfo);
	} else {
		usbi_info (ctx, "allocating new device for session ID 0x%08x", deviceInfo);
		dev = usbi_alloc_device(ctx, (unsigned long)deviceInfo);
		if (!dev) {
			return B_NO_MEMORY;
		}
		*((USBDevice**)dev->os_priv) = deviceInfo;

		// TODO: handle device address mapping for devices in non-root hub(s)
		sscanf(deviceInfo->Location(), "/dev/bus/usb/%d/%d", &dev->bus_number, &dev->device_address);
		dev->num_configurations = (uint8_t) deviceInfo->CountConfigurations();

		// printf("bus %d, address %d, # of configs %d\n", dev->bus_number,
		//	dev->device_address, dev->num_configurations);

    	if(usbi_sanitize_device(dev) < 0) {
			libusb_unref_device(dev);
			return B_ERROR;	
		}
	}

    usbi_connect_device (dev);
   	return B_OK;
}


status_t
UsbRoster::DeviceAdded(BUSBDevice* device)
{
#if TRACE
	//printf("UsbRoster::DeviceAdded(BUSBDevice %p: %s%s)\n", device, kBusRootPath, 
	//	device->Location());
#endif
 
 	if (device->IsHub())
 		return B_ERROR;
 
 	char tmp[200];
 	strcpy(tmp,"/dev/bus/usb");
 	strcat(tmp,device->Location());
 	printf("Device : %s\n",tmp);
	USBDevice* deviceInfo = new USBDevice(tmp);
	//deviceInfo->Get();
	
	// Add this new device to each active context's device list
	struct libusb_context *ctx;
	usbi_mutex_lock(&active_contexts_lock);
	list_for_each_entry(ctx, &active_contexts_list, list, struct libusb_context) {
		// printf("UsbRoster::DeviceAdded() active_contexts_list: ctx %p\n", ctx); 
		_AddNewDevice(ctx, deviceInfo);
	}
	usbi_mutex_unlock(&active_contexts_lock);

	BAutolock locker(fDevicesLock);
	fDevices.AddItem(deviceInfo);
	
	return B_OK;
}


void
UsbRoster::DeviceRemoved(BUSBDevice* device)
{
#if TRACE
	//printf("UsbRoster::DeviceRemoved(BUSBDevice %p: %s%s)\n", device, kBusRootPath, 
	//	device->Location());
#endif

	BAutolock locker(fDevicesLock);
	USBDevice* deviceInfo;
	int i = 0;
	while (deviceInfo = (USBDevice*)fDevices.ItemAt(i++)) {
		if (!deviceInfo)
			continue;
		char tmp[200];
		strcpy(tmp,"/dev/bus/usb");
		strcat(tmp,device->Location());
		if (strcmp(deviceInfo->Location(), tmp) == 0)
			break;
	}

	if (!deviceInfo)
		return;

	// Remove this device from each active context's device list 
	struct libusb_context *ctx;
	struct libusb_device *dev;
	
	usbi_mutex_lock(&active_contexts_lock);
	list_for_each_entry(ctx, &active_contexts_list, list, struct libusb_context) {
		dev = usbi_get_device_by_session_id (ctx, (unsigned long)deviceInfo);
		if (dev != NULL) {
			usbi_disconnect_device (dev);
		}
	}
	usbi_mutex_static_unlock(&active_contexts_lock);

	fDevices.RemoveItem(deviceInfo);
}


UsbRoster 		gUsbRoster;
 int32	gInitCount = 0;

static int
haiku_init(struct libusb_context* ctx)
{
	if (atomic_add(&gInitCount, 1) == 0)
		gUsbRoster.Start();
	return 0;
}

static void
haiku_exit(void)
{
	if (atomic_add(&gInitCount, -1) == 1)
		gUsbRoster.Stop();
}

static int haiku_open(struct libusb_device_handle *dev_handle)
{
}

static void haiku_close(struct libusb_device_handle *dev_handle)
{
}

const struct usbi_os_backend haiku_usb_raw_backend = {
	/*.name =*/ "Haiku usbfs",
	/*.caps =*/ 0,
	/*.init =*/ haiku_init,
	/*.exit =*/ haiku_exit,
	/*.get_device_list =*/ NULL,
	/*.hotplug_poll =*/ NULL,
	/*.open =*/ haiku_open,
	/*.close =*/ haiku_close,
	/*.get_device_descriptor =*/ NULL,
	/*.get_active_config_descriptor =*/ NULL,
	/*.get_config_descriptor =*/ NULL,
	/*.get_config_descriptor_by_value =*/ NULL,


	/*.get_configuration =*/ NULL,
	/*.set_configuration =*/ NULL,
	/*.claim_interface =*/ NULL,
	/*.release_interface =*/ NULL,

	/*.set_interface_altsetting =*/ NULL,
	/*.clear_halt =*/ NULL,
	/*.reset_device =*/ NULL,

	/*.alloc_streams =*/ NULL,
	/*.free_streams =*/ NULL,

	/*.kernel_driver_active =*/ NULL,
	/*.detach_kernel_driver =*/ NULL,
	/*.attach_kernel_driver =*/ NULL,

	/*.destroy_device =*/ NULL,

	/*.submit_transfer =*/ NULL,
	/*.cancel_transfer =*/ NULL,
	/*.clear_transfer_priv =*/ NULL,

	/*.handle_events =*/ NULL,

	/*.clock_gettime =*/ NULL,

#ifdef USBI_TIMERFD_AVAILABLE
	/*.get_timerfd_clockid =*/ NULL,
#endif

	/*.device_priv_size =*/ 0,
	/*.device_handle_priv_size =*/ 0,
	/*.transfer_priv_size =*/ 0,
	/*.add_iso_packet_size =*/ 0,
};
