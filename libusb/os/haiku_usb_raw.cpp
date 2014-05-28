#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <new>
#include <vector>

#include "haiku_usb_raw.h"

UsbRoster 		gUsbRoster;
int32			gInitCount = 0;

static int
haiku_init(struct libusb_context* ctx)
{
#ifdef TRACE_USB
	TRACE("haiku_init\n");
#endif	

	if (atomic_add(&gInitCount, 1) == 0)
		gUsbRoster.Start();
	return 0;
}

static void
haiku_exit(void)
{
#ifdef TRACE_USB
	TRACE("haiku_exit\n");
#endif
	if (atomic_add(&gInitCount, -1) == 1)
		gUsbRoster.Stop();
}

static int 
haiku_open(struct libusb_device_handle *dev_handle)
{
#ifdef TRACE_USB
	TRACE("haiku_open\n");
#endif
	USBDevice* dev=*((USBDevice**)dev_handle->dev->os_priv);
	USBDeviceHandle *handle=new USBDeviceHandle(dev);
	*((USBDeviceHandle**)dev_handle->os_priv)=handle;
	return usbi_add_pollfd(HANDLE_CTX(dev_handle),handle->EventPipe(0), POLLIN);
}

static void 
haiku_close(struct libusb_device_handle *dev_handle)
{
#ifdef TRACE_USB
	TRACE("haiku_close\n");
#endif
	USBDeviceHandle * handle=*((USBDeviceHandle**)dev_handle->os_priv);
	if(handle==NULL)
		return;
	//Release Interface??
	usbi_remove_pollfd(HANDLE_CTX(dev_handle),handle->EventPipe(0));
	delete handle;
	*((USBDeviceHandle**)dev_handle->os_priv)=NULL;
}

static int 
haiku_get_device_descriptor(struct libusb_device *device, unsigned char* buffer, int *host_endian)
{
#ifdef TRACE_USB
	TRACE("haiku_get_device_descriptor\n");
#endif
	USBDevice *dev = *((USBDevice**)(device->os_priv));
	memcpy(buffer,dev->Descriptor(),DEVICE_DESC_LENGTH);
	*host_endian=0;
	return LIBUSB_SUCCESS; 
}

static int
haiku_get_active_config_descriptor(struct libusb_device *device, unsigned char *buffer, size_t len, int *host_endian)
{
#ifdef TRACE_USB
	TRACE("haiku_get_active_config_descriptor\n");
#endif
	USBDevice *dev = *((USBDevice**)(device->os_priv));
	const usb_configuration_descriptor* act_config = dev->ActiveConfiguration();
	if(len>act_config->total_length)
		len=act_config->total_length;
	memcpy(buffer,act_config,len);
	*host_endian=0;
	return len;
}

static int
haiku_get_config_descriptor(struct libusb_device *device, uint8_t config_index, unsigned char *buffer, size_t len, int *host_endian)
{
#ifdef TRACE_USB
	printf("haiku_get_config_descriptor (len:%d,index:%d)\n",len,(int)config_index);
#endif
	USBDevice *dev = *((USBDevice**)(device->os_priv));
	const usb_configuration_descriptor* config = dev->ConfigurationDescriptor(config_index);
	if(config==NULL)
	{
		printf("returning error\n");
		return LIBUSB_ERROR_INVALID_PARAM;
	}
	if(len>config->total_length)
		len=config->total_length;
	memcpy(buffer,(unsigned char*)config,len);
	*host_endian=0;
	return len;
}

static int
haiku_set_configuration(struct libusb_device_handle *dev_handle, int config)
{
#ifdef TRACE_USB
	TRACE("haiku_set_configuration\n");
#endif
	USBDevice * dev= *((USBDevice**)dev_handle->dev->os_priv);
	return dev->SetConfiguration(config);		//IS THIS SET CONF by BConfigValue?? or Config Index???
}

static int
haiku_claim_interface(struct libusb_device_handle *dev_handle, int interface_number)
{
#ifdef TRACE_USB
	TRACE("haiku_claim_interface\n");
#endif
	USBDeviceHandle * handle=*((USBDeviceHandle**)dev_handle->os_priv);
	handle->SetInterface(interface_number);		//ALLOWS CLAIMING JUST 1 interface :( Is it a problem?
	return LIBUSB_SUCCESS;
}

static int
haiku_set_altsetting(struct libusb_device_handle* dev_handle, int interface_number, int altsetting)
{
#ifdef TRACE_USB
	TRACE("haiku_set_altsetting\n");
#endif
	USBDevice * dev = *((USBDevice**)dev_handle->dev->os_priv);
	return dev->SetAltSetting(interface_number, altsetting);
}

static int
haiku_release_interface(struct libusb_device_handle *dev_handle, int interface_number)
{
#ifdef TRACE_USB
	TRACE("haiku_release_interface\n");
#endif
	USBDeviceHandle * handle=*((USBDeviceHandle**)dev_handle->os_priv);
	//SET ALT SETTING TO 0
	//haiku_set_altsetting(dev_handle,interface_number,0);
	handle->SetInterface(-1);
	return LIBUSB_SUCCESS;
}

static int
haiku_submit_transfer(struct usbi_transfer * itransfer)
{
#ifdef TRACE_USB
	TRACE("haiku_submit_transfer\n");
#endif
	struct libusb_transfer* fLibusbTransfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	USBDeviceHandle * fDeviceHandle = *((USBDeviceHandle**)fLibusbTransfer->dev_handle->os_priv);
	fDeviceHandle->SubmitTransfer(itransfer); 
}

static int
haiku_cancel_transfer(struct usbi_transfer * itransfer)
{
#ifdef TRACE_USB
	TRACE("haiku_cancel_transfer\n");
#endif
}

static int
haiku_handle_events(struct libusb_context* ctx, struct pollfd* fds, nfds_t nfds, int num_ready)
{
#ifdef TRACE_USB
	TRACE("haiku_handle_events\n");
#endif
	struct usbi_transfer *itransfer;
	for(int i=0;i<nfds && num_ready>0;i++)
	{
		struct pollfd *pollfd = &fds[i];
		if(!pollfd->revents)
			continue;
			
		num_ready--;
		read(pollfd->fd, &itransfer, sizeof(itransfer));
		libusb_transfer_status status = LIBUSB_TRANSFER_COMPLETED;
		if(itransfer->transferred < 0)
		{
			printf("transfer error :(\n");
			status = LIBUSB_TRANSFER_ERROR;
			itransfer->transferred=0;
		}
		usbi_handle_transfer_completion(itransfer,status);
	}
	return LIBUSB_SUCCESS;
}

void haiku_destroy_device(struct libusb_device * device)
{
	USBDevice* dev=*((USBDevice**)device->os_priv);
	delete dev;
	*((USBDevice**)device->os_priv)=NULL;
}

static int
haiku_clock_gettime(int clkid, struct timespec *tp)
{
#ifdef TRACE_USB
	TRACE("haiku_clock_gettime\n");
#endif
	if(clkid == USBI_CLOCK_REALTIME)
		return clock_gettime(CLOCK_REALTIME, tp);
	if(clkid == USBI_CLOCK_MONOTONIC)
		return clock_gettime(CLOCK_MONOTONIC, tp);
	return LIBUSB_ERROR_INVALID_PARAM;
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
	/*.get_device_descriptor =*/ haiku_get_device_descriptor,
	/*.get_active_config_descriptor =*/ haiku_get_active_config_descriptor,
	/*.get_config_descriptor =*/ haiku_get_config_descriptor,
	/*.get_config_descriptor_by_value =*/ NULL,


	/*.get_configuration =*/ NULL,
	/*.set_configuration =*/ haiku_set_configuration,
	/*.claim_interface =*/ haiku_claim_interface,
	/*.release_interface =*/ haiku_release_interface,

	/*.set_interface_altsetting =*/ haiku_set_altsetting,
	/*.clear_halt =*/ NULL,
	/*.reset_device =*/ NULL,

	/*.alloc_streams =*/ NULL,
	/*.free_streams =*/ NULL,

	/*.kernel_driver_active =*/ NULL,
	/*.detach_kernel_driver =*/ NULL,
	/*.attach_kernel_driver =*/ NULL,

	/*.destroy_device =*/ haiku_destroy_device,

	/*.submit_transfer =*/ haiku_submit_transfer,
	/*.cancel_transfer =*/ haiku_cancel_transfer,
	/*.clear_transfer_priv =*/ NULL,

	/*.handle_events =*/ haiku_handle_events,

	/*.clock_gettime =*/ haiku_clock_gettime,

#ifdef USBI_TIMERFD_AVAILABLE
	/*.get_timerfd_clockid =*/ NULL,
#endif

	/*.device_priv_size =*/ sizeof(USBDevice*),
	/*.device_handle_priv_size =*/ sizeof(USBDeviceHandle*),
	/*.transfer_priv_size =*/ 0,
	/*.add_iso_packet_size =*/ 0,
};
