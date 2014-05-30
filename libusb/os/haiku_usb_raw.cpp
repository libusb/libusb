#include "usb_raw.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <USBKit.h>
#include <stdlib.h>
#include <Locker.h>
#include <Autolock.h>
#include <List.h>
#include <new>
#include "libusbi.h"

//#define TRACE_USB 1
#ifdef TRACE_USB
#define TRACE(x) printf(x);
#endif

class USBDevice{
public:
	USBDevice(const char *);
	virtual ~USBDevice();
	const char* Location() const;
	uint32 CountConfigurations() const;
	const usb_device_descriptor* Descriptor() const;
	const usb_configuration_descriptor* ConfigurationDescriptor(uint32) const;
	const usb_configuration_descriptor* ActiveConfiguration() const;
	int SetConfiguration(int);
	int SetAltSetting(int,int);
	int								fRawFD;
private:
	int								Initialise();
	usb_device_descriptor			fDeviceDescriptor;
	unsigned char**							fConfigurationDescriptors;
	int								fActiveConfiguration;
	char*							fPath;
	
};

class USBDeviceHandle{
public:
	USBDeviceHandle(USBDevice* dev);
	virtual ~USBDeviceHandle();
	int EventPipe(int) const;
	int SetInterface(int);
	status_t SubmitTransfer(struct usbi_transfer*);
private:
	static status_t TransfersThread(void *);
	void TransfersWorker();
	USBDevice * fUSBDevice;
	int fInterface;
	int fEventPipes[2];
	BList fTransfers;
	BLocker fTransfersLock;
	sem_id fTransfersSem;
	thread_id fTransfersThread;
};

status_t
USBDeviceHandle::TransfersThread(void* self)
{
	USBDeviceHandle * handle = (USBDeviceHandle*)self;
	handle->TransfersWorker();
	
}

void
USBDeviceHandle::TransfersWorker()
{
	while(true)
	{
		status_t status = acquire_sem(fTransfersSem);
		fTransfersLock.Lock();
		struct usbi_transfer* fPendingTransfer= (struct usbi_transfer*)fTransfers.RemoveItem((int32)0);
		fTransfersLock.Unlock();
		struct libusb_transfer* fLibusbTransfer= USBI_TRANSFER_TO_LIBUSB_TRANSFER(fPendingTransfer);
		switch(fLibusbTransfer->type)
		{
			case LIBUSB_TRANSFER_TYPE_CONTROL:
			{
				struct libusb_control_setup* setup=(struct libusb_control_setup*)fLibusbTransfer->buffer;
				usb_raw_command command;
				command.control.request_type=setup->bmRequestType;
				command.control.request=setup->bRequest;
				command.control.value=setup->wValue;
				command.control.index=setup->wIndex;
				command.control.length=setup->wLength;
				command.control.data=fLibusbTransfer->buffer + LIBUSB_CONTROL_SETUP_SIZE;
				if(ioctl(fUSBDevice->fRawFD,B_USB_RAW_COMMAND_CONTROL_TRANSFER,&command,
					sizeof(command)) || command.control.status!=B_USB_RAW_STATUS_SUCCESS)	{
					fPendingTransfer->transferred=-1;
					printf("failed control transfer :(");
					break;
				}
			
				fPendingTransfer->transferred=command.control.length;
				printf("transfer succeeded with length : %d\n",command.control.length);
			}
				break;
			default:
				printf("Type other\n");
		}
		write(fEventPipes[1],&fPendingTransfer,sizeof(fPendingTransfer));
	}
}

status_t
USBDeviceHandle::SubmitTransfer(struct usbi_transfer* itransfer)
{
	BAutolock locker(fTransfersLock);
	fTransfers.AddItem(itransfer);
	release_sem(fTransfersSem);
}

USBDeviceHandle::USBDeviceHandle(USBDevice* dev)
	:
	fUSBDevice(dev),
	fInterface(0)
{
	pipe(fEventPipes);
	fcntl(fEventPipes[1], F_SETFD, O_NONBLOCK);	//Why need??
	fTransfersSem = create_sem(0, "Transfers Queue Sem");
	fTransfersThread = spawn_thread(TransfersThread,"Transfer Worker",B_NORMAL_PRIORITY, this);
	resume_thread(fTransfersThread);
}

USBDeviceHandle::~USBDeviceHandle()
{
	close(fEventPipes[1]);
	close(fEventPipes[0]);
}

int
USBDeviceHandle::EventPipe(int index) const
{
	return fEventPipes[index];
}

int
USBDeviceHandle::SetInterface(int inumber)
{
	fInterface=inumber;
	return 0;
}

USBDevice::USBDevice(const char * path) 
	:
	fPath(NULL),
	fRawFD(-1),
	fActiveConfiguration(0),	//0?
	fConfigurationDescriptors(NULL)
{
	fPath=strdup(path);
	Initialise();
}

USBDevice::~USBDevice()
{
	if(fRawFD>=0)
		close(fRawFD);
	free(fPath);
	for(int i=0;i<fDeviceDescriptor.num_configurations;i++)
	{
		delete fConfigurationDescriptors[i];
	}
	delete[] fConfigurationDescriptors;
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

inline const usb_device_descriptor*
USBDevice::Descriptor() const
{
	return &fDeviceDescriptor;
}

const usb_configuration_descriptor*
USBDevice::ConfigurationDescriptor(uint32 index) const
{
	if(index>CountConfigurations())
		return NULL;
	return (usb_configuration_descriptor*) fConfigurationDescriptors[index];
}

const usb_configuration_descriptor*
USBDevice::ActiveConfiguration() const
{
	return (usb_configuration_descriptor*) fConfigurationDescriptors[fActiveConfiguration];
}

int
USBDevice::SetConfiguration(int config)
{
	usb_raw_command command;
	command.config.config_index=config;
	if(ioctl(fRawFD,B_USB_RAW_COMMAND_SET_CONFIGURATION,&command,
		sizeof(command)) || command.config.status != B_USB_RAW_STATUS_SUCCESS)
	{
		return -1;	//REPAIR
	}
	fActiveConfiguration=config;
	return 0;
}

int
USBDevice::SetAltSetting(int inumber, int alt)
{
	usb_raw_command command;
	command.alternate.alternate_info = alt;
	command.alternate.config_index=fActiveConfiguration;
	command.alternate.interface_index=inumber;
	if(ioctl(fRawFD,B_USB_RAW_COMMAND_SET_ALT_INTERFACE,&command, 
		sizeof(command)) || command.alternate.status!=B_USB_RAW_STATUS_SUCCESS)
		return B_ERROR;
	return LIBUSB_SUCCESS;
}

int 
USBDevice::Initialise()		//Do we need more error checking, etc?
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
	
	size_t size;
	fConfigurationDescriptors = new(std::nothrow) unsigned char*[fDeviceDescriptor.num_configurations];
	for( int i=0; i<fDeviceDescriptor.num_configurations; i++)
	{
		size=0;
		usb_configuration_descriptor tmp_config;
		command.config.descriptor = &tmp_config;
		command.config.config_index = i;
		if(ioctl(fRawFD, B_USB_RAW_COMMAND_GET_CONFIGURATION_DESCRIPTOR, &command,
			sizeof(command)) || command.config.status != B_USB_RAW_STATUS_SUCCESS) {
			return B_ERROR;		
		}
		fConfigurationDescriptors[i]=new(std::nothrow) unsigned char[tmp_config.total_length];
		memcpy(fConfigurationDescriptors[i],&tmp_config,tmp_config.length);
		size+=tmp_config.length;
		for( int j=0;j<tmp_config.number_interfaces;j++)
		{
			usb_interface_descriptor tmp_interface;
			command.interface.config_index=i;
			command.interface.interface_index=j;	//CHECK IF WE NEED ACTIVE ALT INTERFACE OR 0
			command.interface.descriptor=&tmp_interface;
			if(ioctl(fRawFD,B_USB_RAW_COMMAND_GET_INTERFACE_DESCRIPTOR, &command,
				sizeof(command)) || command.config.status != B_USB_RAW_STATUS_SUCCESS) {
				return B_ERROR;
			}
			memcpy(fConfigurationDescriptors[i]+size, &tmp_interface, tmp_interface.length);
			size+=tmp_interface.length;
			for( int k=0;k<tmp_interface.num_endpoints;k++)
			{
				usb_endpoint_descriptor tmp_endpoint;
				command.endpoint.config_index=i;
				command.endpoint.interface_index=j;
				command.endpoint.endpoint_index=k;
				command.endpoint.descriptor=&tmp_endpoint;
				if(ioctl(fRawFD,B_USB_RAW_COMMAND_GET_ENDPOINT_DESCRIPTOR, &command,
					sizeof(command)) || command.config.status != B_USB_RAW_STATUS_SUCCESS) {
					return B_ERROR;
				}
				memcpy(fConfigurationDescriptors[i]+size, &tmp_endpoint, tmp_endpoint.length);
				size+=tmp_endpoint.length;
			}
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
 	if (device->IsHub())
 		return B_ERROR;
 
 	char tmp[200];
 	strcpy(tmp,"/dev/bus/usb");
 	strcat(tmp,device->Location());
	USBDevice* deviceInfo = new USBDevice(tmp);
	//deviceInfo->Get();
	
	// Add this new device to each active context's device list
	struct libusb_context *ctx;
	usbi_mutex_lock(&active_contexts_lock);
	list_for_each_entry(ctx, &active_contexts_list, list, struct libusb_context) { 
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
	return dev->SetConfiguration(config);
}

static int
haiku_claim_interface(struct libusb_device_handle *dev_handle, int interface_number)
{
#ifdef TRACE_USB
	TRACE("haiku_claim_interface\n");
#endif
	USBDeviceHandle * handle=*((USBDeviceHandle**)dev_handle->os_priv);
	handle->SetInterface(interface_number);		//ALLOWS CLAIMING JUST 1 interface :(
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
	haiku_set_altsetting(dev_handle,interface_number,0);
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

	/*.destroy_device =*/ NULL,

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
