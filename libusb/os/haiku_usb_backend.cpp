#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <new>
#include <vector>

#include "haiku_usb_raw.h"

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
		if(status== B_BAD_SEM_ID)
			break;
		if(status == B_INTERRUPTED)
			continue;
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
			}
			break;
			case LIBUSB_TRANSFER_TYPE_BULK:
			case LIBUSB_TRANSFER_TYPE_INTERRUPT:
			{
				usb_raw_command command;
				command.transfer.interface=fInterface;
				command.transfer.endpoint=fUSBDevice->fEndpointAddress[fLibusbTransfer->endpoint];
				command.transfer.data=fLibusbTransfer->buffer;
				command.transfer.length=fLibusbTransfer->length;
				if(fLibusbTransfer->type==LIBUSB_TRANSFER_TYPE_BULK)
				{
					if(ioctl(fUSBDevice->fRawFD,B_USB_RAW_COMMAND_BULK_TRANSFER,&command,
						sizeof(command)) || command.transfer.status!=B_USB_RAW_STATUS_SUCCESS)	{
						fPendingTransfer->transferred=-1;
						printf("failed bulk transfer :(");
						break;
					}
				}
				else
				{
					if(ioctl(fUSBDevice->fRawFD,B_USB_RAW_COMMAND_INTERRUPT_TRANSFER,&command,
						sizeof(command)) || command.transfer.status!=B_USB_RAW_STATUS_SUCCESS)	{
						fPendingTransfer->transferred=-1;
						printf("failed interrupt transfer :(");
						break;
					}
				}
				fPendingTransfer->transferred=command.transfer.length;
			}
			break;
			case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
			{
				usb_raw_command command;
				command.isochronous.interface=fInterface;
				command.isochronous.endpoint=fUSBDevice->fEndpointAddress[fLibusbTransfer->endpoint];
				command.isochronous.data=fLibusbTransfer->buffer;
				command.isochronous.length=fLibusbTransfer->length;
				command.isochronous.packet_count=fLibusbTransfer->num_iso_packets;
				int i=0;
				usb_iso_packet_descriptor *packetDescriptors = new usb_iso_packet_descriptor[fLibusbTransfer->num_iso_packets];
				for (i=0; i<fLibusbTransfer->num_iso_packets; i++)
				{
					if((int16)(fLibusbTransfer->iso_packet_desc[i]).length!=(fLibusbTransfer->iso_packet_desc[i]).length)
					{
						fPendingTransfer->transferred=-1;
						printf("failed isochronous transfer :(");
						break;
					}
					packetDescriptors[i].request_length=(int16)(fLibusbTransfer->iso_packet_desc[i]).length;
				}
				if(i<fLibusbTransfer->num_iso_packets)
				{
					break;
				}
				command.isochronous.packet_descriptors=packetDescriptors;
				if(ioctl(fUSBDevice->fRawFD,B_USB_RAW_COMMAND_ISOCHRONOUS_TRANSFER,&command,
					sizeof(command)) || command.isochronous.status!=B_USB_RAW_STATUS_SUCCESS)	{
					fPendingTransfer->transferred=-1;
					printf("failed isochronous transfer :(");
					break;
				}
				for (i=0; i<fLibusbTransfer->num_iso_packets; i++)
				{
					(fLibusbTransfer->iso_packet_desc[i]).actual_length=packetDescriptors[i].actual_length;
					switch(packetDescriptors[i].status)
					{
						case B_OK: (fLibusbTransfer->iso_packet_desc[i]).status=LIBUSB_TRANSFER_COMPLETED;
							break;
						default: (fLibusbTransfer->iso_packet_desc[i]).status=LIBUSB_TRANSFER_ERROR;
							break;
					}
				}
				fPendingTransfer->transferred=command.transfer.length;
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
	delete_sem(fTransfersSem);
	if(fTransfersThread>0)
		wait_for_thread(fTransfersThread, NULL);
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
				fEndpointAddress[tmp_endpoint.endpoint_address]=k;
				size+=tmp_endpoint.length;
			}
		}
	}
}
