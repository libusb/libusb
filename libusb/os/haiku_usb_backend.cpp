#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <new>
#include <vector>

#include "haiku_usb_raw.h"

int _errno_to_libusb(int status)
{
	return status;
}

USBTransfer::USBTransfer(struct usbi_transfer* itransfer, USBDevice* device)
{
	fUsbiTransfer=itransfer;
	fLibusbTransfer=USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	fUSBDevice=device;
	fCancelled=false;
}

USBTransfer::~USBTransfer()
{
}

struct usbi_transfer*
USBTransfer::itransfer()
{
	return fUsbiTransfer;
}

void
USBTransfer::SetCancelled()
{
	fCancelled=true;
}

bool
USBTransfer::IsCancelled()
{
	return fCancelled;
}

void
USBTransfer::Do(int fRawFD)
{
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
			if(fCancelled)
			{
				break;
			}
			if(ioctl(fRawFD,B_USB_RAW_COMMAND_CONTROL_TRANSFER,&command,
				sizeof(command)) || command.control.status!=B_USB_RAW_STATUS_SUCCESS)	{
				fUsbiTransfer->transferred=-1;
				printf("failed control transfer %d :(",command.transfer.status);
				break;
			}		
			fUsbiTransfer->transferred=command.control.length;
		}
		break;
		case LIBUSB_TRANSFER_TYPE_BULK:
		case LIBUSB_TRANSFER_TYPE_INTERRUPT:
		{
			usb_raw_command command;
			command.transfer.interface=fUSBDevice->EndpointToInterface(fLibusbTransfer->endpoint);
			command.transfer.endpoint=fUSBDevice->EndpointToIndex(fLibusbTransfer->endpoint);
			command.transfer.data=fLibusbTransfer->buffer;
			command.transfer.length=fLibusbTransfer->length;
			if(fCancelled)
			{
				break;
			}
			if(fLibusbTransfer->type==LIBUSB_TRANSFER_TYPE_BULK)
			{
				if(ioctl(fRawFD,B_USB_RAW_COMMAND_BULK_TRANSFER,&command,
					sizeof(command)) || command.transfer.status!=B_USB_RAW_STATUS_SUCCESS)	{
					fUsbiTransfer->transferred=-1;
					printf("failed bulk transfer %d :(",command.transfer.status);
					break;
				}
			}
			else
			{
				if(ioctl(fRawFD,B_USB_RAW_COMMAND_INTERRUPT_TRANSFER,&command,
					sizeof(command)) || command.transfer.status!=B_USB_RAW_STATUS_SUCCESS)	{
					fUsbiTransfer->transferred=-1;
					printf("failed interrupt transfer :(");
					break;
				}
			}
			fUsbiTransfer->transferred=command.transfer.length;
		}
		break;
		case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
		{
			usb_raw_command command;
			command.isochronous.interface=fUSBDevice->EndpointToInterface(fLibusbTransfer->endpoint);
			command.isochronous.endpoint=fUSBDevice->EndpointToIndex(fLibusbTransfer->endpoint);
			command.isochronous.data=fLibusbTransfer->buffer;
			command.isochronous.length=fLibusbTransfer->length;
			command.isochronous.packet_count=fLibusbTransfer->num_iso_packets;
			int i=0;
			usb_iso_packet_descriptor *packetDescriptors = new usb_iso_packet_descriptor[fLibusbTransfer->num_iso_packets];
			for (i=0; i<fLibusbTransfer->num_iso_packets; i++)
			{
				if((int16)(fLibusbTransfer->iso_packet_desc[i]).length!=(fLibusbTransfer->iso_packet_desc[i]).length)
				{
					fUsbiTransfer->transferred=-1;
					printf("failed isochronous transfer :(");
					break;
				}
				packetDescriptors[i].request_length=(int16)(fLibusbTransfer->iso_packet_desc[i]).length;
			}
			if(i<fLibusbTransfer->num_iso_packets)
			{
				break;	//Handle this error
			}
			command.isochronous.packet_descriptors=packetDescriptors;
			if(fCancelled)
			{
				break;
			}
			if(ioctl(fRawFD,B_USB_RAW_COMMAND_ISOCHRONOUS_TRANSFER,&command,
				sizeof(command)) || command.isochronous.status!=B_USB_RAW_STATUS_SUCCESS)	{
				fUsbiTransfer->transferred=-1;
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
			delete[] packetDescriptors;
			fUsbiTransfer->transferred=command.transfer.length; //????
		}
		break;
		default:
			printf("Type other\n");
	}
}

status_t
USBDeviceHandle::TransfersThread(void* self)
{
	USBDeviceHandle* handle = (USBDeviceHandle*)self;
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
		USBTransfer* fPendingTransfer= (USBTransfer*) fTransfers.RemoveItem((int32)0);
		fTransfersLock.Unlock();
		fPendingTransfer->Do(fRawFD);
		write(fEventPipes[1],&fPendingTransfer,sizeof(fPendingTransfer));
	}
}

status_t
USBDeviceHandle::SubmitTransfer(struct usbi_transfer* itransfer)
{
	USBTransfer* transfer = new USBTransfer(itransfer,fUSBDevice);
	*((USBTransfer**)usbi_transfer_get_os_priv(itransfer))=transfer;
	BAutolock locker(fTransfersLock);
	fTransfers.AddItem(transfer);
	release_sem(fTransfersSem);
}

status_t
USBDeviceHandle::CancelTransfer(USBTransfer* transfer)
{
	transfer->SetCancelled();
	fTransfersLock.Lock();
	bool removed = fTransfers.RemoveItem(transfer);
	fTransfersLock.Unlock();
	if(removed)
	{
		write(fEventPipes[1],&transfer,sizeof(transfer));
	}
	return B_OK;
}

USBDeviceHandle::USBDeviceHandle(USBDevice* dev)
	:
	fTransfersThread(-1),
	fUSBDevice(dev),
	fClaimedInterfaces(0)
{
	fRawFD=open(dev->Location(), O_RDWR | O_CLOEXEC);
	if(fRawFD < 0)
	{
		//See how to report
	}
	pipe(fEventPipes);
	fcntl(fEventPipes[1], F_SETFD, O_NONBLOCK);
	fTransfersSem = create_sem(0, "Transfers Queue Sem");
	fTransfersThread = spawn_thread(TransfersThread,"Transfer Worker",B_NORMAL_PRIORITY, this);
	resume_thread(fTransfersThread);
}

USBDeviceHandle::~USBDeviceHandle()
{
	if(fRawFD>0)
		close(fRawFD);
	for(int i=0; i<32; i++)	//as max 32 interfaces, do better
	{
		if(fClaimedInterfaces&(1<<i))
			ReleaseInterface(i);
	}
	if(fEventPipes[1]>0)
		close(fEventPipes[1]);
	if(fEventPipes[0]>0)
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
USBDeviceHandle::ClaimInterface(int inumber)
{
	int status=fUSBDevice->ClaimInterface(inumber);
	if(status==LIBUSB_SUCCESS)
	{
		fClaimedInterfaces|=(1<<inumber);
	}
	return status;
}

int
USBDeviceHandle::ReleaseInterface(int inumber)
{
	fUSBDevice->ReleaseInterface(inumber);
	fClaimedInterfaces&=(!(1<<inumber));
	return LIBUSB_SUCCESS;
}

int
USBDeviceHandle::SetConfiguration(int config)
{
	int config_index=fUSBDevice->CheckInterfacesFree(config);
	if(config_index==LIBUSB_ERROR_BUSY || config_index==LIBUSB_ERROR_NOT_FOUND)
		return config_index;
		
	usb_raw_command command;
	command.config.config_index=config_index;
	if(ioctl(fRawFD,B_USB_RAW_COMMAND_SET_CONFIGURATION,&command,
		sizeof(command)) || command.config.status != B_USB_RAW_STATUS_SUCCESS) {
		return _errno_to_libusb(command.config.status);
	}
	fUSBDevice->SetActiveConfiguration(config_index);
	return LIBUSB_SUCCESS;
}

int
USBDeviceHandle::SetAltSetting(int inumber, int alt)
{
	usb_raw_command command;
	command.alternate.config_index=fUSBDevice->ActiveConfigurationIndex();
	command.alternate.interface_index=inumber;
	if(ioctl(fRawFD,B_USB_RAW_COMMAND_GET_ACTIVE_ALT_INTERFACE_INDEX,&command,
		sizeof(command)) || command.alternate.status!=B_USB_RAW_STATUS_SUCCESS)	{
		printf("Error get alt setting : %d\n",command.alternate.status);
		return _errno_to_libusb(command.alternate.status);
	}
	if(command.alternate.alternate_info == alt)
	{
		printf("Set alt succeeded, already set\n");
		return B_OK;
	}
	command.alternate.alternate_info = alt;
	if(ioctl(fRawFD,B_USB_RAW_COMMAND_SET_ALT_INTERFACE,&command, 	//IF IOCTL FAILS DEVICE DISONNECTED PROBABLY
		sizeof(command)) || command.alternate.status!=B_USB_RAW_STATUS_SUCCESS)	{
		printf("Error set alt setting : %d\n",command.alternate.status);
		return _errno_to_libusb(command.alternate.status);
	}
	printf("Set alt succeeded %d\n",command.alternate.status);
}


USBDevice::USBDevice(const char * path) 
	:
	fPath(NULL),
	fActiveConfiguration(0),	//0?
	fConfigurationDescriptors(NULL),
	fClaimedInterfaces(0),
	fEndpointToIndex(NULL),
	fEndpointToInterface(NULL)
{
	fPath=strdup(path);
	Initialise();
}

USBDevice::~USBDevice()
{
	free(fPath);
	for(int i=0;i<fDeviceDescriptor.num_configurations;i++)
	{
		delete fConfigurationDescriptors[i];
	}
	delete[] fConfigurationDescriptors;
	delete[] fEndpointToIndex;
	delete[] fEndpointToInterface;
}

inline const char*
USBDevice::Location() const
{
	return fPath;
}

inline uint8
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
USBDevice::ActiveConfigurationIndex() const
{
	return fActiveConfiguration;
}

int USBDevice::ClaimInterface(int interface)
{
	if(interface>ActiveConfiguration()->number_interfaces)
	{
		return LIBUSB_ERROR_NOT_FOUND;
	}
	if((fClaimedInterfaces & (1<<interface)) !=0 )
		return LIBUSB_ERROR_BUSY;
	fClaimedInterfaces|=(1<<interface);
	return LIBUSB_SUCCESS;
}

int USBDevice::ReleaseInterface(int interface)
{
	fClaimedInterfaces&=(!(1<<interface));
	return LIBUSB_SUCCESS;
}

int
USBDevice::CheckInterfacesFree(int config)
{
	if(fConfigToIndex.count(config)==0)
		return LIBUSB_ERROR_NOT_FOUND;
	if(fClaimedInterfaces==0)
		return fConfigToIndex[(uint8)config];
	return LIBUSB_ERROR_BUSY;
}

int
USBDevice::SetActiveConfiguration(int config_index)
{
	fActiveConfiguration=config_index;
}

uint8
USBDevice::EndpointToIndex(uint8 address) const
{
	return fEndpointToIndex[fActiveConfiguration][address];
}

uint8
USBDevice::EndpointToInterface(uint8 address) const
{
	return fEndpointToInterface[fActiveConfiguration][address];
}

int 
USBDevice::Initialise()		//Do we need more error checking, etc? How to report?
{
	int fRawFD=open(fPath, O_RDWR | O_CLOEXEC);
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
	fEndpointToIndex = new(std::nothrow) map<uint8,uint8> [fDeviceDescriptor.num_configurations];
	fEndpointToInterface = new(std::nothrow) map<uint8,uint8> [fDeviceDescriptor.num_configurations];
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
		fConfigToIndex[tmp_config.configuration_value]=i;
		fConfigurationDescriptors[i]=new(std::nothrow) unsigned char[tmp_config.total_length];
		command.control.request_type=128;
		command.control.request=6;
		command.control.value=(2<<8)|i;
		command.control.index=0;
		command.control.length=tmp_config.total_length;
		command.control.data=fConfigurationDescriptors[i];
		if(ioctl(fRawFD,B_USB_RAW_COMMAND_CONTROL_TRANSFER,&command,
			sizeof(command)) || command.control.status!=B_USB_RAW_STATUS_SUCCESS)	{
			printf("failed descriptor transfer :(");
			break;
		}
		for( int j=0;j<tmp_config.number_interfaces;j++)
		{
			command.alternate.config_index=i;
			command.alternate.interface_index=j;
			if(ioctl(fRawFD,B_USB_RAW_COMMAND_GET_ALT_INTERFACE_COUNT, &command,
				sizeof(command)) || command.config.status != B_USB_RAW_STATUS_SUCCESS) {
				return B_ERROR;
			}
			int num_alternate=command.alternate.alternate_info;
			for( int k=0;k<num_alternate;k++)
			{
				usb_interface_descriptor tmp_interface;
				command.interface_etc.config_index=i;
				command.interface_etc.interface_index=j;
				command.interface_etc.alternate_index=k;
				command.interface_etc.descriptor=&tmp_interface;
				if(ioctl(fRawFD,B_USB_RAW_COMMAND_GET_INTERFACE_DESCRIPTOR_ETC, &command,
					sizeof(command)) || command.config.status != B_USB_RAW_STATUS_SUCCESS) {
					return B_ERROR;
				}
				for( int l=0;l<tmp_interface.num_endpoints;l++)
				{
					usb_endpoint_descriptor tmp_endpoint;
					command.endpoint_etc.config_index=i;
					command.endpoint_etc.interface_index=j;
					command.endpoint_etc.alternate_index=k;
					command.endpoint_etc.endpoint_index=l;
					command.endpoint_etc.descriptor=&tmp_endpoint;
					if(ioctl(fRawFD,B_USB_RAW_COMMAND_GET_ENDPOINT_DESCRIPTOR_ETC, &command,
						sizeof(command)) || command.config.status != B_USB_RAW_STATUS_SUCCESS) {
						return B_ERROR;
					}
					fEndpointToIndex[i][tmp_endpoint.endpoint_address]=l;
					fEndpointToInterface[i][tmp_endpoint.endpoint_address]=j;
				}
			}
		}
	}
	close(fRawFD);
}
