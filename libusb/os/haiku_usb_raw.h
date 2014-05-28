#include <List.h>
#include <Locker.h>
#include <Autolock.h>
#include <USBKit.h>
#include "libusbi.h"
#include "usb_raw.h"

//#define TRACE_USB 1
#ifdef TRACE_USB
#define TRACE(x) printf(x);
#endif

#ifdef __cplusplus
extern "C" {
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
	int 							fEndpointAddress[255];
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

#ifdef __cplusplus
}
#endif
