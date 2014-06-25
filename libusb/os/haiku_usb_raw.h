#include <List.h>
#include <Locker.h>
#include <Autolock.h>
#include <USBKit.h>
#include <map>
#include "libusbi.h"
#include "usb_raw.h"

using namespace std;

//#define TRACE_USB 1
#ifdef TRACE_USB
#define TRACE(x) printf(x);
#endif

class USBDevice;
class USBDeviceHandle;
class USBTransfer;

class USBDevice{
public:
											USBDevice(const char *);
	virtual 								~USBDevice();
	const char* 							Location() const;
	uint8 									CountConfigurations() const;
	const usb_device_descriptor* 			Descriptor() const;
	const usb_configuration_descriptor* 	ConfigurationDescriptor(uint32) const;
	const usb_configuration_descriptor* 	ActiveConfiguration() const;
	uint8 									EndpointToIndex(uint8) const;
	uint8 									EndpointToInterface(uint8) const;
	int 									ClaimInterface(int);
	int 									ReleaseInterface(int);
	int 									CheckInterfacesFree(int);
	int 									SetActiveConfiguration(int);
	int										ActiveConfigurationIndex() const;
private:
	int										Initialise();
	unsigned int							fClaimedInterfaces;		//Linux has an arbitrary defined max_interfaces set to 32 
	usb_device_descriptor					fDeviceDescriptor;
	unsigned char**							fConfigurationDescriptors;
	int										fActiveConfiguration;
	char*									fPath;
	map<uint8,uint8>						fConfigToIndex;
	map<uint8,uint8>*						fEndpointToIndex;
	map<uint8,uint8>*						fEndpointToInterface;
};

class USBDeviceHandle{
public:
						USBDeviceHandle(USBDevice* dev);
	virtual				~USBDeviceHandle();
	int 				EventPipe(int) const;
	int 				ClaimInterface(int);
	int 				ReleaseInterface(int);
	int 				SetConfiguration(int);
	int					SetAltSetting(int,int);
	status_t 			SubmitTransfer(struct usbi_transfer*);
	status_t 			CancelTransfer(USBTransfer*);
private:
	int 				fRawFD;
	static status_t 	TransfersThread(void *);
	void 				TransfersWorker();
	USBDevice*			fUSBDevice;
	unsigned int 		fClaimedInterfaces;
	int 				fEventPipes[2];
	BList 				fTransfers;
	BLocker 			fTransfersLock;
	sem_id 				fTransfersSem;
	thread_id 			fTransfersThread;
};

class USBTransfer{
public:
							USBTransfer(struct usbi_transfer*,USBDevice*);
	virtual					~USBTransfer();
	void					Do(int);
	struct usbi_transfer*	itransfer();	//Do better
	void					SetCancelled();
	bool					IsCancelled();
private:
	struct usbi_transfer*	fUsbiTransfer;
	struct libusb_transfer*	fLibusbTransfer;
//	USBDeviceHandle*		fUSBDeviceHandle;
	USBDevice*				fUSBDevice;
	BLocker					fStatusLock;
	bool					fCancelled;
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

