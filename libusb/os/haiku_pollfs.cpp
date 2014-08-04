#include "haiku_usb_raw.h"
#include <Directory.h>
#include <Entry.h>
#include <Looper.h>
#include <Messenger.h>
#include <Node.h>
#include <NodeMonitor.h>
#include <Path.h>
#include <cstring>

class WatchedEntry {
public:
			WatchedEntry(BMessenger*, entry_ref*);
			~WatchedEntry();
	bool		EntryCreated(entry_ref* ref);
	bool		EntryRemoved(ino_t node);

private:
	BMessenger*	fMessenger;
	node_ref	fNode;
	bool		fIsDirectory;
	USBDevice*	fDevice;
	WatchedEntry*	fEntries;
	WatchedEntry*	fLink;
};


class RosterLooper : public BLooper {
public:
			RosterLooper(USBRoster*);
	void		Stop();
	virtual void	MessageReceived(BMessage*);

private:
	USBRoster*	fRoster;
	WatchedEntry*	fRoot;
	BMessenger*	fMessenger;
};


WatchedEntry::WatchedEntry(BMessenger* messenger, entry_ref* ref)
	:	fMessenger(messenger),
		fIsDirectory(false),
		fDevice(NULL),
		fEntries(NULL),
		fLink(NULL)
{
	BEntry entry(ref);
	entry.GetNodeRef(&fNode);

	BDirectory directory;
	if (entry.IsDirectory() && directory.SetTo(ref) >= B_OK) {
		
		fIsDirectory = true;

		while (directory.GetNextEntry(&entry) >= B_OK) {
			if (entry.GetRef(ref) < B_OK)
				continue;

			WatchedEntry* child = new(std::nothrow) WatchedEntry(fMessenger, ref);
			if (child == NULL)
				continue;
			
			child->fLink = fEntries;
			fEntries = child;
		}

		watch_node(&fNode, B_WATCH_DIRECTORY, *fMessenger);
	
	} else {
		if (strncmp(ref->name, "raw", 3) == 0 || strncmp(ref->name, "hub", 3) == 0)
			return;

		BPath path;
		entry.GetPath(&path);
		fDevice = new(std::nothrow) USBDevice(path.Path());
		if (fDevice != NULL) {
			// Add this new device to each active context's device list
			struct libusb_context *ctx;
			unsigned long session_id = (unsigned long)&fDevice;

			usbi_mutex_lock(&active_contexts_lock);
			list_for_each_entry(ctx, &active_contexts_list, list, struct libusb_context) { 

				struct libusb_device* dev = usbi_get_device_by_session_id(ctx, session_id);
				if (dev) {
					//TODO print info
					libusb_unref_device(dev);
					continue;
				}
				dev = usbi_alloc_device(ctx, session_id);
				if (!dev) {
					continue;
				}
				*((USBDevice**)dev->os_priv) = fDevice;
				// TODO Repair
				sscanf(path.Leaf(), "%d", &dev->device_address);
				sscanf(path.Path(), "/dev/bus/usb/%d", &dev->bus_number);
				(dev->device_address)++;

				int fRawFD = open(path.Path(), O_RDWR | O_CLOEXEC);
				if (fRawFD < 0)
				{
					libusb_unref_device(dev);
					continue;
				}
				close(fRawFD);
				if(usbi_sanitize_device(dev) < 0)
				{
					libusb_unref_device(dev);
					continue;
				}
				usbi_connect_device(dev);
			}
			usbi_mutex_unlock(&active_contexts_lock);
		}
	}
}


WatchedEntry::~WatchedEntry()
{
	if (fIsDirectory) {
		watch_node(&fNode, B_STOP_WATCHING, *fMessenger);

		WatchedEntry* child = fEntries;
		while (child) {
			WatchedEntry *next = child->fLink;
			delete child;
			child = next;
		}
	}

	if (fDevice) {
		// Remove this device from each active context's device list 
		struct libusb_context *ctx;
		struct libusb_device *dev;
		unsigned long session_id = (unsigned long)&fDevice;

		usbi_mutex_lock(&active_contexts_lock);
		list_for_each_entry(ctx, &active_contexts_list, list, struct libusb_context) {
			dev = usbi_get_device_by_session_id (ctx, session_id);
			if (dev != NULL) {
				usbi_disconnect_device (dev);
				libusb_unref_device(dev);
			} else {
				//TODO print not found
			}
		}
		usbi_mutex_static_unlock(&active_contexts_lock);
		delete fDevice;
	}
}


bool
WatchedEntry::EntryCreated(entry_ref *ref)
{
	if (!fIsDirectory) 
		return false;

	if (ref->directory != fNode.node) {
		WatchedEntry* child = fEntries;
		while (child) {
			if (child->EntryCreated(ref))
				return true;
			child = child->fLink;
		}
		return false;
	}

	WatchedEntry* child = new(std::nothrow) WatchedEntry(fMessenger, ref);
	if (child == NULL)
		return false;
	child->fLink = fEntries;
	fEntries = child;
	return true;
}


bool
WatchedEntry::EntryRemoved(ino_t node)
{
	if (!fIsDirectory)
		return false;

	WatchedEntry* child = fEntries;
	WatchedEntry* lastChild = NULL;
	while (child) {
		if (child->fNode.node == node) {
			if (lastChild)
				lastChild->fLink = child->fLink;
			else
				fEntries = child->fLink;
			delete child;
			return true;
		}

		if (child->EntryRemoved(node))
			return true;

		lastChild = child;
		child = child->fLink;
	}
	return false;
}


RosterLooper::RosterLooper(USBRoster* roster)
	:	BLooper("LibusbRoster Looper"),
		fRoster(roster),
		fRoot(NULL),
		fMessenger(NULL)
{
	BEntry entry("/dev/bus/usb");
	if (!entry.Exists()) {
		fprintf(stderr,"Libusb: usb_raw not published\n");
		return;
	}

	Run();
	fMessenger = new(std::nothrow) BMessenger(this);
	if (fMessenger == NULL)
		return;

	if(Lock()) {
		entry_ref ref;
		entry.GetRef(&ref);
		fRoot = new(std::nothrow) WatchedEntry(fMessenger, &ref);
		Unlock();
	}
}


void
RosterLooper::Stop()
{
	Lock();
	delete fRoot;
	Quit();
}


void
RosterLooper::MessageReceived(BMessage *message)
{
	int32 opcode;
	if (message->FindInt32("opcode", &opcode) < B_OK)
		return;

	switch (opcode) {
		case B_ENTRY_CREATED: {
			dev_t device;
			ino_t directory;
			const char* name;
			if (message->FindInt32("device", &device) < B_OK
				|| message->FindInt64("directory", &directory) < B_OK
				|| message->FindString("name", &name) < B_OK)
				break;

			entry_ref ref(device, directory, name);
			fRoot->EntryCreated(&ref);
			break;
		}
		case B_ENTRY_REMOVED: {
			ino_t node;
			if (message->FindInt64("node", &node) < B_OK)
				break;
			fRoot->EntryRemoved(node);
			break;
		}
	}
}


USBRoster::USBRoster()
	:	fLooper(NULL)
{
}


USBRoster::~USBRoster()
{
	Stop();
}


void
USBRoster::Start()
{
	if(fLooper)
		return;

	fLooper = new(std::nothrow) RosterLooper(this);
}


void
USBRoster::Stop()
{
	if(!fLooper)
		return;

	((RosterLooper *)fLooper)->Stop();
	fLooper = NULL;
}


