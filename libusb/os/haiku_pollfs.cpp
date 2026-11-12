/* -*- Mode: C++; indent-tabs-mode:t ; c-basic-offset:4 -*- */
/*
 * Copyright 2007-2008, Haiku Inc. All rights reserved.
 * Distributed under the terms of the MIT License.
 *
 * Authors:
 *		Michael Lotz <mmlr@mlotz.ch>
 */

#include "haiku_usb.h"
#include <cstdio>
#include <Directory.h>
#include <Entry.h>
#include <Looper.h>
#include <Messenger.h>
#include <Node.h>
#include <NodeMonitor.h>
#include <Path.h>
#include <cstring>

class WatchedEntry;

/* Guards gDeviceRegistry and, with it, the transitions that add a device to a
   context or take it away again. Held by the roster looper thread (device
   arrival and removal) and by USBRoster::EnumerateInto() (a context being
   created), so that those two paths cannot interleave for the same device.

   Lock order is gInitLock -> RosterLooper's BLooper lock -> gRosterLock ->
   active_contexts_lock -> ctx->usb_devs_lock. The BLooper lock sits between
   the first two on every path that takes both: the looper thread holds it
   while dispatching device arrival and removal, the initial tree build in the
   RosterLooper constructor holds it around the WatchedEntry walk, and
   RosterLooper::Stop() takes it before deleting the tree. Nothing may lock the
   looper while holding gRosterLock. The looper thread never takes gInitLock,
   which is what makes it safe to hold gInitLock across the blocking
   RosterLooper::Stop(). */
static usbi_mutex_static_t gRosterLock = USBI_MUTEX_INITIALIZER;

/* Every device the roster currently knows about, in discovery order, so that
   a context populated from the registry ends up with the same device order as
   one populated by the constructor loop below. */
static WatchedEntry *gDeviceRegistry GUARDED_BY(gRosterLock) = NULL;

/* Guards the roster reference count and USBRoster::fLooper. Never taken by
   the looper thread; see the lock order above. */
static usbi_mutex_static_t gInitLock = USBI_MUTEX_INITIALIZER;
static int gInitCount GUARDED_BY(gInitLock) = 0;


class WatchedEntry {
public:
			WatchedEntry(BMessenger *, entry_ref *);
			~WatchedEntry();
	bool		EntryCreated(entry_ref *ref);
	bool		EntryRemoved(ino_t node);
	bool		InitCheck();

	/* Called for a single context. */
	void		AddToContext(struct libusb_context *ctx) REQUIRES(gRosterLock);
	void		RemoveFromContext(struct libusb_context *ctx) REQUIRES(gRosterLock);
	WatchedEntry*	RegistryLink() const { return fRegistryLink; }

private:
	void		Register() REQUIRES(gRosterLock);
	void		Unregister() REQUIRES(gRosterLock);

	BMessenger*	fMessenger;
	node_ref	fNode;
	bool		fIsDirectory;
	USBDevice*	fDevice;
	unsigned long	fSessionID;
	uint8		fBusNumber;
	uint8		fDeviceAddress;
	WatchedEntry*	fEntries;
	WatchedEntry*	fLink;
	WatchedEntry*	fRegistryLink;
	bool		fInitCheck;
};


class RosterLooper : public BLooper {
public:
			RosterLooper(USBRoster *);
	void		Stop();
	virtual void	MessageReceived(BMessage *);
	bool		InitCheck();

private:
	USBRoster*	fRoster;
	WatchedEntry*	fRoot;
	BMessenger*	fMessenger;
	bool		fInitCheck;
};


void
WatchedEntry::Register()
{
	WatchedEntry **tail = &gDeviceRegistry;
	while (*tail != NULL)
		tail = &(*tail)->fRegistryLink;
	*tail = this;
}


void
WatchedEntry::Unregister()
{
	WatchedEntry **link = &gDeviceRegistry;
	while (*link != NULL && *link != this)
		link = &(*link)->fRegistryLink;
	if (*link == this)
		*link = fRegistryLink;
	fRegistryLink = NULL;
}


void
WatchedEntry::AddToContext(struct libusb_context *ctx)
{
	struct libusb_device *dev = usbi_get_device_by_session_id(ctx, fSessionID);
	if (dev != NULL) {
		usbi_dbg(ctx, "using previously allocated device with location %lu", fSessionID);
		libusb_unref_device(dev);
		return;
	}

	usbi_dbg(ctx, "allocating new device with location %lu", fSessionID);
	dev = usbi_alloc_device(ctx, fSessionID);
	if (dev == NULL) {
		/* Logged as an error rather than debug: a context that silently
		   ends up with fewer devices than its siblings is exactly the
		   symptom this backend used to have. */
		usbi_err(ctx, "device allocation failed");
		return;
	}

	*((USBDevice **)usbi_get_device_priv(dev)) = fDevice;
	dev->bus_number = fBusNumber;
	dev->device_address = fDeviceAddress;

	static_assert(sizeof(dev->device_descriptor) == sizeof(usb_device_descriptor),
		      "mismatch between libusb and OS device descriptor sizes");
	memcpy(&dev->device_descriptor, fDevice->Descriptor(), LIBUSB_DT_DEVICE_SIZE);
	usbi_localize_device_descriptor(&dev->device_descriptor);

	if (usbi_sanitize_device(dev) < 0) {
		usbi_err(ctx, "device sanitization failed");
		libusb_unref_device(dev);
		return;
	}

	usbi_connect_device(dev);
}


void
WatchedEntry::RemoveFromContext(struct libusb_context *ctx)
{
	struct libusb_device *dev = usbi_get_device_by_session_id(ctx, fSessionID);
	if (dev == NULL) {
		usbi_dbg(ctx, "device with location %lu not found", fSessionID);
		return;
	}

	if (usbi_atomic_load(&ctx->hotplug_ready)) {
		/* The device-left message takes over the reference held by the
		   context's device list. */
		usbi_disconnect_device(dev);
	} else {
		/* A context is only enumerated but not yet hotplug-ready while
		   it is inside libusb_init_context(); no message is posted
		   there, so nothing would inherit that reference. */
		usbi_detach_device(dev);
		libusb_unref_device(dev);
	}

	libusb_unref_device(dev);
}


WatchedEntry::WatchedEntry(BMessenger *messenger, entry_ref *ref)
	:	fMessenger(messenger),
		fIsDirectory(false),
		fDevice(NULL),
		fSessionID(0),
		fBusNumber(0),
		fDeviceAddress(0),
		fEntries(NULL),
		fLink(NULL),
		fRegistryLink(NULL),
		fInitCheck(false)
{
	BEntry entry(ref);
	entry.GetNodeRef(&fNode);

	BDirectory directory;
	if (entry.IsDirectory() && directory.SetTo(ref) >= B_OK) {
		fIsDirectory = true;

		while (directory.GetNextEntry(&entry) >= B_OK) {
			if (entry.GetRef(ref) < B_OK)
				continue;

			WatchedEntry *child = new(std::nothrow) WatchedEntry(fMessenger, ref);
			if (child == NULL)
				continue;
			if (child->InitCheck() == false) {
				delete child;
				continue;
			}

			child->fLink = fEntries;
			fEntries = child;
		}

		watch_node(&fNode, B_WATCH_DIRECTORY, *fMessenger);
	}
	else {
		if (strncmp(ref->name, "raw", 3) == 0)
			return;

		BPath path, parent_path;
		entry.GetPath(&path);
		fDevice = new(std::nothrow) USBDevice(path.Path());
		if (fDevice == NULL)
			return;
		if (fDevice->InitCheck() == false) {
			/* Loud, because a device dropped here is invisible to
			   every context for as long as the roster lives. */
			usbi_err(NULL, "failed to read descriptors of %s", path.Path());
			delete fDevice;
			fDevice = NULL;
			return;
		}

		/* The session id only has to be unique among the devices that
		   exist at the same time and stable for as long as this entry
		   does; the USBDevice this entry owns is both. */
		fSessionID = (unsigned long)fDevice;

		// Calculate pseudo-device-address
		int addr, tmp;
		if (strcmp(path.Leaf(), "hub") == 0)
			tmp = 100;	//Random Number
		else
			sscanf(path.Leaf(), "%d", &tmp);
		addr = tmp + 1;
		path.GetParent(&parent_path);
		while (strcmp(parent_path.Leaf(), "usb") != 0) {
			sscanf(parent_path.Leaf(), "%d", &tmp);
			addr += tmp + 1;
			parent_path.GetParent(&parent_path);
		}
		sscanf(path.Path(), "/dev/bus/usb/%hhu", &fBusNumber);
		fDeviceAddress = (uint8)(addr - (fBusNumber + 1));

		/* Publish the device to the contexts that exist right now. A
		   context created later picks it up from the registry, in
		   USBRoster::EnumerateInto(). active_contexts_lock is held
		   across the whole loop so that a context cannot be unlinked
		   half way through it. */
		struct libusb_context *ctx;

		usbi_mutex_static_lock(&gRosterLock);
		Register();
		usbi_mutex_static_lock(&active_contexts_lock);
		for_each_context(ctx)
			AddToContext(ctx);
		usbi_mutex_static_unlock(&active_contexts_lock);
		usbi_mutex_static_unlock(&gRosterLock);
	}
	fInitCheck = true;
}


WatchedEntry::~WatchedEntry()
{
	if (fIsDirectory) {
		watch_node(&fNode, B_STOP_WATCHING, *fMessenger);

		WatchedEntry *child = fEntries;
		while (child) {
			WatchedEntry *next = child->fLink;
			delete child;
			child = next;
		}
	}

	if (fDevice) {
		// Remove this device from the registry and from each active
		// context's device list
		struct libusb_context *ctx;

		usbi_mutex_static_lock(&gRosterLock);
		Unregister();
		usbi_mutex_static_lock(&active_contexts_lock);
		for_each_context(ctx)
			RemoveFromContext(ctx);
		usbi_mutex_static_unlock(&active_contexts_lock);
		usbi_mutex_static_unlock(&gRosterLock);

		delete fDevice;
	}
}


bool
WatchedEntry::EntryCreated(entry_ref *ref)
{
	if (!fIsDirectory)
		return false;

	if (ref->directory != fNode.node) {
		WatchedEntry *child = fEntries;
		while (child) {
			if (child->EntryCreated(ref))
				return true;
			child = child->fLink;
		}
		return false;
	}

	WatchedEntry *child = new(std::nothrow) WatchedEntry(fMessenger, ref);
	if (child == NULL)
		return false;
	if (child->InitCheck() == false) {
		delete child;
		return false;
	}
	child->fLink = fEntries;
	fEntries = child;
	return true;
}


bool
WatchedEntry::EntryRemoved(ino_t node)
{
	if (!fIsDirectory)
		return false;

	WatchedEntry *child = fEntries;
	WatchedEntry *lastChild = NULL;
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


bool
WatchedEntry::InitCheck()
{
	return fInitCheck;
}


RosterLooper::RosterLooper(USBRoster *roster)
	:	BLooper("LibusbRoster Looper"),
		fRoster(roster),
		fRoot(NULL),
		fMessenger(NULL),
		fInitCheck(false)
{
	BEntry entry("/dev/bus/usb");
	if (!entry.Exists()) {
		usbi_err(NULL, "usb_raw not published");
		return;
	}

	/* A failing Run() returns without unlocking the looper and without
	   setting its fRunCalled, so the constructor's own lock is still held.
	   Lock() would then nest rather than block and the rest of this would
	   look like it worked, leaving a roster with no thread behind it and a
	   looper that only this thread can ever unlock. Give up instead: Start()
	   takes the object down through Stop(), where Quit() sees fRunCalled
	   unset and simply deletes it. */
	if (Run() < B_OK) {
		usbi_err(NULL, "failed to start the roster looper thread");
		return;
	}

	fMessenger = new(std::nothrow) BMessenger(this);
	if (fMessenger == NULL) {
		usbi_err(NULL, "error creating BMessenger object");
		return;
	}

	if (Lock()) {
		entry_ref ref;
		entry.GetRef(&ref);
		fRoot = new(std::nothrow) WatchedEntry(fMessenger, &ref);
		Unlock();
		if (fRoot == NULL)
			return;
		if (fRoot->InitCheck() == false) {
			delete fRoot;
			fRoot = NULL;
			return;
		}
		fInitCheck = true;
	}
}


void
RosterLooper::Stop()
{
	if (!Lock()) {
		usbi_err(NULL, "failed to lock the roster looper");
		return;
	}

	/* Tear the tree down while this looper is still alive: ~WatchedEntry
	   deregisters its node monitors through fMessenger, whose target is
	   this looper. Clearing fRoot first keeps the messages that Quit()
	   still dispatches away from a partially destroyed tree. */
	WatchedEntry *root = fRoot;
	fRoot = NULL;
	delete root;

	/* Quit() deletes this looper, so nothing may touch a member after it. */
	BMessenger *messenger = fMessenger;
	fMessenger = NULL;
	Quit();
	delete messenger;
}


void
RosterLooper::MessageReceived(BMessage *message)
{
	int32 opcode;
	if (message->FindInt32("opcode", &opcode) < B_OK)
		return;

	/* Stop() clears fRoot under the looper lock, but Quit() still
	   dispatches whatever was already queued. */
	if (fRoot == NULL)
		return;

	switch (opcode) {
		case B_ENTRY_CREATED:
		{
			dev_t device;
			ino_t directory;
			const char *name;
			if (message->FindInt32("device", &device) < B_OK ||
				message->FindInt64("directory", &directory) < B_OK ||
				message->FindString("name", &name) < B_OK)
				break;

			entry_ref ref(device, directory, name);
			fRoot->EntryCreated(&ref);
			break;
		}
		case B_ENTRY_REMOVED:
		{
			ino_t node;
			if (message->FindInt64("node", &node) < B_OK)
				break;
			fRoot->EntryRemoved(node);
			break;
		}
	}
}


bool
RosterLooper::InitCheck()
{
	return fInitCheck;
}


USBRoster::USBRoster()
	:	fLooper(NULL)
{
}


USBRoster::~USBRoster()
{
	usbi_mutex_static_lock(&gInitLock);
	if (gInitCount > 0)
		usbi_warn(NULL, "%d context(s) not deinitialized at exit", gInitCount);
	gInitCount = 0;
	Stop();
	usbi_mutex_static_unlock(&gInitLock);
}


int
USBRoster::Init(struct libusb_context *ctx)
{
	int status = LIBUSB_SUCCESS;

	usbi_mutex_static_lock(&gInitLock);
	if (gInitCount == 0)
		status = Start();
	if (status == LIBUSB_SUCCESS) {
		/* Counted only on success, so that a roster that failed to
		   start is retried by the next context instead of leaving
		   every later context permanently empty. */
		gInitCount++;

		/* Every context has to be given the devices that are already
		   present, not just the one that happened to start the roster.
		   Devices showing up later are added by the roster itself. */
		EnumerateInto(ctx);
	}
	usbi_mutex_static_unlock(&gInitLock);

	return status;
}


void
USBRoster::Exit(struct libusb_context *ctx)
{
	UNUSED(ctx);

	usbi_mutex_static_lock(&gInitLock);
	if (gInitCount > 0 && --gInitCount == 0)
		Stop();
	usbi_mutex_static_unlock(&gInitLock);
}


void
USBRoster::EnumerateInto(struct libusb_context *ctx)
{
	usbi_mutex_static_lock(&gRosterLock);
	for (WatchedEntry *entry = gDeviceRegistry; entry != NULL;
	     entry = entry->RegistryLink())
		entry->AddToContext(ctx);
	usbi_mutex_static_unlock(&gRosterLock);
}


int
USBRoster::Start()
{
	if (fLooper != NULL)
		return LIBUSB_SUCCESS;

	RosterLooper *looper = new(std::nothrow) RosterLooper(this);
	if (looper == NULL)
		return LIBUSB_ERROR_NO_MEM;
	if (looper->InitCheck() == false) {
		/* Run() is called early in the constructor, so the looper
		   thread may already be alive; it has to be taken down through
		   Stop() rather than simply dropped. */
		looper->Stop();
		return LIBUSB_ERROR_OTHER;
	}

	fLooper = looper;
	return LIBUSB_SUCCESS;
}


void
USBRoster::Stop()
{
	if (fLooper == NULL)
		return;

	RosterLooper *looper = (RosterLooper *)fLooper;
	fLooper = NULL;
	looper->Stop();
}
