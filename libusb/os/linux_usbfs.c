/*
 * Linux usbfs backend for libusb
 * Copyright (C) 2007-2008 Daniel Drake <dsd@gentoo.org>
 * Copyright (c) 2001 Johannes Erdfelt <johannes@erdfelt.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <config.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "libusb.h"
#include "libusbi.h"
#include "linux_usbfs.h"

static const char *usbfs_path = NULL;
static int have_sysfs;

/* sysfs vs usbfs:
 * opening a usbfs node causes the device to be resumed, so we attempt to
 * avoid this during enumeration.
 *
 * sysfs allows us to read the kernel's in-memory copies of device descriptors
 * and so forth, avoiding the need to open the device:
 *  - The binary "descriptors" file was added in 2.6.23.
 *  - The "busnum" file was added in 2.6.22
 *  - The "devnum" file has been present since pre-2.6.18
 * Hence we check for the existance of a descriptors file to determine whether
 * sysfs provides all the information we need. We effectively require 2.6.23
 * in order to avoid waking suspended devices during enumeration.
 */

struct linux_device_priv {
	/* FIXME remove this, infer from dev->busnum etc */
	char *nodepath;

	union {
		char sysfs_dir[SYSFS_DIR_LENGTH];
		struct {
			unsigned char *dev_descriptor;
			unsigned char *config_descriptor;
		};
	};
};

struct linux_device_handle_priv {
	int fd;
};

enum reap_action {
	NORMAL = 0,
	/* submission failed after the first URB, so await cancellation/completion
	 * of all the others */
	SUBMIT_FAILED,

	/* cancelled by user or timeout */
	CANCELLED,
};

struct linux_transfer_priv {
	union {
		struct usbfs_urb *urbs;
		struct usbfs_urb **iso_urbs;
	};

	enum reap_action reap_action;
	int num_urbs;
	unsigned int awaiting_reap;
	unsigned int awaiting_discard;

	/* next iso packet in user-supplied transfer to be populated */
	int iso_packet_offset;
};

static struct linux_device_priv *__device_priv(struct libusb_device *dev)
{
	return (struct linux_device_priv *) dev->os_priv;
}

static struct linux_device_handle_priv *__device_handle_priv(
	struct libusb_device_handle *handle)
{
	return (struct linux_device_handle_priv *) handle->os_priv;
}

static int check_usb_vfs(const char *dirname)
{
	DIR *dir;
	struct dirent *entry;
	int found = 0;

	dir = opendir(dirname);
	if (!dir)
		return 0;

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.')
			continue;

		/* We assume if we find any files that it must be the right place */
		found = 1;
		break;
	}

	closedir(dir);
	return found;
}

static const char *find_usbfs_path(void)
{
	const char *path = "/dev/bus/usb";
	const char *ret = NULL;

	if (check_usb_vfs(path)) {
		ret = path;
	} else {
		path = "/proc/bus/usb";
		if (check_usb_vfs(path))
			ret = path;
	}

	usbi_dbg("found usbfs at %s", ret);
	return ret;
}

static int op_init(void)
{
	struct stat statbuf;
	int r;

	usbfs_path = find_usbfs_path();
	if (!usbfs_path) {
		usbi_err("could not find usbfs");
		return LIBUSB_ERROR_OTHER;
	}

	r = stat(SYSFS_DEVICE_PATH, &statbuf);
	if (r == 0 && S_ISDIR(statbuf.st_mode)) {
		usbi_dbg("found usb devices in sysfs");
		have_sysfs = 1;
	} else {
		usbi_dbg("sysfs usb info not available");
		have_sysfs = 0;
	}

	return 0;
}

static int usbfs_get_device_descriptor(struct libusb_device *dev,
	unsigned char *buffer)
{
	struct linux_device_priv *priv = __device_priv(dev);

	/* return cached copy */
	memcpy(buffer, priv->dev_descriptor, DEVICE_DESC_LENGTH);
	return 0;
}

static int open_sysfs_descriptors(struct libusb_device *dev)
{
	struct linux_device_priv *priv = __device_priv(dev);
	char filename[PATH_MAX + 1];
	int fd;

	snprintf(filename, PATH_MAX, "%s/%s/descriptors", SYSFS_DEVICE_PATH,
		priv->sysfs_dir);
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		usbi_err("open '%s' failed, ret=%d errno=%d", filename, fd, errno);
		return LIBUSB_ERROR_IO;
	}

	return fd;
}

static int sysfs_get_device_descriptor(struct libusb_device *dev,
	unsigned char *buffer)
{
	int fd;
	ssize_t r;

	/* sysfs provides access to an in-memory copy of the device descriptor,
	 * so we use that rather than keeping our own copy */

	fd = open_sysfs_descriptors(dev);
	if (fd < 0)
		return fd;

	r = read(fd, buffer, DEVICE_DESC_LENGTH);;
	close(fd);
	if (r < 0) {
		usbi_err("read failed, ret=%d errno=%d", fd, errno);
		return LIBUSB_ERROR_IO;
	} else if (r < DEVICE_DESC_LENGTH) {
		usbi_err("short read %d/%d", r, DEVICE_DESC_LENGTH);
		return LIBUSB_ERROR_IO;
	}

	return 0;
}

static int op_get_device_descriptor(struct libusb_device *dev,
	unsigned char *buffer)
{
	if (have_sysfs)
		return sysfs_get_device_descriptor(dev, buffer);
	else
		return usbfs_get_device_descriptor(dev, buffer);
}

static int usbfs_get_active_config_descriptor(struct libusb_device *dev,
	unsigned char *buffer, size_t len)
{
	struct linux_device_priv *priv = __device_priv(dev);
	/* retrieve cached copy */
	memcpy(buffer, priv->config_descriptor, len);
	return 0;
}

static int sysfs_get_active_config_descriptor(struct libusb_device *dev,
	unsigned char *buffer, size_t len)
{
	int fd;
	ssize_t r;
	off_t off;

	/* sysfs provides access to an in-memory copy of the device descriptor,
	 * so we use that rather than keeping our own copy */

	fd = open_sysfs_descriptors(dev);
	if (fd < 0)
		return fd;

	off = lseek(fd, DEVICE_DESC_LENGTH, SEEK_SET);
	if (off < 0) {
		usbi_err("seek failed, ret=%d errno=%d", off, errno);
		close(fd);
		return LIBUSB_ERROR_IO;
	}

	r = read(fd, buffer, len);
	close(fd);
	if (r < 0) {
		usbi_err("read failed, ret=%d errno=%d", fd, errno);
		return LIBUSB_ERROR_IO;
	} else if (r < len) {
		usbi_err("short read %d/%d", r, len);
		return LIBUSB_ERROR_IO;
	}

	return 0;
}

static int op_get_active_config_descriptor(struct libusb_device *dev,
	unsigned char *buffer, size_t len)
{
	if (have_sysfs)
		return sysfs_get_active_config_descriptor(dev, buffer, len);
	else
		return usbfs_get_active_config_descriptor(dev, buffer, len);
}


/* takes a usbfs fd, attempts to find the requested config and copy a certain
 * amount of it into an output buffer. a bConfigurationValue of -1 indicates
 * that the first config should be retreived. */
static int get_config_descriptor(int fd, int bConfigurationValue,
	unsigned char *buffer, size_t len)
{
	unsigned char tmp[8];
	uint8_t num_configurations;
	off_t off;
	ssize_t r;

	if (bConfigurationValue == -1) {
		/* read first configuration */
		off = lseek(fd, DEVICE_DESC_LENGTH, SEEK_SET);
		if (off < 0) {
			usbi_err("seek failed, ret=%d errno=%d", off, errno);
			return LIBUSB_ERROR_IO;
		}
		r = read(fd, buffer, len);
		if (r < 0) {
			usbi_err("read failed ret=%d errno=%d", r, errno);
			return LIBUSB_ERROR_IO;
		} else if (r < len) {
			usbi_err("short output read %d/%d", r, len);
			return LIBUSB_ERROR_IO;
		}
		return 0;
	}

	/* seek to last byte of device descriptor to determine number of
	 * configurations */
	off = lseek(fd, DEVICE_DESC_LENGTH - 1, SEEK_SET);
	if (off < 0) {
		usbi_err("seek failed, ret=%d errno=%d", off, errno);
		return LIBUSB_ERROR_IO;
	}

	r = read(fd, &num_configurations, 1);
	if (r < 0) {
		usbi_err("read num_configurations failed, ret=%d errno=%d", off, errno);
		return LIBUSB_ERROR_IO;
	}

	/* might need to skip some configuration descriptors to reach the
	 * requested configuration */
	while (num_configurations) {
		struct libusb_config_descriptor config;

		/* read first 8 bytes of descriptor */
		r = read(fd, tmp, sizeof(tmp));
		if (r < 0) {
			usbi_err("read failed ret=%d errno=%d", r, errno);
			return LIBUSB_ERROR_IO;
		} else if (r < sizeof(tmp)) {
			usbi_err("short descriptor read %d/%d", r, sizeof(tmp));
			return LIBUSB_ERROR_IO;
		}

		usbi_parse_descriptor(tmp, "bbwbb", &config);
		if (config.bConfigurationValue == bConfigurationValue)
			break;

		/* seek forward to end of config */
		off = lseek(fd, config.wTotalLength - sizeof(tmp), SEEK_CUR);
		if (off < 0) {
			usbi_err("seek failed ret=%d errno=%d", off, errno);
			return LIBUSB_ERROR_IO;
		}

		num_configurations--;
	}

	if (num_configurations == 0)
		return LIBUSB_ERROR_NOT_FOUND;

	/* copy config-so-far */
	memcpy(buffer, tmp, sizeof(tmp));

	/* read the rest of the descriptor */
	r = read(fd, buffer + sizeof(tmp), len - sizeof(tmp));
	if (r < 0) {
		usbi_err("read failed ret=%d errno=%d", r, errno);
		return LIBUSB_ERROR_IO;
	} else if (r < (len - sizeof(tmp))) {
		usbi_err("short output read %d/%d", r, len);
		return LIBUSB_ERROR_IO;
	}

	return 0;
}

static int op_get_config_descriptor(struct libusb_device *dev, uint8_t config,
	unsigned char *buffer, size_t len)
{
	struct linux_device_priv *priv = __device_priv(dev);
	int fd;
	int r;

	/* always read from usbfs: sysfs only has the active descriptor
	 * this will involve waking the device up, but oh well! */

	fd = open(priv->nodepath, O_RDONLY);
	if (fd < 0) {
		usbi_err("open '%s' failed, ret=%d errno=%d",
			priv->nodepath, fd, errno);
		return LIBUSB_ERROR_IO;
	}

	r = get_config_descriptor(fd, config, buffer, len);
	close(fd);
	return r;
}

static int cache_active_config(struct libusb_device *dev, int fd,
	int active_config)
{
	struct linux_device_priv *priv = __device_priv(dev);
	struct libusb_config_descriptor config;
	unsigned char tmp[8];
	unsigned char *buf;
	int r;

	r = get_config_descriptor(fd, active_config, tmp, sizeof(tmp));
	if (r < 0) {
		usbi_err("first read error %d", r);
		return r;
	}

	usbi_parse_descriptor(tmp, "bbw", &config);
	buf = malloc(config.wTotalLength);
	if (!buf)
		return LIBUSB_ERROR_NO_MEM;

	r = get_config_descriptor(fd, active_config, buf, config.wTotalLength);
	if (r < 0) {
		free(buf);
		return r;
	}

	if (priv->config_descriptor)
		free(priv->config_descriptor);
	priv->config_descriptor = buf;
	return 0;
}

static int initialize_device(struct libusb_device *dev, uint8_t busnum,
	uint8_t devaddr, const char *sysfs_dir)
{
	struct linux_device_priv *priv = __device_priv(dev);
	char path[PATH_MAX + 1];

	priv->nodepath = NULL;
	dev->bus_number = busnum;
	dev->device_address = devaddr;

	snprintf(path, PATH_MAX, "%s/%03d/%03d", usbfs_path, busnum, devaddr);
	usbi_dbg("%s", path);

	if (!have_sysfs) {
		/* cache device descriptor in memory so that we can retrieve it later
		 * without waking the device up (op_get_device_descriptor) */
		unsigned char *dev_buf = malloc(DEVICE_DESC_LENGTH);
		int fd;
		ssize_t r;
		int tmp;
		int active_config = 0;

		struct usbfs_ctrltransfer ctrl = {
			.bmRequestType = LIBUSB_ENDPOINT_IN,
			.bRequest = LIBUSB_REQUEST_GET_CONFIGURATION,
			.wValue = 0,
			.wIndex = 0,
			.wLength = 1,
			.timeout = 1000,
			.data = &active_config
		};
		
		priv->dev_descriptor = NULL;
		priv->config_descriptor = NULL;
		if (!dev_buf)
			return LIBUSB_ERROR_NO_MEM;

		fd = open(path, O_RDWR);
		if (fd < 0 && errno == EACCES) {
			usbi_dbg("sysfs unavailable and read-only access to usbfs --> "
				"cannot determine which configuration is active");
			fd = open(path, O_RDONLY);
			/* if we only have read-only access to the device, we cannot
			 * send a control message to determine the active config. just
			 * assume the first one is active. */
			active_config = -1;
		}

		if (fd < 0) {
			usbi_err("open failed, ret=%d errno=%d", fd, errno);
			free(dev_buf);
			return LIBUSB_ERROR_IO;
		}

		r = read(fd, dev_buf, DEVICE_DESC_LENGTH);
		if (r < 0) {
			usbi_err("read descriptor failed ret=%d errno=%d", fd, errno);
			free(dev_buf);
			close(fd);
			return LIBUSB_ERROR_IO;
		} else if (r < DEVICE_DESC_LENGTH) {
			usbi_err("short descriptor read (%d)", r);
			free(dev_buf);
			close(fd);
			return LIBUSB_ERROR_IO;
		}

		if (active_config == 0) {
			/* determine active configuration and cache the descriptor */
			tmp = ioctl(fd, IOCTL_USBFS_CONTROL, &ctrl);
			if (tmp < 0) {
				usbi_err("get_configuration failed ret=%d errno=%d", tmp, errno);
				free(dev_buf);
				close(fd);
				return LIBUSB_ERROR_IO;
			}
		}

		r = cache_active_config(dev, fd, active_config);
		if (r < 0) {
			free(dev_buf);
			close(fd);
			return r;
		}

		priv->dev_descriptor = dev_buf;
		close(fd);
	}

	if (sysfs_dir)
		strncpy(priv->sysfs_dir, sysfs_dir, SYSFS_DIR_LENGTH);

	priv->nodepath = strdup(path);
	if (!priv->nodepath)
		return LIBUSB_ERROR_NO_MEM;

	return 0;
}

static int enumerate_device(struct discovered_devs **_discdevs,
	uint8_t busnum, uint8_t devaddr, const char *sysfs_dir)
{
	struct discovered_devs *discdevs;
	unsigned long session_id;
	int need_unref = 0;
	struct libusb_device *dev;
	int r = 0;

	/* FIXME: session ID is not guaranteed unique as addresses can wrap and
	 * will be reused. instead we should add a simple sysfs attribute with
	 * a session ID. */
	session_id = busnum << 8 | devaddr;
	usbi_dbg("busnum %d devaddr %d session_id %ld", busnum, devaddr,
		session_id);

	dev = usbi_get_device_by_session_id(session_id);
	if (dev) {
		usbi_dbg("using existing device for %d/%d (session %ld)",
			busnum, devaddr, session_id);
	} else {
		usbi_dbg("allocating new device for %d/%d (session %ld)",
			busnum, devaddr, session_id);
		dev = usbi_alloc_device(session_id);
		if (!dev)
			return LIBUSB_ERROR_NO_MEM;
		need_unref = 1;
		r = initialize_device(dev, busnum, devaddr, sysfs_dir);
		if (r < 0)
			goto out;
		r = usbi_sanitize_device(dev);
		if (r < 0)
			goto out;
	}

	discdevs = discovered_devs_append(*_discdevs, dev);
	if (!discdevs)
		r = LIBUSB_ERROR_NO_MEM;
	else
		*_discdevs = discdevs;

out:
	if (need_unref)
		libusb_unref_device(dev);
	return r;
}

/* open a bus directory and adds all discovered devices to discdevs. on
 * failure (non-zero return) the pre-existing discdevs should be destroyed
 * (and devices freed). on success, the new discdevs pointer should be used
 * as it may have been moved. */
static int usbfs_scan_busdir(struct discovered_devs **_discdevs, uint8_t busnum)
{
	DIR *dir;
	char dirpath[PATH_MAX + 1];
	struct dirent *entry;
	struct discovered_devs *discdevs = *_discdevs;
	int r = 0;

	snprintf(dirpath, PATH_MAX, "%s/%03d", usbfs_path, busnum);
	usbi_dbg("%s", dirpath);
	dir = opendir(dirpath);
	if (!dir) {
		usbi_err("opendir '%s' failed, errno=%d", dirpath, errno);
		/* FIXME: should handle valid race conditions like hub unplugged
		 * during directory iteration - this is not an error */
		return LIBUSB_ERROR_IO;
	}

	while ((entry = readdir(dir))) {
		int devaddr;

		if (entry->d_name[0] == '.')
			continue;

		devaddr = atoi(entry->d_name);
		if (devaddr == 0) {
			usbi_dbg("unknown dir entry %s", entry->d_name);
			continue;
		}

		r = enumerate_device(&discdevs, busnum, (uint8_t) devaddr, NULL);
		if (r < 0)
			goto out;
	}

	*_discdevs = discdevs;
out:
	closedir(dir);
	return r;
}

static int usbfs_get_device_list(struct discovered_devs **_discdevs)
{
	struct dirent *entry;
	DIR *buses = opendir(usbfs_path);
	struct discovered_devs *discdevs = *_discdevs;
	int r = 0;

	if (!buses) {
		usbi_err("opendir buses failed errno=%d", errno);
		return LIBUSB_ERROR_IO;
	}

	while ((entry = readdir(buses))) {
		struct discovered_devs *discdevs_new = discdevs;
		int busnum;

		if (entry->d_name[0] == '.')
			continue;

		busnum = atoi(entry->d_name);
		if (busnum == 0) {
			usbi_dbg("unknown dir entry %s", entry->d_name);
			continue;
		}

		r = usbfs_scan_busdir(&discdevs_new, busnum);
		if (r < 0)
			goto out;
		discdevs = discdevs_new;
	}

out:
	closedir(buses);
	*_discdevs = discdevs;
	return r;

}

static int sysfs_scan_device(struct discovered_devs **_discdevs,
	const char *devname)
{
	int r = 0;
	FILE *fd;
	char filename[PATH_MAX + 1];
	int busnum;
	int devaddr;

	usbi_dbg("scan %s", devname);

	snprintf(filename, PATH_MAX, "%s/%s/busnum", SYSFS_DEVICE_PATH, devname);
	fd = fopen(filename, "r");
	if (!fd) {
		usbi_err("open busnum failed, errno=%d", errno);
		return LIBUSB_ERROR_IO;
	}

	r = fscanf(fd, "%d", &busnum);
	fclose(fd);
	if (r != 1) {
		usbi_err("fscanf busnum returned %d, errno=%d", r, errno);
		return LIBUSB_ERROR_IO;
	}

	snprintf(filename, PATH_MAX, "%s/%s/devnum", SYSFS_DEVICE_PATH, devname);
	fd = fopen(filename, "r");
	if (!fd) {
		usbi_err("open devnum failed, errno=%d", errno);
		return LIBUSB_ERROR_IO;
	}

	r = fscanf(fd, "%d", &devaddr);
	fclose(fd);
	if (r != 1) {
		usbi_err("fscanf devnum returned %d, errno=%d", r, errno);
		return LIBUSB_ERROR_IO;
	}

	usbi_dbg("bus=%d dev=%d", busnum, devaddr);
	if (busnum > 255 || devaddr > 255)
		return LIBUSB_ERROR_INVALID_PARAM;

	return enumerate_device(_discdevs, busnum & 0xff, devaddr & 0xff, devname);
}

static int sysfs_get_device_list(struct discovered_devs **_discdevs)
{
	struct discovered_devs *discdevs = *_discdevs;
	DIR *devices = opendir(SYSFS_DEVICE_PATH);
	struct dirent *entry;
	int r = 0;

	if (!devices) {
		usbi_err("opendir devices failed errno=%d", errno);
		return LIBUSB_ERROR_IO;
	}

	while ((entry = readdir(devices))) {
		struct discovered_devs *discdevs_new = discdevs;

		if ((!isdigit(entry->d_name[0]) && strncmp(entry->d_name, "usb", 3))
				|| strchr(entry->d_name, ':'))
			continue;

		r = sysfs_scan_device(&discdevs_new, entry->d_name);
		if (r < 0)
			goto out;
		discdevs = discdevs_new;
	}	

out:
	closedir(devices);
	*_discdevs = discdevs;
	return r;
}

static int op_get_device_list(struct discovered_devs **_discdevs)
{
	/* we can retrieve device list and descriptors from sysfs or usbfs.
	 * sysfs is preferable, because if we use usbfs we end up resuming
	 * any autosuspended USB devices. however, sysfs is not available
	 * everywhere, so we need a usbfs fallback too */
	if (have_sysfs)
		return sysfs_get_device_list(_discdevs);
	else
		return usbfs_get_device_list(_discdevs);
}

static int op_open(struct libusb_device_handle *handle)
{
	struct linux_device_priv *dpriv = __device_priv(handle->dev);
	struct linux_device_handle_priv *hpriv = __device_handle_priv(handle);

	hpriv->fd = open(dpriv->nodepath, O_RDWR);
	if (hpriv->fd < 0) {
		if (errno == EACCES) {
			fprintf(stderr, "libusb couldn't open USB device %s: "
				"Permission denied.\n"
				"libusb requires write access to USB device nodes.\n",
				dpriv->nodepath);
			return LIBUSB_ERROR_ACCESS;
		} else {
			usbi_err("open failed, code %d errno %d", hpriv->fd, errno);
			return LIBUSB_ERROR_IO;
		}
	}

	return usbi_add_pollfd(hpriv->fd, POLLOUT);
}

static void op_close(struct libusb_device_handle *dev_handle)
{
	int fd = __device_handle_priv(dev_handle)->fd;
	usbi_remove_pollfd(fd);
	close(fd);
}

static int op_set_configuration(struct libusb_device_handle *handle, int config)
{
	int fd = __device_handle_priv(handle)->fd;
	int r = ioctl(fd, IOCTL_USBFS_SETCONFIG, &config);
	if (r) {
		if (errno == EINVAL)
			return LIBUSB_ERROR_NOT_FOUND;
		else if (errno == EBUSY)
			return LIBUSB_ERROR_BUSY;

		usbi_err("failed, error %d errno %d", r, errno);
		return LIBUSB_ERROR_OTHER;
	}

	if (!have_sysfs) {
		/* update our cached active config descriptor */
		r = cache_active_config(handle->dev, fd, config);
		if (r < 0)
			usbi_warn("failed to update cached config descriptor, error %d", r);
	}

	return 0;
}

static int op_claim_interface(struct libusb_device_handle *handle, int iface)
{
	int fd = __device_handle_priv(handle)->fd;
	int r = ioctl(fd, IOCTL_USBFS_CLAIMINTF, &iface);
	if (r) {
		if (errno == ENOENT)
			return LIBUSB_ERROR_NOT_FOUND;
		else if (errno == EBUSY)
			return LIBUSB_ERROR_BUSY;

		usbi_err("claim interface failed, error %d errno %d", r, errno);
		return LIBUSB_ERROR_OTHER;
	}
	return 0;
}

static int op_release_interface(struct libusb_device_handle *handle, int iface)
{
	int fd = __device_handle_priv(handle)->fd;
	int r = ioctl(fd, IOCTL_USBFS_RELEASEINTF, &iface);
	if (r) {
		usbi_err("release interface failed, error %d errno %d", r, errno);
		return LIBUSB_ERROR_OTHER;
	}
	return 0;
}

static int op_set_interface(struct libusb_device_handle *handle, int iface,
	int altsetting)
{
	int fd = __device_handle_priv(handle)->fd;
	struct usbfs_setinterface setintf;
	int r;

	setintf.interface = iface;
	setintf.altsetting = altsetting;
	r = ioctl(fd, IOCTL_USBFS_SETINTF, &setintf);
	if (r) {
		if (errno == EINVAL)
			return LIBUSB_ERROR_NOT_FOUND;

		usbi_err("setintf failed error %d errno %d", r, errno);
		return LIBUSB_ERROR_OTHER;
	}

	return 0;
}

static int op_clear_halt(struct libusb_device_handle *handle,
	unsigned char endpoint)
{
	int fd = __device_handle_priv(handle)->fd;
	unsigned int _endpoint = endpoint;
	int r = ioctl(fd, IOCTL_USBFS_CLEAR_HALT, &_endpoint);
	if (r) {
		if (errno == ENOENT)
			return LIBUSB_ERROR_NOT_FOUND;

		usbi_err("clear_halt failed error %d errno %d", r, errno);
		return LIBUSB_ERROR_OTHER;
	}

	return 0;
}

static int op_reset_device(struct libusb_device_handle *handle)
{
	int fd = __device_handle_priv(handle)->fd;
	int r = ioctl(fd, IOCTL_USBFS_RESET, NULL);
	if (r) {
		if (errno == ENODEV)
			return LIBUSB_ERROR_NOT_FOUND;

		usbi_err("reset failed error %d errno %d", r, errno);
		return LIBUSB_ERROR_OTHER;
	}

	return 0;
}

static int op_kernel_driver_active(struct libusb_device_handle *handle,
	int interface)
{
	int fd = __device_handle_priv(handle)->fd;
	struct usbfs_getdriver getdrv;
	int r;

	getdrv.interface = interface;
	r = ioctl(fd, IOCTL_USBFS_GETDRIVER, &getdrv);
	if (r) {
		if (errno == ENODATA)
			return 0;

		usbi_err("get driver failed error %d errno %d", r, errno);
		return LIBUSB_ERROR_OTHER;
	}

	return 1;
}

static int op_detach_kernel_driver(struct libusb_device_handle *handle,
	int interface)
{
	int fd = __device_handle_priv(handle)->fd;
	struct usbfs_ioctl command;
	int r;

	command.ifno = interface;
	command.ioctl_code = IOCTL_USBFS_DISCONNECT;
	command.data = NULL;

	r = ioctl(fd, IOCTL_USBFS_IOCTL, &command);
	if (r) {
		if (errno == ENODATA)
			return LIBUSB_ERROR_NOT_FOUND;
		else if (errno == EINVAL)
			return LIBUSB_ERROR_INVALID_PARAM;

		usbi_err("detach failed error %d errno %d", r, errno);
		return LIBUSB_ERROR_OTHER;
	}

	return 0;
}

static void op_destroy_device(struct libusb_device *dev)
{
	struct linux_device_priv *priv = __device_priv(dev);
	if (priv->nodepath)
		free(priv->nodepath);

	if (!have_sysfs) {
		if (priv->dev_descriptor)
			free(priv->dev_descriptor);
		if (priv->config_descriptor)
			free(priv->config_descriptor);
	}
}

static void free_iso_urbs(struct linux_transfer_priv *tpriv)
{
	int i;
	for (i = 0; i < tpriv->num_urbs; i++) {
		struct usbfs_urb *urb = tpriv->iso_urbs[i];
		if (!urb)
			break;
		free(urb);
	}

	free(tpriv->iso_urbs);
}

static int submit_bulk_transfer(struct usbi_transfer *itransfer,
	unsigned char urb_type)
{
	struct libusb_transfer *transfer =
		__USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct linux_transfer_priv *tpriv = usbi_transfer_get_os_priv(itransfer);
	struct linux_device_handle_priv *dpriv =
		__device_handle_priv(transfer->dev_handle);
	struct usbfs_urb *urbs;
	int r;
	int i;
	size_t alloc_size;

	/* usbfs places a 16kb limit on bulk URBs. we divide up larger requests
	 * into smaller units to meet such restriction, then fire off all the
	 * units at once. it would be simpler if we just fired one unit at a time,
	 * but there is a big performance gain through doing it this way. */
	int num_urbs = transfer->length / MAX_BULK_BUFFER_LENGTH;
	int last_urb_partial = 0;

	if ((transfer->length % MAX_BULK_BUFFER_LENGTH) > 0) {
		last_urb_partial = 1;
		num_urbs++;
	}
	usbi_dbg("need %d urbs for new transfer with length %d", num_urbs,
		transfer->length);
	alloc_size = num_urbs * sizeof(struct usbfs_urb);
	urbs = malloc(alloc_size);
	if (!urbs)
		return LIBUSB_ERROR_NO_MEM;
	memset(urbs, 0, alloc_size);
	tpriv->urbs = urbs;
	tpriv->num_urbs = num_urbs;
	tpriv->awaiting_discard = 0;
	tpriv->awaiting_reap = 0;
	tpriv->reap_action = NORMAL;

	for (i = 0; i < num_urbs; i++) {
		struct usbfs_urb *urb = &urbs[i];
		urb->usercontext = itransfer;
		urb->type = urb_type;
		urb->endpoint = transfer->endpoint;
		urb->buffer = transfer->buffer + (i * MAX_BULK_BUFFER_LENGTH);
		if (i == num_urbs - 1 && last_urb_partial)
			urb->buffer_length = transfer->length % MAX_BULK_BUFFER_LENGTH;
		else
			urb->buffer_length = MAX_BULK_BUFFER_LENGTH;

		r = ioctl(dpriv->fd, IOCTL_USBFS_SUBMITURB, urb);
		if (r < 0) {
			int j;
			usbi_err("submiturb failed error %d errno=%d", r, errno);
	
			/* if the first URB submission fails, we can simply free up and
			 * return failure immediately. */
			if (i == 0) {
				usbi_dbg("first URB failed, easy peasy");
				free(urbs);
				return LIBUSB_ERROR_IO;
			}

			/* if it's not the first URB that failed, the situation is a bit
			 * tricky. we must discard all previous URBs. there are
			 * complications:
			 *  - discarding is asynchronous - discarded urbs will be reaped
			 *    later. the user must not have freed the transfer when the
			 *    discarded URBs are reaped, otherwise libusb will be using
			 *    freed memory.
			 *  - the earlier URBs may have completed successfully and we do
			 *    not want to throw away any data.
			 * so, in this case we discard all the previous URBs BUT we report
			 * that the transfer was submitted successfully. then later when
			 * the final discard completes we can report error to the user.
			 */
			tpriv->reap_action = SUBMIT_FAILED;
			for (j = 0; j < i; j++) {
				int tmp = ioctl(dpriv->fd, IOCTL_USBFS_DISCARDURB, &urbs[j]);
				if (tmp == 0)
					tpriv->awaiting_discard++;
				else if (tmp == -EINVAL)
					tpriv->awaiting_reap++;
				else
					usbi_warn("unrecognised discard return %d", tmp);
			}

			usbi_dbg("reporting successful submission but waiting for %d "
				"discards and %d reaps before reporting error",
				tpriv->awaiting_discard, tpriv->awaiting_reap);
			return 0;
		}
	}

	return 0;
}

static int submit_iso_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer =
		__USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct linux_transfer_priv *tpriv = usbi_transfer_get_os_priv(itransfer);
	struct linux_device_handle_priv *dpriv =
		__device_handle_priv(transfer->dev_handle);
	struct usbfs_urb **urbs;
	size_t alloc_size;
	int num_packets = transfer->num_iso_packets;
	int i;
	int this_urb_len = 0;
	int num_urbs = 1;
	int packet_offset = 0;
	unsigned int packet_len;
	unsigned char *urb_buffer = transfer->buffer;

	/* usbfs places a 32kb limit on iso URBs. we divide up larger requests
	 * into smaller units to meet such restriction, then fire off all the
	 * units at once. it would be simpler if we just fired one unit at a time,
	 * but there is a big performance gain through doing it this way. */

	/* calculate how many URBs we need */
	for (i = 0; i < num_packets; i++) {
		int space_remaining = MAX_ISO_BUFFER_LENGTH - this_urb_len;
		packet_len = transfer->iso_packet_desc[i].length;

		if (packet_len > space_remaining) {
			num_urbs++;
			this_urb_len = packet_len;
		} else {
			this_urb_len += packet_len;
		}
	}
	usbi_dbg("need %d 32k URBs for transfer", num_urbs);

	alloc_size = num_urbs * sizeof(*urbs);
	urbs = malloc(alloc_size);
	if (!urbs)
		return LIBUSB_ERROR_NO_MEM;
	memset(urbs, 0, alloc_size);

	tpriv->iso_urbs = urbs;
	tpriv->num_urbs = num_urbs;
	tpriv->awaiting_discard = 0;
	tpriv->awaiting_reap = 0;
	tpriv->reap_action = NORMAL;
	tpriv->iso_packet_offset = 0;

	/* allocate + initialize each URB with the correct number of packets */
	for (i = 0; i < num_urbs; i++) {
		struct usbfs_urb *urb;
		int space_remaining_in_urb = MAX_ISO_BUFFER_LENGTH;
		int urb_packet_offset = 0;
		unsigned char *urb_buffer_orig = urb_buffer;
		int j;
		int k;

		/* swallow up all the packets we can fit into this URB */
		while (packet_offset < transfer->num_iso_packets) {
			packet_len = transfer->iso_packet_desc[packet_offset].length;
			if (packet_len <= space_remaining_in_urb) {
				/* throw it in */
				urb_packet_offset++;
				packet_offset++;
				space_remaining_in_urb -= packet_len;
				urb_buffer += packet_len;
			} else {
				/* it can't fit, save it for the next URB */
				break;
			}
		}

		alloc_size = sizeof(*urb)
			+ (urb_packet_offset * sizeof(struct usbfs_iso_packet_desc));
		urb = malloc(alloc_size);
		if (!urb) {
			free_iso_urbs(tpriv);
			return LIBUSB_ERROR_NO_MEM;
		}
		memset(urb, 0, alloc_size);
		urbs[i] = urb;

		/* populate packet lengths */
		for (j = 0, k = packet_offset - urb_packet_offset;
				k < packet_offset; k++, j++) {
			packet_len = transfer->iso_packet_desc[k].length;
			urb->iso_frame_desc[j].length = packet_len;
		}

		urb->usercontext = itransfer;
		urb->type = USBFS_URB_TYPE_ISO;
		/* FIXME: interface for non-ASAP data? */
		urb->flags = USBFS_URB_ISO_ASAP;
		urb->endpoint = transfer->endpoint;
		urb->number_of_packets = urb_packet_offset;
		urb->buffer = urb_buffer_orig;
	}

	/* submit URBs */
	for (i = 0; i < num_urbs; i++) {
		int r = ioctl(dpriv->fd, IOCTL_USBFS_SUBMITURB, urbs[i]);
		if (r < 0) {
			int j;
			usbi_err("submiturb failed error %d errno=%d", r, errno);

			/* if the first URB submission fails, we can simply free up and
			 * return failure immediately. */
			if (i == 0) {
				usbi_dbg("first URB failed, easy peasy");
				free_iso_urbs(tpriv);
				return LIBUSB_ERROR_IO;
			}

			/* if it's not the first URB that failed, the situation is a bit
			 * tricky. we must discard all previous URBs. there are
			 * complications:
			 *  - discarding is asynchronous - discarded urbs will be reaped
			 *    later. the user must not have freed the transfer when the
			 *    discarded URBs are reaped, otherwise libusb will be using
			 *    freed memory.
			 *  - the earlier URBs may have completed successfully and we do
			 *    not want to throw away any data.
			 * so, in this case we discard all the previous URBs BUT we report
			 * that the transfer was submitted successfully. then later when
			 * the final discard completes we can report error to the user.
			 */
			tpriv->reap_action = SUBMIT_FAILED;
			for (j = 0; j < i; j++) {
				int tmp = ioctl(dpriv->fd, IOCTL_USBFS_DISCARDURB, urbs[j]);
				if (tmp == 0)
					tpriv->awaiting_discard++;
				else if (tmp == -EINVAL)
					tpriv->awaiting_reap++;
				else
					usbi_warn("unrecognised discard return %d", tmp);
			}

			usbi_dbg("reporting successful submission but waiting for %d "
				"discards and %d reaps before reporting error",
				tpriv->awaiting_discard, tpriv->awaiting_reap);
			return 0;
		}
	}

	return 0;
}

static int submit_control_transfer(struct usbi_transfer *itransfer)
{
	struct linux_transfer_priv *tpriv = usbi_transfer_get_os_priv(itransfer);
	struct libusb_transfer *transfer =
		__USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct linux_device_handle_priv *dpriv =
		__device_handle_priv(transfer->dev_handle);
	struct usbfs_urb *urb;
	int r;

	if (transfer->length - LIBUSB_CONTROL_SETUP_SIZE > MAX_CTRL_BUFFER_LENGTH)
		return LIBUSB_ERROR_INVALID_PARAM;

	urb = malloc(sizeof(struct usbfs_urb));
	if (!urb)
		return LIBUSB_ERROR_NO_MEM;
	memset(urb, 0, sizeof(struct usbfs_urb));
	tpriv->urbs = urb;
	tpriv->reap_action = NORMAL;

	urb->usercontext = itransfer;
	urb->type = USBFS_URB_TYPE_CONTROL;
	urb->endpoint = transfer->endpoint;
	urb->buffer = transfer->buffer;
	urb->buffer_length = transfer->length;

	r = ioctl(dpriv->fd, IOCTL_USBFS_SUBMITURB, urb);
	if (r < 0) {
		usbi_err("submiturb failed error %d errno=%d", r, errno);
		free(urb);
		return LIBUSB_ERROR_IO;
	}
	return 0;
}

static int op_submit_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer =
		__USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);

	switch (transfer->type) {
	case LIBUSB_TRANSFER_TYPE_CONTROL:
		return submit_control_transfer(itransfer);
	case LIBUSB_TRANSFER_TYPE_BULK:
		return submit_bulk_transfer(itransfer, USBFS_URB_TYPE_BULK);
	case LIBUSB_TRANSFER_TYPE_INTERRUPT:
		return submit_bulk_transfer(itransfer, USBFS_URB_TYPE_INTERRUPT);
	case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
		return submit_iso_transfer(itransfer);
	default:
		usbi_err("unknown endpoint type %d", transfer->type);
		return LIBUSB_ERROR_INVALID_PARAM;
	}
}

static int cancel_control_transfer(struct usbi_transfer *itransfer)
{
	struct linux_transfer_priv *tpriv = usbi_transfer_get_os_priv(itransfer);
	struct libusb_transfer *transfer =
		__USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct linux_device_handle_priv *dpriv =
		__device_handle_priv(transfer->dev_handle);
	int r;

	tpriv->reap_action = CANCELLED;
	r = ioctl(dpriv->fd, IOCTL_USBFS_DISCARDURB, tpriv->urbs);
	if (r == -EINVAL) {
		usbi_dbg("URB not found --> assuming ready to be reaped");
		return 0;
	} else if (r) {
		usbi_err("unrecognised DISCARD code %d", r);
		return LIBUSB_ERROR_OTHER;
	}

	return 0;
}

static void cancel_bulk_transfer(struct usbi_transfer *itransfer)
{
	struct linux_transfer_priv *tpriv = usbi_transfer_get_os_priv(itransfer);
	struct libusb_transfer *transfer =
		__USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct linux_device_handle_priv *dpriv =
		__device_handle_priv(transfer->dev_handle);
	int i;

	tpriv->reap_action = CANCELLED;
	for (i = 0; i < tpriv->num_urbs; i++) {
		int tmp = ioctl(dpriv->fd, IOCTL_USBFS_DISCARDURB, &tpriv->urbs[i]);
		if (tmp == 0)
			tpriv->awaiting_discard++;
		else if (tmp == -EINVAL)
			tpriv->awaiting_reap++;
		else
			usbi_warn("unrecognised discard return %d", tmp);
	}
}

static void cancel_iso_transfer(struct usbi_transfer *itransfer)
{
	struct linux_transfer_priv *tpriv = usbi_transfer_get_os_priv(itransfer);
	struct libusb_transfer *transfer =
		__USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct linux_device_handle_priv *dpriv =
		__device_handle_priv(transfer->dev_handle);
	int i;

	tpriv->reap_action = CANCELLED;
	for (i = 0; i < tpriv->num_urbs; i++) {
		int tmp = ioctl(dpriv->fd, IOCTL_USBFS_DISCARDURB, tpriv->iso_urbs[i]);
		if (tmp == 0)
			tpriv->awaiting_discard++;
		else if (tmp == -EINVAL)
			tpriv->awaiting_reap++;
		else
			usbi_warn("unrecognised discard return %d", tmp);
	}
}

static int op_cancel_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer *transfer =
		__USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);

	switch (transfer->type) {
	case LIBUSB_TRANSFER_TYPE_CONTROL:
		return cancel_control_transfer(itransfer);
	case LIBUSB_TRANSFER_TYPE_BULK:
	case LIBUSB_TRANSFER_TYPE_INTERRUPT:
		cancel_bulk_transfer(itransfer);
		return 0;
	case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
		cancel_iso_transfer(itransfer);
		return 0;
	default:
		usbi_err("unknown endpoint type %d", transfer->type);
		return LIBUSB_ERROR_INVALID_PARAM;
	}
}

static int handle_bulk_completion(struct usbi_transfer *itransfer,
	struct usbfs_urb *urb)
{
	struct linux_transfer_priv *tpriv = usbi_transfer_get_os_priv(itransfer);
	int num_urbs = tpriv->num_urbs;
	int urb_idx = urb - tpriv->urbs;

	usbi_dbg("handling completion status %d of bulk urb %d/%d", urb->status,
		urb_idx + 1, num_urbs);

	if (urb->status == 0)
		itransfer->transferred += urb->actual_length;

	if (tpriv->reap_action != NORMAL) { /* cancelled or submit_fail */
		if (urb->status == -ENOENT) {
			usbi_dbg("CANCEL: detected a cancelled URB");
			if (tpriv->awaiting_discard == 0)
				usbi_err("CANCEL: cancelled URB but not awaiting discards?");
			else
				tpriv->awaiting_discard--;
		} else if (urb->status == 0) {
			usbi_dbg("CANCEL: detected a completed URB");
			if (tpriv->awaiting_reap == 0)
				usbi_err("CANCEL: completed URB not awaiting reap?");
			else
				tpriv->awaiting_reap--;
		} else {
			usbi_warn("unhandled CANCEL urb status %d", urb->status);
		}

		if (tpriv->awaiting_reap == 0 && tpriv->awaiting_discard == 0) {
			usbi_dbg("CANCEL: last URB handled, reporting");
			free(tpriv->urbs);
			if (tpriv->reap_action == CANCELLED)
				usbi_handle_transfer_cancellation(itransfer);
			else
				usbi_handle_transfer_completion(itransfer,
					LIBUSB_TRANSFER_ERROR);
		}
		return 0;
	}

	if (urb->status == -EPIPE) {
		usbi_dbg("detected endpoint stall");
		usbi_handle_transfer_completion(itransfer, LIBUSB_TRANSFER_STALL);
		return 0;
	} else if (urb->status != 0) {
		usbi_warn("unrecognised urb status %d", urb->status);
	}

	/* if we're the last urb or we got less data than requested then we're
	 * done */
	if (urb_idx == num_urbs - 1)
		usbi_dbg("last URB in transfer --> complete!");
	else if (urb->actual_length < urb->buffer_length)
		usbi_dbg("short transfer %d/%d --> complete!",
			urb->actual_length, urb->buffer_length);
	else
		return 0;

	free(tpriv->urbs);
	usbi_handle_transfer_completion(itransfer, LIBUSB_TRANSFER_COMPLETED);
	return 0;
}

static int handle_iso_completion(struct usbi_transfer *itransfer,
	struct usbfs_urb *urb)
{
	struct libusb_transfer *transfer =
		__USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct linux_transfer_priv *tpriv = usbi_transfer_get_os_priv(itransfer);
	int num_urbs = tpriv->num_urbs;
	int urb_idx = 0;
	int i;

	for (i = 0; i < num_urbs; i++) {
		if (urb == tpriv->iso_urbs[i]) {
			urb_idx = i + 1;
			break;
		}
	}
	if (urb_idx == 0) {
		usbi_err("could not locate urb!");
		return LIBUSB_ERROR_NOT_FOUND;
	}

	usbi_dbg("handling completion status %d of iso urb %d/%d", urb->status,
		urb_idx, num_urbs);

	if (urb->status == 0) {
		/* copy isochronous results back in */

		for (i = 0; i < urb->number_of_packets; i++) {
			struct usbfs_iso_packet_desc *urb_desc = &urb->iso_frame_desc[i];
			struct libusb_iso_packet_descriptor *lib_desc =
				&transfer->iso_packet_desc[tpriv->iso_packet_offset++];
			lib_desc->status = urb_desc->status;
			lib_desc->actual_length = urb_desc->actual_length;
		}
	}

	if (tpriv->reap_action != NORMAL) { /* cancelled or submit_fail */
		if (urb->status == -ENOENT) {
			usbi_dbg("CANCEL: detected a cancelled URB");
			if (tpriv->awaiting_discard == 0)
				usbi_err("CANCEL: cancelled URB but not awaiting discards?");
			else
				tpriv->awaiting_discard--;
		} else if (urb->status == 0) {
			usbi_dbg("CANCEL: detected a completed URB");
			if (tpriv->awaiting_reap == 0)
				usbi_err("CANCEL: completed URB not awaiting reap?");
			else
				tpriv->awaiting_reap--;
		} else {
			usbi_warn("unhandled CANCEL urb status %d", urb->status);
		}

		if (tpriv->awaiting_reap == 0 && tpriv->awaiting_discard == 0) {
			usbi_dbg("CANCEL: last URB handled, reporting");
			free_iso_urbs(tpriv);
			if (tpriv->reap_action == CANCELLED)
				usbi_handle_transfer_cancellation(itransfer);
			else
				usbi_handle_transfer_completion(itransfer,
					LIBUSB_TRANSFER_ERROR);
		}
		return 0;
	}

	if (urb->status != 0)
		usbi_warn("unrecognised urb status %d", urb->status);

	/* if we're the last urb or we got less data than requested then we're
	 * done */
	if (urb_idx == num_urbs) {
		usbi_dbg("last URB in transfer --> complete!");
		free_iso_urbs(tpriv);
		usbi_handle_transfer_completion(itransfer, LIBUSB_TRANSFER_COMPLETED);
	}

	return 0;
}

static int handle_control_completion(struct usbi_transfer *itransfer,
	struct usbfs_urb *urb)
{
	struct linux_transfer_priv *tpriv = usbi_transfer_get_os_priv(itransfer);
	int status;

	usbi_dbg("handling completion status %d", urb->status);

	if (urb->status == 0)
		itransfer->transferred += urb->actual_length;

	if (tpriv->reap_action == CANCELLED) {
		if (urb->status != 0 && urb->status != -ENOENT)
			usbi_warn("cancel: unrecognised urb status %d", urb->status);
		free(tpriv->urbs);
		usbi_handle_transfer_cancellation(itransfer);
		return 0;
	}

	if (urb->status == -EPIPE) {
		usbi_dbg("unsupported control request");
		status = LIBUSB_TRANSFER_STALL;
		goto out;
	} else if (urb->status != 0) {
		usbi_warn("unrecognised urb status %d", urb->status);
		status = LIBUSB_TRANSFER_ERROR;
		goto out;
	}

	itransfer->transferred = urb->actual_length;
	status = LIBUSB_TRANSFER_COMPLETED;
out:
	free(tpriv->urbs);
	usbi_handle_transfer_completion(itransfer, status);
	return 0;
}

static int reap_for_handle(struct libusb_device_handle *handle)
{
	struct linux_device_handle_priv *hpriv = __device_handle_priv(handle);
	int r;
	struct usbfs_urb *urb;
	struct usbi_transfer *itransfer;
	struct libusb_transfer *transfer;

	r = ioctl(hpriv->fd, IOCTL_USBFS_REAPURBNDELAY, &urb);
	if (r == -1 && errno == EAGAIN)
		return r;
	if (r < 0) {
		usbi_err("reap failed error %d errno=%d", r, errno);
		return r;
	}

	itransfer = urb->usercontext;
	transfer = __USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);

	usbi_dbg("urb type=%d status=%d transferred=%d", urb->type, urb->status,
		urb->actual_length);

	switch (transfer->type) {
	case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
		return handle_iso_completion(itransfer, urb);
	case LIBUSB_TRANSFER_TYPE_BULK:
	case LIBUSB_TRANSFER_TYPE_INTERRUPT:
		return handle_bulk_completion(itransfer, urb);
	case LIBUSB_TRANSFER_TYPE_CONTROL:
		return handle_control_completion(itransfer, urb);
	default:
		usbi_err("unrecognised endpoint type %x", transfer->type);
		return LIBUSB_ERROR_OTHER;
	}
}

static int op_handle_events(fd_set *readfds, fd_set *writefds)
{
	struct libusb_device_handle *handle;
	int ret = 0;

	pthread_mutex_lock(&usbi_open_devs_lock);
	list_for_each_entry(handle, &usbi_open_devs, list) {
		struct linux_device_handle_priv *hpriv = __device_handle_priv(handle);
		int r;

		if (!FD_ISSET(hpriv->fd, writefds))
			continue;
		r = reap_for_handle(handle);
		if (r == -1 && errno == EAGAIN)
			continue;
		if (r < 0) {
			ret = LIBUSB_ERROR_IO;
			goto out;
		}
	}

out:
	pthread_mutex_unlock(&usbi_open_devs_lock);
	return ret;
}

const struct usbi_os_backend linux_usbfs_backend = {
	.name = "Linux usbfs",
	.init = op_init,
	.exit = NULL,
	.get_device_list = op_get_device_list,
	.get_device_descriptor = op_get_device_descriptor,
	.get_active_config_descriptor = op_get_active_config_descriptor,
	.get_config_descriptor = op_get_config_descriptor,

	.open = op_open,
	.close = op_close,
	.set_configuration = op_set_configuration,
	.claim_interface = op_claim_interface,
	.release_interface = op_release_interface,

	.set_interface_altsetting = op_set_interface,
	.clear_halt = op_clear_halt,
	.reset_device = op_reset_device,

	.kernel_driver_active = op_kernel_driver_active,
	.detach_kernel_driver = op_detach_kernel_driver,

	.destroy_device = op_destroy_device,

	.submit_transfer = op_submit_transfer,
	.cancel_transfer = op_cancel_transfer,

	.handle_events = op_handle_events,

	.device_priv_size = sizeof(struct linux_device_priv),
	.device_handle_priv_size = sizeof(struct linux_device_handle_priv),
	.transfer_priv_size = sizeof(struct linux_transfer_priv),
	.add_iso_packet_size = 0,
};

