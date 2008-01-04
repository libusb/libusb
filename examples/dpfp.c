/*
 * libusb example program to manipulate U.are.U 4000B fingerprint scanner.
 * Copyright (C) 2007 Daniel Drake <dsd@gentoo.org>
 *
 * Basic image capture program only, does not consider the powerup quirks or
 * the fact that image encryption may be enabled. Not expected to work
 * flawlessly all of the time.
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

#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <libusb/libusb.h>

#define EP_INTR			(1 | LIBUSB_ENDPOINT_IN)
#define EP_DATA			(2 | LIBUSB_ENDPOINT_IN)
#define CTRL_IN			(LIBUSB_TYPE_VENDOR | LIBUSB_ENDPOINT_IN)
#define CTRL_OUT		(LIBUSB_TYPE_VENDOR | LIBUSB_ENDPOINT_OUT)
#define USB_RQ			0x04
#define INTR_LENGTH		64

enum {
	MODE_INIT = 0x00,
	MODE_AWAIT_FINGER_ON = 0x10,
	MODE_AWAIT_FINGER_OFF = 0x12,
	MODE_CAPTURE = 0x20,
	MODE_SHUT_UP = 0x30,
	MODE_READY = 0x80,
};

static int next_state(void);
static int submit_irq_urb(void);
static int submit_img_urb(void);

enum {
	STATE_AWAIT_MODE_CHANGE_AWAIT_FINGER_ON = 1,
	STATE_AWAIT_IRQ_FINGER_DETECTED,
	STATE_AWAIT_MODE_CHANGE_CAPTURE,
	STATE_AWAIT_IMAGE,
	STATE_AWAIT_MODE_CHANGE_AWAIT_FINGER_OFF,
	STATE_AWAIT_IRQ_FINGER_REMOVED,
};

static int state = 0;
static struct libusb_dev_handle *devh = NULL;
static unsigned char imgbuf[0x1b340];
static unsigned char irqbuf[INTR_LENGTH];
static libusb_urb_handle *img_urbh = NULL;
static libusb_urb_handle *irq_urbh = NULL;
static int img_idx = 0;
static int do_exit = 0;

static struct libusb_bulk_transfer imgtrf = {
	.endpoint = EP_DATA,
	.data = imgbuf,
	.length = sizeof(imgbuf),
};

static struct libusb_bulk_transfer irqtrf = {
	.endpoint = EP_INTR,
	.data = irqbuf,
	.length = sizeof(irqbuf),
};

static struct libusb_dev *find_dpfp_device(void)
{
	struct libusb_dev *dev;

	libusb_find_devices();

	for (dev = libusb_get_devices(); dev; dev = libusb_dev_next(dev)) {
		struct libusb_dev_descriptor *desc = libusb_dev_get_descriptor(dev);
		if (desc->idVendor == 0x05ba && desc->idProduct == 0x000a)
			return dev;
	}

	return NULL;
}

static int print_f0_data(void)
{
	unsigned char data[0x10];
	struct libusb_control_transfer transfer = {
		.requesttype = CTRL_IN,
		.request = USB_RQ,
		.value = 0xf0,
		.index = 0,
		.length = sizeof(data),
		.data = data,
	};
	int r;
	unsigned int i;

	r = libusb_control_transfer(devh, &transfer, 0);
	if (r < 0) {
		fprintf(stderr, "F0 error %d\n", r);
		return r;
	}
	if ((unsigned int) r < sizeof(data)) {
		fprintf(stderr, "short read (%d)\n", r);
		return -1;
	}

	printf("F0 data:");
	for (i = 0; i < sizeof(data); i++)
		printf("%02x ", data[i]);
	printf("\n");
	return 0;
}

static int get_hwstat(unsigned char *status)
{
	struct libusb_control_transfer transfer = {
		.requesttype = CTRL_IN,
		.request = USB_RQ,
		.value = 0x07,
		.index = 0,
		.length = 1,
		.data = status,
	};
	int r;

	r = libusb_control_transfer(devh, &transfer, 0);
	if (r < 0) {
		fprintf(stderr, "read hwstat error %d\n", r);
		return r;
	}
	if ((unsigned int) r < 1) {
		fprintf(stderr, "short read (%d)\n", r);
		return -1;
	}

	printf("hwstat reads %02x\n", *status);
	return 0;
}

static int set_hwstat(unsigned char data)
{
	int r;
	struct libusb_control_transfer transfer = {
		.requesttype = CTRL_OUT,
		.request = USB_RQ,
		.value = 0x07,
		.index = 0,
		.length = 1,
		.data = &data,
	};

	printf("set hwstat to %02x\n", data);

	r = libusb_control_transfer(devh, &transfer, 0);
	if (r < 0) {
		fprintf(stderr, "set hwstat error %d\n", r);
		return r;
	}
	if ((unsigned int) r < 1) {
		fprintf(stderr, "short write (%d)", r);
		return -1;
	}

	return 0;
}

static int set_mode(unsigned char data)
{
	int r;
	struct libusb_control_transfer transfer = {
		.requesttype = CTRL_OUT,
		.request = USB_RQ,
		.value = 0x4e,
		.index = 0,
		.length = 1,
		.data = &data,
	};

	printf("set mode %02x\n", data);

	r = libusb_control_transfer(devh, &transfer, 0);
	if (r < 0) {
		fprintf(stderr, "set mode error %d\n", r);
		return r;
	}
	if ((unsigned int) r < 1) {
		fprintf(stderr, "short write (%d)", r);
		return -1;
	}

	return 0;
}

static void cb_mode_changed(struct libusb_dev_handle *_devh,
	struct libusb_urb_handle *urbh, enum fp_urb_cb_status status,
	struct libusb_ctrl_setup *setup, unsigned char *data, int actual_length,
	void *user_data)
{
	if (status != FP_URB_COMPLETED) {
		fprintf(stderr, "mode change URB not completed!\n");
		do_exit = 2;
	}

	printf("async cb_mode_changed\n");
	if (next_state() < 0)
		do_exit = 2;
}

static int set_mode_async(unsigned char data)
{
	libusb_urb_handle *urbh;
	struct libusb_control_transfer transfer = {
		.requesttype = CTRL_OUT,
		.request = USB_RQ,
		.value = 0x4e,
		.index = 0,
		.length = 1,
		.data = &data,
	};

	printf("async set mode %02x\n", data);

	urbh = libusb_async_control_transfer(devh, &transfer, cb_mode_changed, NULL,
		1000);
	if (!urbh) {
		fprintf(stderr, "set mode submit error\n");
		return -1;
	}

	return 0;
}

static int do_sync_intr(unsigned char *data)
{
	struct libusb_bulk_transfer transfer = {
		.endpoint = EP_INTR,
		.data = data,
		.length = INTR_LENGTH,
	};
	int r;
	int transferred;

	r = libusb_interrupt_transfer(devh, &transfer, &transferred, 1000);
	if (r < 0) {
		fprintf(stderr, "intr error %d\n", r);
		return r;
	}
	if (transferred < INTR_LENGTH) {
		fprintf(stderr, "short read (%d)\n", r);
		return -1;
	}

	printf("recv interrupt %04x\n", *((uint16_t *) data));
	return 0;
}

static int sync_intr(unsigned char type)
{	
	int r;
	unsigned char data[INTR_LENGTH];

	while (1) {
		r = do_sync_intr(data);
		if (r < 0)
			return r;
		if (data[0] == type)
			return 0;
	}
}

static int save_to_file(unsigned char *data)
{
	FILE *fd;
	char filename[64];

	sprintf(filename, "finger%d.pgm", img_idx++);
	fd = fopen(filename, "w");
	if (!fd)
		return -1;

	fputs("P5 384 289 255 ", fd);
	fwrite(data + 64, 1, 384*289, fd);
	fclose(fd);
	printf("saved image to %s\n", filename);
	return 0;
}

static int next_state(void)
{
	int r = 0;
	printf("old state: %d\n", state);
	switch (state) {
	case STATE_AWAIT_IRQ_FINGER_REMOVED:
		state = STATE_AWAIT_MODE_CHANGE_AWAIT_FINGER_ON;
		r = set_mode_async(MODE_AWAIT_FINGER_ON);
		break;
	case STATE_AWAIT_MODE_CHANGE_AWAIT_FINGER_ON:
		state = STATE_AWAIT_IRQ_FINGER_DETECTED;
		break;
	case STATE_AWAIT_IRQ_FINGER_DETECTED:
		state = STATE_AWAIT_MODE_CHANGE_CAPTURE;
		r = set_mode_async(MODE_CAPTURE);
		break;
	case STATE_AWAIT_MODE_CHANGE_CAPTURE:
		state = STATE_AWAIT_IMAGE;
		break;
	case STATE_AWAIT_IMAGE:
		state = STATE_AWAIT_MODE_CHANGE_AWAIT_FINGER_OFF;
		r = set_mode_async(MODE_AWAIT_FINGER_OFF);
		break;
	case STATE_AWAIT_MODE_CHANGE_AWAIT_FINGER_OFF:
		state = STATE_AWAIT_IRQ_FINGER_REMOVED;
		break;
	default:
		printf("unrecognised state %d\n", state);
	}
	if (r < 0) {
		fprintf(stderr, "error detected changing state");
		return r;
	}

	printf("new state: %d\n", state);
	return 0;
}

static void cb_irq(libusb_dev_handle *_devh, libusb_urb_handle *urbh,
	enum fp_urb_cb_status status, unsigned char endpoint, int rqlength,
	unsigned char *data, int actual_length, void *user_data)
{
	unsigned char irqtype = data[0];

	if (status != FP_URB_COMPLETED) {
		fprintf(stderr, "irq URB status %d?\n", status);
		do_exit = 2;
		return;
	}

	printf("IRQ callback %02x\n", irqtype);
	switch (state) {
	case STATE_AWAIT_IRQ_FINGER_DETECTED:
		if (irqtype == 0x01) {
			if (next_state() < 0) {
				do_exit = 2;
				return;
			}
		} else {
			printf("finger-on-sensor detected in wrong state!\n");
		}
		break;
	case STATE_AWAIT_IRQ_FINGER_REMOVED:
		if (irqtype == 0x02) {
			if (next_state() < 0) {
				do_exit = 2;
				return;
			}
		} else {
			printf("finger-on-sensor detected in wrong state!\n");
		}
		break;
	}
	if (submit_irq_urb() < 0)
		do_exit = 2;
}

static void cb_img(libusb_dev_handle *_devh, libusb_urb_handle *urbh,
	enum fp_urb_cb_status status, unsigned char endpoint, int rqlength,
	unsigned char *data, int actual_length, void *user_data)
{
	if (status != FP_URB_COMPLETED) {
		fprintf(stderr, "img URB status %d?\n", status);
		do_exit = 2;
		return;
	}

	printf("Image callback\n");
	save_to_file(imgbuf);
	if (next_state() < 0) {
		do_exit = 2;
		return;
	}
	if (submit_img_urb() < 0)
		do_exit = 2;
}

static int submit_irq_urb(void)
{
	libusb_urb_handle_free(irq_urbh);
	irq_urbh = libusb_async_interrupt_transfer(devh, &irqtrf, cb_irq, NULL, 0);
	return irq_urbh != NULL;
}

static int submit_img_urb(void)
{
	libusb_urb_handle_free(img_urbh);
	img_urbh = libusb_async_bulk_transfer(devh, &imgtrf, cb_img, NULL, 0);
	return img_urbh != NULL;
}

static int init_capture(void)
{
	int r;

	r = submit_irq_urb();
	if (r < 0)
		return r;

	r = submit_img_urb();
	if (r < 0) {
		libusb_urb_handle_cancel_sync(devh, img_urbh);
		return r;
	}

	/* start state machine */
	state = STATE_AWAIT_IRQ_FINGER_REMOVED;
	return next_state();
}

static int do_init(void)
{
	unsigned char status;
	int r;

	r = get_hwstat(&status);
	if (r < 0)
		return r;

	if (!(status & 0x80)) {
		r = set_hwstat(status | 0x80);
		if (r < 0)
			return r;
		r = get_hwstat(&status);
		if (r < 0)
			return r;
	}

	status &= ~0x80;
	r = set_hwstat(status);
	if (r < 0)
		return r;

	r = get_hwstat(&status);
	if (r < 0)
		return r;

	r = sync_intr(0x56);
	if (r < 0)
		return r;

	return 0;
}

static void sighandler(int signum)
{
	do_exit = 1;	
}

int main(void)
{
	struct libusb_dev *dev;
	struct sigaction sigact;
	int r = 1;

	r = libusb_init(0);
	if (r < 0) {
		fprintf(stderr, "failed to initialise libusb\n");
		exit(1);
	}

	dev = find_dpfp_device();
	if (!dev) {
		fprintf(stderr, "No device found\n");
		goto out;
	}
	printf("found device\n");

	devh = libusb_open(dev);
	if (!devh) {
		fprintf(stderr, "Could not open device\n");
		goto out;
	}
	printf("opened device\n");

	r = libusb_claim_interface(devh, 0);
	if (r < 0) {
		fprintf(stderr, "usb_claim_interface error %d %s\n", r, strerror(-r));
		goto out;
	}
	printf("claimed interface\n");

	r = print_f0_data();
	if (r < 0)
		goto out_release;

	r = do_init();
	if (r < 0)
		goto out_deinit;

	/* async from here onwards */

	r = init_capture();
	if (r < 0)
		goto out_deinit;

	sigact.sa_handler = sighandler;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;
	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGTERM, &sigact, NULL);
	sigaction(SIGQUIT, &sigact, NULL);

	while (!do_exit) {
		r = libusb_poll();
		if (r < 0)
			goto out_deinit;
	}

	printf("shutting down...\n");

	r = libusb_urb_handle_cancel_sync(devh, irq_urbh);
	if (r < 0)
		goto out_deinit;

	r = libusb_urb_handle_cancel_sync(devh, img_urbh);
	if (r < 0)
		goto out_deinit;
	
	if (do_exit == 1)
		r = 0;
	else
		r = 1;

out_deinit:
	libusb_urb_handle_free(img_urbh);
	libusb_urb_handle_free(irq_urbh);
	set_mode(0);
	set_hwstat(0x80);
out_release:
	libusb_release_interface(devh, 0);
out:
	libusb_close(devh);
	libusb_exit();
	return r >= 0 ? r : -r;
}

