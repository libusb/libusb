/*
 * libusb multi-thread test program
 * Copyright 2022-2023 Tormod Volden
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <config.h>

#include <libusb.h>
#include <stdio.h>
#include <stdbool.h>

#if defined(PLATFORM_POSIX)

#include <pthread.h>
typedef pthread_t thread_t;
typedef void * thread_return_t;
#define THREAD_RETURN_VALUE NULL
#define THREAD_CALL_TYPE

static inline int thread_create(thread_t *thread,
	thread_return_t (*thread_entry)(void *arg), void *arg)
{
	return pthread_create(thread, NULL, thread_entry, arg) == 0 ? 0 : -1;
}

static inline void thread_join(thread_t thread)
{
	(void)pthread_join(thread, NULL);
}

#include <stdatomic.h>

#elif defined(PLATFORM_WINDOWS)

typedef HANDLE thread_t;
#define THREAD_RETURN_VALUE 0
#define THREAD_CALL_TYPE __stdcall

#if defined(__CYGWIN__)
typedef DWORD thread_return_t;
#else
#include <process.h>
typedef unsigned thread_return_t;
#endif

static inline int thread_create(thread_t *thread,
	thread_return_t (__stdcall *thread_entry)(void *arg), void *arg)
{
#if defined(__CYGWIN__)
	*thread = CreateThread(NULL, 0, thread_entry, arg, 0, NULL);
#else
	*thread = (HANDLE)_beginthreadex(NULL, 0, thread_entry, arg, 0, NULL);
#endif
	return *thread != NULL ? 0 : -1;
}

static inline void thread_join(thread_t thread)
{
	(void)WaitForSingleObject(thread, INFINITE);
	(void)CloseHandle(thread);
}

typedef volatile LONG atomic_bool;

#define atomic_exchange InterlockedExchange
#endif /* PLATFORM_WINDOWS */

/* Test that creates and destroys contexts repeatedly */

#define NTHREADS 8
#define ITERS 64
#define MAX_DEVCOUNT 128

struct thread_info {
	int number;
	int enumerate;
	ssize_t devcount;
	int err;
	int iteration;
} tinfo[NTHREADS];

atomic_bool no_access[MAX_DEVCOUNT];

/* Function called by backend during device initialization to convert
 * multi-byte fields in the device descriptor to host-endian format.
 * Copied from libusbi.h as we want test to be realistic and not depend on internals.
 */
static inline void usbi_localize_device_descriptor(struct libusb_device_descriptor *desc)
{
	desc->bcdUSB = libusb_le16_to_cpu(desc->bcdUSB);
	desc->idVendor = libusb_le16_to_cpu(desc->idVendor);
	desc->idProduct = libusb_le16_to_cpu(desc->idProduct);
	desc->bcdDevice = libusb_le16_to_cpu(desc->bcdDevice);
}

static thread_return_t THREAD_CALL_TYPE init_and_exit(void * arg)
{
	struct thread_info *ti = (struct thread_info *) arg;

	for (ti->iteration = 0; ti->iteration < ITERS && !ti->err; ti->iteration++) {
		libusb_context *ctx = NULL;

		if ((ti->err = libusb_init_context(&ctx, /*options=*/NULL, /*num_options=*/0)) != 0) {
			break;
		}
		if (ti->enumerate) {
			libusb_device **devs;
			ti->devcount = libusb_get_device_list(ctx, &devs);
			if (ti->devcount < 0) {
				ti->err = (int)ti->devcount;
				break;
			}
			for (int i = 0; i < ti->devcount && ti->err == 0; i++) {
				libusb_device *dev = devs[i];
				struct libusb_device_descriptor desc;
				if ((ti->err = libusb_get_device_descriptor(dev, &desc)) != 0) {
					break;
				}
				if (no_access[i]) {
					continue;
				}
				libusb_device_handle *dev_handle;
				int open_err = libusb_open(dev, &dev_handle);
				if (open_err == LIBUSB_ERROR_ACCESS
#if defined(PLATFORM_WINDOWS)
				    || open_err == LIBUSB_ERROR_NOT_SUPPORTED
				    || open_err == LIBUSB_ERROR_NOT_FOUND
#endif
						) {
					/* Use atomic swap to ensure we print warning only once across all threads.
					   This is a warning and not a hard error because it should be fine to run tests
					   even if we don't have access to some devices. */
					if (!atomic_exchange(&no_access[i], true)) {
						fprintf(stderr, "No access to device %04x:%04x, skipping transfer tests.\n", desc.idVendor, desc.idProduct);
					}
					continue;
				}
				if (open_err != 0) {
					ti->err = open_err;
					break;
				}
				/* Request raw descriptor via control transfer.
				   This tests opening, transferring and closing from multiple threads in parallel. */
				struct libusb_device_descriptor raw_desc;
				int raw_desc_len = libusb_get_descriptor(dev_handle, LIBUSB_DT_DEVICE, 0, (unsigned char *)&raw_desc, sizeof(raw_desc));
				if (raw_desc_len < 0) {
					ti->err = raw_desc_len;
					goto close;
				}
				if (raw_desc_len != sizeof(raw_desc)) {
					fprintf(stderr, "Thread %d: device %d: unexpected raw descriptor length %d\n",
						ti->number, i, raw_desc_len);
					ti->err = LIBUSB_ERROR_OTHER;
					goto close;
				}
				usbi_localize_device_descriptor(&raw_desc);
#define ASSERT_EQ(field) if (raw_desc.field != desc.field) { \
	fprintf(stderr, "Thread %d: device %d: mismatch in field " #field ": %d != %d\n", \
		ti->number, i, raw_desc.field, desc.field); \
		ti->err = LIBUSB_ERROR_OTHER; \
		goto close; \
}
				ASSERT_EQ(bLength);
				ASSERT_EQ(bDescriptorType);
#if !defined(PLATFORM_WINDOWS)
				/* these are hardcoded by the winusbx HID backend */
				ASSERT_EQ(bcdUSB);
				ASSERT_EQ(bDeviceClass);
				ASSERT_EQ(bDeviceSubClass);
				ASSERT_EQ(bDeviceProtocol);
				ASSERT_EQ(bMaxPacketSize0);
				ASSERT_EQ(bcdDevice);
#endif
				ASSERT_EQ(idVendor);
				ASSERT_EQ(idProduct);
				ASSERT_EQ(iManufacturer);
				ASSERT_EQ(iProduct);
				ASSERT_EQ(iSerialNumber);
				ASSERT_EQ(bNumConfigurations);
			close:
				libusb_close(dev_handle);
			}
			libusb_free_device_list(devs, 1);
		}

		libusb_exit(ctx);
	}
	return (thread_return_t) THREAD_RETURN_VALUE;
}

static int test_multi_init(int enumerate)
{
	thread_t threadId[NTHREADS];
	int errs = 0;
	int t, i;
	ssize_t last_devcount = 0;
	int devcount_mismatch = 0;
	int access_failures = 0;

	printf("Starting %d threads\n", NTHREADS);
	for (t = 0; t < NTHREADS; t++) {
		tinfo[t].err = 0;
		tinfo[t].number = t;
		tinfo[t].enumerate = enumerate;
		thread_create(&threadId[t], &init_and_exit, (void *) &tinfo[t]);
	}

	for (t = 0; t < NTHREADS; t++) {
		thread_join(threadId[t]);
		if (tinfo[t].err) {
			errs++;
			fprintf(stderr,
				"Thread %d failed (iteration %d): %s\n",
				tinfo[t].number,
				tinfo[t].iteration,
				libusb_error_name(tinfo[t].err));
		} else if (enumerate) {
			if (t > 0 && tinfo[t].devcount != last_devcount) {
				devcount_mismatch++;
				printf("Device count mismatch: Thread %d discovered %ld devices instead of %ld\n",
				       tinfo[t].number,
				       (long int) tinfo[t].devcount,
				       (long int) last_devcount);
			}
			last_devcount = tinfo[t].devcount;
		}
	}

	for (i = 0; i < MAX_DEVCOUNT; i++)
		if (no_access[i])
			access_failures++;

	if (enumerate && !devcount_mismatch)
		printf("All threads discovered %ld devices (%i not opened)\n",
		       (long int) last_devcount, access_failures);

	return errs + devcount_mismatch;
}

int main(void)
{
	int errs = 0;

	printf("Running multithreaded init/exit test...\n");
	errs += test_multi_init(0);
	printf("Running multithreaded init/exit test with enumeration...\n");
	errs += test_multi_init(1);
	printf("All done, %d errors\n", errs);

	return errs != 0;
}
