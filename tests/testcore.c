/*
 * libusb concurrent get/free_device_list reproducer for issue #1793
 *
 * Repeatedly enumerates and frees the device list from multiple threads
 * to stress concurrent access to:
 *   - usbi_get_device_by_session_id()
 *   - usbi_alloc_device()
 *   - usbi_connect_device()
 *   - libusb_unref_device()
 *   - ctx->usb_devs_lock correctness
 *   - winusb_device_priv setup race in set_composite_interface (Windows)
 *
 * Originally posted by mcuee in
 * https://github.com/libusb/libusb/pull/1795#issuecomment-4258288585
 * Adapted here to use the platform thread abstraction from stress_mt.c
 * so it builds with MSVC.
 */

#include <config.h>

#include <libusb.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(PLATFORM_POSIX)

#include <pthread.h>
#include <sched.h>
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

static inline void thread_yield(void)
{
	sched_yield();
}

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

static inline void thread_yield(void)
{
	Sleep(0);
}

#endif /* PLATFORM_WINDOWS */

#define THREADS 12
#define LOOPS   100000

struct worker_arg {
	libusb_context *ctx;
	int index;
};

static thread_return_t THREAD_CALL_TYPE worker(void *arg)
{
	struct worker_arg *wa = (struct worker_arg *)arg;
	int i;

	for (i = 0; i < LOOPS; i++) {
		libusb_device **list = NULL;
		ssize_t cnt = libusb_get_device_list(wa->ctx, &list);

		if (cnt < 0) {
			fprintf(stderr,
				"thread %d: get_device_list failed: %ld\n",
				wa->index, (long)cnt);
			break;
		}

		/*
		 * Intentionally no inspection of devices.
		 * Just exercise concurrent visibility + refcounting.
		 */

		libusb_free_device_list(list, 1);

		/* Small yield to encourage interleaving */
		if ((i & 0xFF) == 0)
			thread_yield();
	}

	return (thread_return_t)THREAD_RETURN_VALUE;
}

int main(void)
{
	libusb_context *ctx = NULL;
	thread_t threads[THREADS];
	struct worker_arg args[THREADS];
	int i;

	if (libusb_init_context(&ctx, /*options=*/NULL, /*num_options=*/0) != 0) {
		fprintf(stderr, "libusb_init_context failed\n");
		return EXIT_FAILURE;
	}

	//libusb_set_option(ctx, LIBUSB_OPTION_LOG_LEVEL, LIBUSB_LOG_LEVEL_DEBUG);

	libusb_device **list;
	ssize_t cnt = libusb_get_device_list(NULL, &list);
	for (i = 0; i < cnt; i++) {
	    struct libusb_device_descriptor desc;
	    libusb_get_device_descriptor(list[i], &desc);
	    printf("Device %d: %04x:%04x class=0x%02x\n",
	        i, desc.idVendor, desc.idProduct, desc.bDeviceClass);
	}
	libusb_free_device_list(list, 1);

	printf("Starting %d threads, %d loops each...\n", THREADS, LOOPS);

	for (i = 0; i < THREADS; i++) {
		args[i].ctx = ctx;
		args[i].index = i;

		if (thread_create(&threads[i], worker, &args[i]) != 0) {
			fprintf(stderr, "thread_create failed for thread %d\n", i);
			libusb_exit(ctx);
			return EXIT_FAILURE;
		}
	}

	for (i = 0; i < THREADS; i++)
		thread_join(threads[i]);

	printf("Completed without crash.\n");

	libusb_exit(ctx);
	return EXIT_SUCCESS;
}
