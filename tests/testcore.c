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
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static const int DEFAULT_THREADS = 4;
static const int DEFAULT_LOOPS = 10000;

struct worker_arg {
	libusb_context *ctx;
	int index;
	int loops;
	int failed;
};

static thread_return_t THREAD_CALL_TYPE worker(void *arg)
{
	struct worker_arg *wa = (struct worker_arg *)arg;
	int i;

	for (i = 0; i < wa->loops; i++) {
		libusb_device **list = NULL;
		ssize_t cnt = libusb_get_device_list(wa->ctx, &list);

		if (cnt < 0) {
			fprintf(stderr,
				"thread %d: get_device_list failed: %ld\n",
				wa->index, (long)cnt);
			wa->failed = 1;
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

static void usage(const char *argv0)
{
	printf("Usage: %s [-h] [num_threads [num_loops]]\n", argv0);
	printf("Concurrently enumerates and frees the USB device list.\n");
	printf("  num_threads  number of worker threads (default %d)\n",
		DEFAULT_THREADS);
	printf("  num_loops    get/free device list iterations per thread (default %d)\n",
		DEFAULT_LOOPS);
	printf("On backends without hotplug support (e.g. Windows), every\n"
	       "libusb_get_device_list() performs a full enumeration (~10-100 ms),\n"
	       "so large loop counts (e.g. 100000, useful for bug hunting) can\n"
	       "run for hours.\n");
}

static int parse_count(const char *str, int *out)
{
	char *end;
	long val;

	errno = 0;
	val = strtol(str, &end, 10);
	if (end == str || *end != '\0' || errno != 0 || val <= 0 || val > INT_MAX)
		return -1;

	*out = (int)val;
	return 0;
}

int main(int argc, char *argv[])
{
	libusb_context *ctx = NULL;
	thread_t *threads;
	struct worker_arg *args;
	int num_threads = DEFAULT_THREADS;
	int num_loops = DEFAULT_LOOPS;
	int failed = 0;
	int i;

	if (argc > 1 &&
	    (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
		usage(argv[0]);
		return EXIT_SUCCESS;
	}

	if (argc > 3 ||
	    (argc > 1 && parse_count(argv[1], &num_threads) != 0) ||
	    (argc > 2 && parse_count(argv[2], &num_loops) != 0)) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	/*
	 * To exercise the Linux non-hotplug code path, where every
	 * libusb_get_device_list() rescans instead of returning the
	 * cached list, initialize with:
	 *
	 *   struct libusb_init_option opts[] = {
	 *       { .option = LIBUSB_OPTION_NO_DEVICE_DISCOVERY },
	 *   };
	 *   libusb_init_context(&ctx, opts, 1);
	 */
	if (libusb_init_context(&ctx, /*options=*/NULL, /*num_options=*/0) != 0) {
		fprintf(stderr, "libusb_init_context failed\n");
		return EXIT_FAILURE;
	}

	//libusb_set_option(ctx, LIBUSB_OPTION_LOG_LEVEL, LIBUSB_LOG_LEVEL_DEBUG);

	libusb_device **list = NULL;
	ssize_t cnt = libusb_get_device_list(ctx, &list);
	for (i = 0; i < cnt; i++) {
	    struct libusb_device_descriptor desc;
	    libusb_get_device_descriptor(list[i], &desc);
	    printf("Device %d: %04x:%04x class=0x%02x\n",
	        i, desc.idVendor, desc.idProduct, desc.bDeviceClass);
	}
	libusb_free_device_list(list, 1);

	threads = calloc((size_t)num_threads, sizeof(*threads));
	args = calloc((size_t)num_threads, sizeof(*args));
	if (threads == NULL || args == NULL) {
		fprintf(stderr, "out of memory\n");
		free(threads);
		free(args);
		libusb_exit(ctx);
		return EXIT_FAILURE;
	}

	printf("Starting %d threads, %d loops each...\n", num_threads, num_loops);

	for (i = 0; i < num_threads; i++) {
		args[i].ctx = ctx;
		args[i].index = i;
		args[i].loops = num_loops;
		args[i].failed = 0;

		if (thread_create(&threads[i], worker, &args[i]) != 0) {
			fprintf(stderr, "thread_create failed for thread %d\n", i);
			num_threads = i;
			failed = 1;
			break;
		}
	}

	for (i = 0; i < num_threads; i++)
		thread_join(threads[i]);

	for (i = 0; i < num_threads; i++)
		failed |= args[i].failed;

	free(threads);
	free(args);
	libusb_exit(ctx);

	if (failed) {
		fprintf(stderr, "FAILED\n");
		return EXIT_FAILURE;
	}

	printf("Completed without crash.\n");
	return EXIT_SUCCESS;
}
