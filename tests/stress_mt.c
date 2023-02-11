#include "config.h"

#include <libusb.h>
#include <stdio.h>

#if defined (HAVE_PTHREAD_CREATE) || defined(HAVE_WIN_PTHREAD)
#include <pthread.h>

/* Test that creates and destroys contexts repeatedly */

#define NTHREADS 8
#define ITERS 64

static void *test_init_and_exit(void * arg)
{
	long int threadno = (long int)(intptr_t) arg;

	printf("Thread %ld started\n", threadno);
	for (int i = 0; i < ITERS; ++i) {
		libusb_context *ctx = NULL;
		int r;

		r = libusb_init_context(&ctx, /*options=*/NULL, /*num_options=*/0);
		if (r != LIBUSB_SUCCESS) {
			printf("Failed to init libusb on iteration %d: %d", i, r);
			return NULL;
		}
		libusb_exit(ctx);
	}
	printf("Thread %ld done\n", threadno);
	return NULL;
}

int main(void)
{
	pthread_t threadId[NTHREADS];
	long int t;

	printf("Starting multithreaded init and exit test...\n");
	for(t = 0; t < NTHREADS; t++)
		pthread_create(&threadId[t], NULL, &test_init_and_exit, (void *)(intptr_t) t);

	for(t = 0; t < NTHREADS; t++)
		pthread_join(threadId[t], NULL);

	printf("All Done\n");

	return 0;
}

#else
int main(int argc, char **argv)
{
	(void) argc;
	printf("%s: This test requires Posix threads\n", argv[0]);
	/* return success to not upset CI test runs */
	return 0;
}
#endif /* HAVE_PTHREAD_CREATE */
