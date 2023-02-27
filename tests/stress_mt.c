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
#endif /* PLATFORM_WINDOWS */

/* Test that creates and destroys contexts repeatedly */

#define NTHREADS 8
#define ITERS 64

static thread_return_t THREAD_CALL_TYPE init_and_exit(void * arg)
{
	long int threadno = (long int)(uintptr_t) arg;

	printf("Thread %ld started\n", threadno);
	for (int i = 0; i < ITERS; ++i) {
		libusb_context *ctx = NULL;
		int r;

		r = libusb_init_context(&ctx, /*options=*/NULL, /*num_options=*/0);
		if (r != LIBUSB_SUCCESS) {
			printf("Failed to init libusb on iteration %d: %d", i, r);
			return (thread_return_t) THREAD_RETURN_VALUE;
		}
		libusb_exit(ctx);
	}
	printf("Thread %ld done\n", threadno);
	return (thread_return_t) THREAD_RETURN_VALUE;
}

int main(void)
{
	thread_t threadId[NTHREADS];
	long int t;

	printf("Starting multithreaded init and exit test...\n");
	for(t = 0; t < NTHREADS; t++)
		thread_create(&threadId[t], &init_and_exit, (void *)(uintptr_t) t);

	for(t = 0; t < NTHREADS; t++)
		thread_join(threadId[t]);

	printf("All Done\n");

	return 0;
}
