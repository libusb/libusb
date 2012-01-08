/*
 * libusb synchronization using POSIX Threads
 *
 * Copyright (C) 2011 Vitali Lovich <vlovich@aliph.com>
 * Copyright (C) 2011 Peter Stuge <peter@stuge.se>
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

#ifdef _XOPEN_SOURCE
# if _XOPEN_SOURCE < 500
#  undef _XOPEN_SOURCE
#  define _XOPEN_SOURCE 500
# endif
#else
#define _XOPEN_SOURCE 500
#endif /* _XOPEN_SOURCE */

#include <pthread.h>

int usbi_mutex_init_recursive(pthread_mutex_t *mutex, pthread_mutexattr_t *attr)
{
	int err;
	pthread_mutexattr_t stack_attr;
	if (!attr) {
		attr = &stack_attr;
		err = pthread_mutexattr_init(&stack_attr);
		if (err != 0)
			return err;
	}

	err = pthread_mutexattr_settype(attr, PTHREAD_MUTEX_RECURSIVE);
	if (err != 0)
		goto finish;

	err = pthread_mutex_init(mutex, attr);

finish:
	if (attr == &stack_attr)
		pthread_mutexattr_destroy(&stack_attr);

	return err;
}
