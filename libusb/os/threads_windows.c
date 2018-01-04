/*
 * libusb synchronization on Microsoft Windows
 *
 * Copyright © 2010 Michael Plante <michael.plante@gmail.com>
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

#include <errno.h>

#include "libusbi.h"

struct usbi_cond_perthread {
	struct list_head list;
	HANDLE event;
};

int usbi_mutex_static_lock(usbi_mutex_static_t *mutex)
{
	while (InterlockedExchange(mutex, 1) == 1)
		SleepEx(0, TRUE);
	return 0;
}

int usbi_mutex_static_unlock(usbi_mutex_static_t *mutex)
{
	InterlockedExchange(mutex, 0);
	return 0;
}

int usbi_mutex_init(usbi_mutex_t *mutex)
{
	InitializeCriticalSection(mutex);
	return 0;
}

int usbi_mutex_lock(usbi_mutex_t *mutex)
{
	EnterCriticalSection(mutex);
	return 0;
}

int usbi_mutex_unlock(usbi_mutex_t *mutex)
{
	LeaveCriticalSection(mutex);
	return 0;
}

int usbi_mutex_trylock(usbi_mutex_t *mutex)
{
	if (TryEnterCriticalSection(mutex))
		return 0;
	else
		return EBUSY;
}

int usbi_mutex_destroy(usbi_mutex_t *mutex)
{
	DeleteCriticalSection(mutex);
	return 0;
}

int usbi_cond_init(usbi_cond_t *cond)
{
	list_init(&cond->waiters);
	list_init(&cond->not_waiting);
	return 0;
}

int usbi_cond_destroy(usbi_cond_t *cond)
{
	// This assumes no one is using this anymore.  The check MAY NOT BE safe.
	struct usbi_cond_perthread *pos, *next;

	if (!list_empty(&cond->waiters))
		return EBUSY; // (!see above!)
	list_for_each_entry_safe(pos, next, &cond->not_waiting, list, struct usbi_cond_perthread) {
		CloseHandle(pos->event);
		list_del(&pos->list);
		free(pos);
	}
	return 0;
}

int usbi_cond_broadcast(usbi_cond_t *cond)
{
	// Assumes mutex is locked; this is not in keeping with POSIX spec, but
	//   libusb does this anyway, so we simplify by not adding more sync
	//   primitives to the CV definition!
	struct usbi_cond_perthread *pos;
	int r = 0;

	list_for_each_entry(pos, &cond->waiters, list, struct usbi_cond_perthread) {
		if (!SetEvent(pos->event))
			r = EINVAL;
	}
	// The wait function will remove its respective item from the list.
	return r;
}

static int usbi_cond_intwait(usbi_cond_t *cond,
	usbi_mutex_t *mutex, DWORD timeout_ms)
{
	struct usbi_cond_perthread *pos;
	DWORD r;

	// Same assumption as usbi_cond_broadcast() holds
	if (list_empty(&cond->not_waiting)) {
		pos = malloc(sizeof(*pos));
		if (pos == NULL)
			return ENOMEM; // This errno is not POSIX-allowed.
		pos->event = CreateEvent(NULL, FALSE, FALSE, NULL); // auto-reset.
		if (pos->event == NULL) {
			free(pos);
			return ENOMEM;
		}
	} else {
		pos = list_first_entry(&cond->not_waiting, struct usbi_cond_perthread, list);
		list_del(&pos->list); // remove from not_waiting list.
		// Ensure the event is clear before waiting
		WaitForSingleObject(pos->event, 0);
	}

	list_add(&pos->list, &cond->waiters);

	LeaveCriticalSection(mutex);
	r = WaitForSingleObject(pos->event, timeout_ms);
	EnterCriticalSection(mutex);

	list_del(&pos->list);
	list_add(&pos->list, &cond->not_waiting);

	if (r == WAIT_OBJECT_0)
		return 0;
	else if (r == WAIT_TIMEOUT)
		return ETIMEDOUT;
	else
		return EINVAL;
}

// N.B.: usbi_cond_*wait() can also return ENOMEM, even though pthread_cond_*wait cannot!
int usbi_cond_wait(usbi_cond_t *cond, usbi_mutex_t *mutex)
{
	return usbi_cond_intwait(cond, mutex, INFINITE);
}

int usbi_cond_timedwait(usbi_cond_t *cond,
	usbi_mutex_t *mutex, const struct timeval *tv)
{
	DWORD millis;

	millis = (DWORD)(tv->tv_sec * 1000) + (tv->tv_usec / 1000);
	/* round up to next millisecond */
	if (tv->tv_usec % 1000)
		millis++;
	return usbi_cond_intwait(cond, mutex, millis);
}

int usbi_tls_key_create(usbi_tls_key_t *key)
{
	*key = TlsAlloc();
	if (*key == TLS_OUT_OF_INDEXES)
		return ENOMEM;
	else
		return 0;
}

void *usbi_tls_key_get(usbi_tls_key_t key)
{
	return TlsGetValue(key);
}

int usbi_tls_key_set(usbi_tls_key_t key, void *value)
{
	if (TlsSetValue(key, value))
		return 0;
	else
		return EINVAL;
}

int usbi_tls_key_delete(usbi_tls_key_t key)
{
	if (TlsFree(key))
		return 0;
	else
		return EINVAL;
}

int usbi_get_tid(void)
{
	return (int)GetCurrentThreadId();
}
