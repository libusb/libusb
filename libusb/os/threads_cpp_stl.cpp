/*
 * C++ STL threading backend for libusb 1.0
 * Copyright © 2025 James Smith <jmsmith86@gmail.com>
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

#include "libusbi.h"

#include <mutex>
#include <condition_variable>
#include <thread>
#include <memory>
#include <list>
#include <thread>
#include <unordered_map>



struct cpp_stl_usbi_mutex_static
{
    std::mutex mtx;
};

// This is here just to ensure these mutexes are properly deleted on program exit
// mutex_static is assumed to have a lifespan until application exit
static std::list<std::unique_ptr<cpp_stl_usbi_mutex_static>> static_mutex_list;

static usbi_mutex_static_t new_usbi_mutex_static()
{
    auto unique_static_mutex = std::unique_ptr<cpp_stl_usbi_mutex_static>(new cpp_stl_usbi_mutex_static);
    usbi_mutex_static_t new_static_mutex = unique_static_mutex.get();
    static_mutex_list.push_back(std::move(unique_static_mutex));
    return new_static_mutex;
}

void usbi_mutex_static_lock(usbi_mutex_static_t *mutex)
{
    {
        // Need to serialize check-and-set logic
        static std::mutex static_mutex_mutex;
        std::lock_guard<std::mutex> lock(static_mutex_mutex);
        if (!(*mutex))
        {
            (*mutex) = new_usbi_mutex_static();
        }
    }

    #pragma warning(suppress: 26115)
    (*mutex)->mtx.lock();
}
void usbi_mutex_static_unlock(usbi_mutex_static_t *mutex)
{
    assert((*mutex) != NULL);
    #pragma warning(suppress: 26110)
    (*mutex)->mtx.unlock();
}

struct cpp_stl_usbi_mutex
{
    std::mutex mtx;
};

void usbi_mutex_init(usbi_mutex_t *mutex)
{
	*mutex = new cpp_stl_usbi_mutex();
}
void usbi_mutex_lock(usbi_mutex_t *mutex)
{
	(*mutex)->mtx.lock();
}
void usbi_mutex_unlock(usbi_mutex_t *mutex)
{
    #pragma warning(suppress: 26110)
	(*mutex)->mtx.unlock();
}
int usbi_mutex_trylock(usbi_mutex_t *mutex)
{
	return (*mutex)->mtx.try_lock();
}
void usbi_mutex_destroy(usbi_mutex_t *mutex)
{
	delete (*mutex);
    (*mutex) = nullptr;
}

struct cpp_stl_usbi_cond
{
    std::condition_variable cv;
    // This is needed because C++ condition_variable is documented to spurriously wake
    bool signaled = false;
};

void usbi_cond_init(usbi_cond_t *cond)
{
	(*cond) = new cpp_stl_usbi_cond();
}
void usbi_cond_wait(usbi_cond_t *cond, usbi_mutex_t *mutex)
{
    #pragma warning(suppress: 26110)
	std::unique_lock<std::mutex> lock((*mutex)->mtx, std::adopt_lock);
    (*cond)->cv.wait(lock, [&cond](){return (*cond)->signaled;});
    (*cond)->signaled = false;
    lock.release();
}
int usbi_cond_timedwait(usbi_cond_t *cond, usbi_mutex_t *mutex, const struct timeval *tv)
{
    #pragma warning(suppress: 26110)
	std::unique_lock<std::mutex> lock((*mutex)->mtx, std::adopt_lock);
    std::cv_status status = (*cond)->cv.wait_for(
        lock,
        std::chrono::seconds(tv->tv_sec) + std::chrono::microseconds(tv->tv_usec)
    );
    lock.release();

    return ((status == std::cv_status::timeout) ? LIBUSB_ERROR_TIMEOUT : 0);
}
void usbi_cond_broadcast(usbi_cond_t *cond)
{
    (*cond)->signaled = true;
	(*cond)->cv.notify_all();
}
void usbi_cond_destroy(usbi_cond_t *cond)
{
	delete (*cond);
    (*cond) = nullptr;
}

struct cpp_stl_usbi_tls
{
    std::mutex mtx;
    // Thread Local Storage means 0 to 1 pointer stored per thread
    std::unordered_map<std::thread::id, void*> ptrs;
};

void usbi_tls_key_create(usbi_tls_key_t *key)
{
	(*key) = new cpp_stl_usbi_tls();
}
void *usbi_tls_key_get(usbi_tls_key_t key)
{
	std::lock_guard<std::mutex> lock(key->mtx);
    auto iter = key->ptrs.find(std::this_thread::get_id());
    if (iter == key->ptrs.end())
    {
        return NULL;
    }
    return iter->second;
}
void usbi_tls_key_set(usbi_tls_key_t key, void *ptr)
{
	std::lock_guard<std::mutex> lock(key->mtx);
    if (ptr)
    {
        key->ptrs.insert_or_assign(std::this_thread::get_id(), ptr);
    }
    else
    {
        key->ptrs.erase(std::this_thread::get_id());
    }
}
void usbi_tls_key_delete(usbi_tls_key_t key)
{
	delete key;
    key = nullptr;
}

unsigned long usbi_get_tid()
{
    const std::thread::id id = std::this_thread::get_id();
    // This is not guaranteed to be 1:1, but this is used only for logging purposes anyway
    return static_cast<unsigned long>(std::hash<std::thread::id>{}(id));
}


