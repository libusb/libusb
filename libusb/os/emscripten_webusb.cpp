/*
 * Copyright © 2021 Google LLC
 * Copyright © 2023 Ingvar Stepanyan <me@rreverser.com>
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
 *
 * Authors:
 *		Ingvar Stepanyan <me@rreverser.com>
 */

#include <emscripten/version.h>

static_assert((__EMSCRIPTEN_major__ * 100 * 100 + __EMSCRIPTEN_minor__ * 100 +
			   __EMSCRIPTEN_tiny__) >= 30148,
			  "Emscripten 3.1.48 or newer is required.");

#include <assert.h>
#include <emscripten.h>
#include <emscripten/val.h>

#include <type_traits>
#include <utility>

#include "libusbi.h"

using namespace emscripten;

#ifdef _REENTRANT
#include <emscripten/proxying.h>
#include <emscripten/threading.h>
#include <pthread.h>

static ProxyingQueue queue;
#endif

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-prototypes"
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wshadow"

namespace {

// clang-format off
EM_JS(EM_VAL, usbi_em_promise_catch, (EM_VAL handle), {
	let promise = Emval.toValue(handle);
	promise = promise.then(
		value => ({error : 0, value}),
		error => {
			console.error(error);
			let errorCode = -99; // LIBUSB_ERROR_OTHER
			if (error instanceof DOMException) {
				const ERROR_CODES = {
					// LIBUSB_ERROR_IO
					NetworkError : -1,
					// LIBUSB_ERROR_INVALID_PARAM
					DataError : -2,
					TypeMismatchError : -2,
					IndexSizeError : -2,
					// LIBUSB_ERROR_ACCESS
					SecurityError : -3,
					// LIBUSB_ERROR_NOT_FOUND
					NotFoundError : -5,
					// LIBUSB_ERROR_BUSY
					InvalidStateError : -6,
					// LIBUSB_ERROR_TIMEOUT
					TimeoutError : -7,
					// LIBUSB_ERROR_INTERRUPTED
					AbortError : -10,
					// LIBUSB_ERROR_NOT_SUPPORTED
					NotSupportedError : -12,
				};
				errorCode = ERROR_CODES[error.name] ?? errorCode;
			} else if (error instanceof RangeError || error instanceof TypeError) {
				errorCode = -2; // LIBUSB_ERROR_INVALID_PARAM
			}
			return {error: errorCode, value: undefined};
		}
	);
	return Emval.toHandle(promise);
});

EM_JS(void, usbi_em_copy_from_dataview, (void* dst, EM_VAL src), {
	src = Emval.toValue(src);
	src = new Uint8Array(src.buffer, src.byteOffset, src.byteLength);
	HEAPU8.set(src, dst);
});

// Our implementation proxies operations from multiple threads to the same
// underlying USBDevice on the main thread. This can lead to issues when
// multiple threads try to open/close the same device at the same time.
//
// First, since open/close operations are asynchronous in WebUSB, we can end up
// with multiple open/close operations in flight at the same time, which can
// lead to unpredictable outcome (e.g. device got closed but opening succeeded
// right before that).
//
// Second, since multiple threads are allowed to have their own handles to the
// same device, we need to keep track of number of open handles and close the
// device only when the last handle is closed.
//
// We fix both of these issues by using a shared promise chain that executes
// open and close operations sequentially and keeps track of the reference count
// in each promise's result. This way, we can ensure that only one open/close
// operation is in flight at any given time. Note that we don't need to worry
// about all other operations because they're preconditioned on the device being
// open and having at least 1 reference anyway.
EM_JS(EM_VAL, usbi_em_device_safe_open_close, (EM_VAL device, bool open), {
	device = Emval.toValue(device);
	const symbol = Symbol.for('libusb.open_close_chain');
	let promiseChain = device[symbol] ?? Promise.resolve(0);
	device[symbol] = promiseChain = promiseChain.then(async refCount => {
		if (open) {
			if (!refCount++) {
				await device.open();
			}
		} else {
			if (!--refCount) {
				await device.close();
			}
		}
		return refCount;
	});
	return Emval.toHandle(promiseChain);
});
// clang-format on

libusb_transfer_status getTransferStatus(const val& transfer_result) {
	auto status = transfer_result["status"].as<std::string>();
	if (status == "ok") {
		return LIBUSB_TRANSFER_COMPLETED;
	} else if (status == "stall") {
		return LIBUSB_TRANSFER_STALL;
	} else if (status == "babble") {
		return LIBUSB_TRANSFER_OVERFLOW;
	} else {
		return LIBUSB_TRANSFER_ERROR;
	}
}

// Note: this assumes that `dst` is valid for at least `src.byteLength` bytes.
// This is true for all results returned from WebUSB as we pass max length to
// the transfer APIs.
void copyFromDataView(void* dst, const val& src) {
	usbi_em_copy_from_dataview(dst, src.as_handle());
}

auto getUnsharedMemoryView(void* src, size_t len) {
	auto view = typed_memory_view(len, (uint8_t*)src);
#ifdef _REENTRANT
	// Unfortunately, TypedArrays backed by SharedArrayBuffers are not accepted
	// by most Web APIs, trading off guaranteed thread-safety for performance
	// loss. The usual workaround is to copy them into a new TypedArray, which
	// is what we do here via the `.slice()` method.
	return val(view).call<val>("slice");
#else
	// Non-threaded builds can avoid the copy penalty.
	return view;
#endif
}

// A helper that proxies a function call to the main thread if not already
// there. This is a wrapper around Emscripten's raw proxying API with couple of
// high-level improvements, namely support for destroying lambda on the target
// thread as well as custom return types.
template <typename Func>
auto runOnMain(Func&& func) {
#ifdef _REENTRANT
	if (!emscripten_is_main_runtime_thread()) {
		if constexpr (std::is_same_v<std::invoke_result_t<Func>, void>) {
			bool proxied =
				queue.proxySync(emscripten_main_runtime_thread_id(), [&func] {
					// Capture func by reference and move into a local variable
					// to render the captured func inert on the first (and only)
					// call. This way it can be safely destructed on the main
					// thread instead of the current one when this call
					// finishes. TODO: remove this when
					// https://github.com/emscripten-core/emscripten/issues/20610
					// is fixed.
					auto func_ = std::move(func);
					func_();
				});
			assert(proxied);
			return;
		} else {
			// A storage for the result of the function call.
			// TODO: remove when
			// https://github.com/emscripten-core/emscripten/issues/20611 is
			// implemented.
			std::optional<std::invoke_result_t<Func>> result;
			runOnMain(
				[&result, func = std::move(func)] { result.emplace(func()); });
			return std::move(result.value());
		}
	}
#endif
	return func();
}

// C++ struct representation for `{value, error}` object used by `CaughtPromise`
// below.
struct PromiseResult {
	int error;
	val value;

	PromiseResult() = delete;
	PromiseResult(PromiseResult&&) = default;

	PromiseResult(val&& result)
		: error(result["error"].as<int>()), value(result["value"]) {}

	~PromiseResult() {
		// make sure value is freed on the thread it exists on
		runOnMain([value = std::move(value)] {});
	}
};

struct CaughtPromise : val {
	CaughtPromise(val&& promise)
		: val(wrapPromiseWithCatch(std::move(promise))) {}

	using AwaitResult = PromiseResult;

private:

	// Wrap promise with conversion from some value T to `{value: T, error:
	// number}`.
	static val wrapPromiseWithCatch(val&& promise) {
		auto handle = promise.as_handle();
		handle = usbi_em_promise_catch(handle);
		return val::take_ownership(handle);
	}
};

#define co_await_try(promise)                                   \
	({                                                          \
		PromiseResult result = co_await CaughtPromise(promise); \
		if (result.error) {                                     \
			co_return result.error;                             \
		}                                                       \
		std::move(result.value);                                \
	})

// A helper that runs an asynchronous callback when the promise is resolved.
template <typename Promise, typename OnResult>
val promiseThen(Promise&& promise, OnResult&& onResult) {
	// Save captures from the callback while we can, or they'll be destructed.
	// https://devblogs.microsoft.com/oldnewthing/20211103-00/?p=105870
	auto onResult_ = std::move(onResult);
	onResult_(co_await promise);
	co_return val::undefined();
}

// A helper that runs an asynchronous function on the main thread and blocks the
// current thread until the promise is resolved (via Asyncify "blocking" if
// already on the main thread or regular blocking otherwise).
template <typename Func>
static std::invoke_result_t<Func>::AwaitResult awaitOnMain(Func&& func) {
#ifdef _REENTRANT
	if (!emscripten_is_main_runtime_thread()) {
		// If we're on a different thread, we can't use main thread's Asyncify
		// as multiple threads might be fighting for its state; instead, use
		// proxying to synchronously block the current thread until the promise
		// is complete.
		std::optional<typename std::invoke_result_t<Func>::AwaitResult> result;
		queue.proxySyncWithCtx(
			emscripten_main_runtime_thread_id(),
			[&result, &func](ProxyingQueue::ProxyingCtx ctx) {
				// Same as `func` in `runOnMain`, move to destruct on the first
				// call.
				auto func_ = std::move(func);
				promiseThen(
					func_(),
					[&result, ctx = std::move(ctx)](auto&& result_) mutable {
						result.emplace(std::move(result_));
						ctx.finish();
					});
			});
		return std::move(result.value());
	}
#endif
	// If we're already on the main thread, use Asyncify to block until the
	// promise is resolved.
	return func().await();
}

// A helper that makes a control transfer given a setup pointer (assumed to be
// followed by data payload for out-transfers).
val makeControlTransferPromise(const val& dev, libusb_control_setup* setup) {
	auto params = val::object();

	const char* request_type = "unknown";
	// See LIBUSB_REQ_TYPE in windows_winusb.h (or docs for `bmRequestType`).
	switch (setup->bmRequestType & (0x03 << 5)) {
		case LIBUSB_REQUEST_TYPE_STANDARD:
			request_type = "standard";
			break;
		case LIBUSB_REQUEST_TYPE_CLASS:
			request_type = "class";
			break;
		case LIBUSB_REQUEST_TYPE_VENDOR:
			request_type = "vendor";
			break;
	}
	params.set("requestType", request_type);

	const char* recipient = "other";
	switch (setup->bmRequestType & 0x0f) {
		case LIBUSB_RECIPIENT_DEVICE:
			recipient = "device";
			break;
		case LIBUSB_RECIPIENT_INTERFACE:
			recipient = "interface";
			break;
		case LIBUSB_RECIPIENT_ENDPOINT:
			recipient = "endpoint";
			break;
	}
	params.set("recipient", recipient);

	params.set("request", setup->bRequest);
	params.set("value", setup->wValue);
	params.set("index", setup->wIndex);

	if (setup->bmRequestType & LIBUSB_ENDPOINT_IN) {
		return dev.call<val>("controlTransferIn", params, setup->wLength);
	} else {
		return dev.call<val>("controlTransferOut", params,
							 getUnsharedMemoryView(setup + 1, setup->wLength));
	}
}

// Smart pointer for managing pointers to places allocated by libusb inside its
// backend structures.
template <typename T>
struct ValPtr {
	template <typename... Args>
	void emplace(Args&&... args) {
		new (ptr) T(std::forward<Args>(args)...);
	}

	const T& operator*() const { return *ptr; }
	T& operator*() { return *ptr; }

	const T* operator->() const { return ptr; }
	T* operator->() { return ptr; }

	void free() { ptr->~T(); }

	T take() {
		auto value = std::move(*ptr);
		free();
		return value;
	}

protected:

	ValPtr(void* ptr) : ptr(static_cast<T*>(ptr)) {}

private:

	// Note: this is not a heap-allocated pointer, but a pointer to a part
	// of the backend structure allocated by libusb itself.
	T* ptr;
};

struct CachedDevice;

struct WebUsbDevicePtr : ValPtr<CachedDevice> {
public:

	WebUsbDevicePtr(libusb_device* dev) : ValPtr(usbi_get_device_priv(dev)) {}
	WebUsbDevicePtr(libusb_device_handle* handle)
		: WebUsbDevicePtr(handle->dev) {}
};

struct WebUsbTransferPtr : ValPtr<PromiseResult> {
public:

	WebUsbTransferPtr(usbi_transfer* itransfer)
		: ValPtr(usbi_get_transfer_priv(itransfer)) {}
};

enum class OpenClose : bool {
	Open = true,
	Close = false,
};

struct CachedDevice {
	CachedDevice() = delete;
	CachedDevice(CachedDevice&&) = delete;

	// Fill in the device descriptor and configurations by reading them from the
	// WebUSB device.
	static val initFromDevice(val&& web_usb_dev, libusb_device* libusb_dev) {
		auto cachedDevicePtr = WebUsbDevicePtr(libusb_dev);
		cachedDevicePtr.emplace(std::move(web_usb_dev));
		bool must_close = false;
		val result = co_await cachedDevicePtr->initFromDeviceWithoutClosing(
			libusb_dev, must_close);
		if (must_close) {
			co_await_try(cachedDevicePtr->safeOpenCloseAssumingMainThread(
				OpenClose::Close));
		}
		co_return std::move(result);
	}

	const val& getDeviceAssumingMainThread() const { return device; }

	uint8_t getActiveConfigValue() const {
		return runOnMain([&] {
			auto web_usb_config = device["configuration"];
			return web_usb_config.isNull()
				? 0
				: web_usb_config["configurationValue"].as<uint8_t>();
		});
	}

	usbi_configuration_descriptor* getConfigDescriptor(uint8_t config_id) {
		return config_id < configurations.size()
			? configurations[config_id].get()
			: nullptr;
	}

	usbi_configuration_descriptor* findConfigDescriptorByValue(
		uint8_t config_id) const {
		for (auto& config : configurations) {
			if (config->bConfigurationValue == config_id) {
				return config.get();
			}
		}
		return nullptr;
	}

	int copyConfigDescriptor(const usbi_configuration_descriptor* config,
							 void* buf,
							 size_t buf_len) {
		auto len = std::min(buf_len, (size_t)config->wTotalLength);
		memcpy(buf, config, len);
		return len;
	}

	template <typename... Args>
	int awaitOnMain(const char* methodName, Args&&... args) const {
		return ::awaitOnMain([&] {
				   return CaughtPromise(device.call<val>(
					   methodName, std::forward<Args>(args)...));
			   })
			.error;
	}

	~CachedDevice() {
		runOnMain([device = std::move(device)] {});
	}

	CaughtPromise safeOpenCloseAssumingMainThread(OpenClose open) {
		return val::take_ownership(usbi_em_device_safe_open_close(
			device.as_handle(), static_cast<bool>(open)));
	}

	int safeOpenCloseOnMain(OpenClose open) {
		return ::awaitOnMain([this, open] {
				   return safeOpenCloseAssumingMainThread(open);
			   })
			.error;
	}

private:

	val device;
	std::vector<std::unique_ptr<usbi_configuration_descriptor>> configurations;

	CaughtPromise requestDescriptor(libusb_descriptor_type desc_type,
									uint8_t desc_index,
									uint16_t max_length) const {
		libusb_control_setup setup = {
			.bmRequestType = LIBUSB_ENDPOINT_IN,
			.bRequest = LIBUSB_REQUEST_GET_DESCRIPTOR,
			.wValue = (uint16_t)((desc_type << 8) | desc_index),
			.wIndex = 0,
			.wLength = max_length,
		};
		return makeControlTransferPromise(device, &setup);
	}

	// Implementation of the `CachedDevice::initFromDevice` above. This is a
	// separate function just because we need to close the device on exit if
	// we opened it successfully, and we can't use an async operation (`close`)
	// in RAII destructor.
	val initFromDeviceWithoutClosing(libusb_device* dev, bool& must_close) {
		co_await_try(safeOpenCloseAssumingMainThread(OpenClose::Open));

		// Can't use RAII to close on exit as co_await is not permitted in
		// destructors (yet:
		// https://github.com/cplusplus/papers/issues/445), so use a good
		// old boolean + a wrapper instead.
		must_close = true;

		{
			auto result = co_await_try(
				requestDescriptor(LIBUSB_DT_DEVICE, 0, LIBUSB_DT_DEVICE_SIZE));
			if (auto error = getTransferStatus(result)) {
				co_return error;
			}
			copyFromDataView(&dev->device_descriptor, result["data"]);
		}

		// Infer the device speed (which is not yet provided by WebUSB) from
		// the descriptor.
		if (dev->device_descriptor.bMaxPacketSize0 ==
			/* actually means 2^9, only valid for superspeeds */ 9) {
			dev->speed = dev->device_descriptor.bcdUSB >= 0x0310
				? LIBUSB_SPEED_SUPER_PLUS
				: LIBUSB_SPEED_SUPER;
		} else if (dev->device_descriptor.bcdUSB >= 0x0200) {
			dev->speed = LIBUSB_SPEED_HIGH;
		} else if (dev->device_descriptor.bMaxPacketSize0 > 8) {
			dev->speed = LIBUSB_SPEED_FULL;
		} else {
			dev->speed = LIBUSB_SPEED_LOW;
		}

		if (auto error = usbi_sanitize_device(dev)) {
			co_return error;
		}

		auto configurations_len = dev->device_descriptor.bNumConfigurations;
		configurations.reserve(configurations_len);
		for (uint8_t j = 0; j < configurations_len; j++) {
			// Note: requesting more than (platform-specific limit) bytes
			// here will cause the transfer to fail, see
			// https://crbug.com/1489414. Use the most common limit of 4096
			// bytes for now.
			constexpr uint16_t MAX_CTRL_BUFFER_LENGTH = 4096;
			auto result = co_await_try(
				requestDescriptor(LIBUSB_DT_CONFIG, j, MAX_CTRL_BUFFER_LENGTH));
			if (auto error = getTransferStatus(result)) {
				co_return error;
			}
			auto configVal = result["data"];
			auto configLen = configVal["byteLength"].as<size_t>();
			auto& config = configurations.emplace_back(
				(usbi_configuration_descriptor*)::operator new(configLen));
			copyFromDataView(config.get(), configVal);
		}

		co_return (int) LIBUSB_SUCCESS;
	}

	CachedDevice(val device) : device(std::move(device)) {}

	friend struct ValPtr<CachedDevice>;
};

unsigned long getDeviceSessionId(val& web_usb_device) {
	thread_local const val SessionIdSymbol =
		val::global("Symbol")(val("libusb.session_id"));

	val session_id_val = web_usb_device[SessionIdSymbol];
	if (!session_id_val.isUndefined()) {
		return session_id_val.as<unsigned long>();
	}

	// If the device doesn't have a session ID, it means we haven't seen
	// it before. Generate a new session ID for it. We can associate an
	// incrementing ID with the `USBDevice` object itself. It's
	// guaranteed to be alive and, thus, stable as long as the device is
	// connected, even between different libusb invocations. See
	// https://github.com/WICG/webusb/issues/241.

	static unsigned long next_session_id = 0;

	web_usb_device.set(SessionIdSymbol, next_session_id);
	return next_session_id++;
}

val getDeviceList(libusb_context* ctx, discovered_devs** devs) {
	// C++ equivalent of `await navigator.usb.getDevices()`. Note: at this point
	// we must already have some devices exposed - caller must have called
	// `await navigator.usb.requestDevice(...)` in response to user interaction
	// before going to LibUSB. Otherwise this list will be empty.
	auto web_usb_devices =
		co_await_try(val::global("navigator")["usb"].call<val>("getDevices"));
	for (auto&& web_usb_device : web_usb_devices) {
		auto session_id = getDeviceSessionId(web_usb_device);

		auto dev = usbi_get_device_by_session_id(ctx, session_id);
		if (dev == NULL) {
			dev = usbi_alloc_device(ctx, session_id);
			if (dev == NULL) {
				usbi_err(ctx, "failed to allocate a new device structure");
				continue;
			}

			auto statusVal = co_await CachedDevice::initFromDevice(
				std::move(web_usb_device), dev);
			if (auto error = statusVal.as<int>()) {
				usbi_err(ctx, "failed to read device information: %s",
						 libusb_error_name(error));
				libusb_unref_device(dev);
				continue;
			}

			// We don't have real buses in WebUSB, just pretend everything
			// is on bus 1.
			dev->bus_number = 1;
			// This can wrap around but it's the best approximation of a stable
			// device address and port number we can provide.
			dev->device_address = dev->port_number = (uint8_t)session_id;
		}
		*devs = discovered_devs_append(*devs, dev);
		libusb_unref_device(dev);
	}
	co_return (int) LIBUSB_SUCCESS;
}

int em_get_device_list(libusb_context* ctx, discovered_devs** devs) {
	// No need to wrap into CaughtPromise as we catch all individual ops in the
	// inner implementation and return just the error code. We do need a custom
	// promise type to ensure conversion to int happens on the main thread
	// though.
	struct IntPromise : val {
		IntPromise(val&& promise) : val(std::move(promise)) {}

		struct AwaitResult {
			int error;

			AwaitResult(val&& result) : error(result.as<int>()) {}
		};
	};

	return awaitOnMain(
			   [ctx, devs] { return IntPromise(getDeviceList(ctx, devs)); })
		.error;
}

int em_open(libusb_device_handle* handle) {
	return WebUsbDevicePtr(handle)->safeOpenCloseOnMain(OpenClose::Open);
}

void em_close(libusb_device_handle* handle) {
	// LibUSB API doesn't allow us to handle an error here, but we still need to
	// wait for the promise to make sure that subsequent attempt to reopen the
	// same device doesn't fail with a "device busy" error.
	if (auto error =
			WebUsbDevicePtr(handle)->safeOpenCloseOnMain(OpenClose::Close)) {
		usbi_err(handle->dev->ctx, "failed to close device: %s",
				 libusb_error_name(error));
	}
}

int em_get_active_config_descriptor(libusb_device* dev, void* buf, size_t len) {
	auto& cached_device = *WebUsbDevicePtr(dev);
	auto config_value = cached_device.getActiveConfigValue();
	if (auto config = cached_device.findConfigDescriptorByValue(config_value)) {
		return cached_device.copyConfigDescriptor(config, buf, len);
	} else {
		return LIBUSB_ERROR_NOT_FOUND;
	}
}

int em_get_config_descriptor(libusb_device* dev,
							 uint8_t config_id,
							 void* buf,
							 size_t len) {
	auto& cached_device = *WebUsbDevicePtr(dev);
	if (auto config = cached_device.getConfigDescriptor(config_id)) {
		return cached_device.copyConfigDescriptor(config, buf, len);
	} else {
		return LIBUSB_ERROR_NOT_FOUND;
	}
}

int em_get_configuration(libusb_device_handle* dev_handle,
						 uint8_t* config_value) {
	*config_value = WebUsbDevicePtr(dev_handle)->getActiveConfigValue();
	return LIBUSB_SUCCESS;
}

int em_get_config_descriptor_by_value(libusb_device* dev,
									  uint8_t config_value,
									  void** buf) {
	auto& cached_device = *WebUsbDevicePtr(dev);
	if (auto config = cached_device.findConfigDescriptorByValue(config_value)) {
		*buf = config;
		return config->wTotalLength;
	} else {
		return LIBUSB_ERROR_NOT_FOUND;
	}
}

int em_set_configuration(libusb_device_handle* dev_handle, int config) {
	return WebUsbDevicePtr(dev_handle)->awaitOnMain("setConfiguration", config);
}

int em_claim_interface(libusb_device_handle* handle, uint8_t iface) {
	return WebUsbDevicePtr(handle)->awaitOnMain("claimInterface", iface);
}

int em_release_interface(libusb_device_handle* handle, uint8_t iface) {
	return WebUsbDevicePtr(handle)->awaitOnMain("releaseInterface", iface);
}

int em_set_interface_altsetting(libusb_device_handle* handle,
								uint8_t iface,
								uint8_t altsetting) {
	return WebUsbDevicePtr(handle)->awaitOnMain("selectAlternateInterface",
												iface, altsetting);
}

int em_clear_halt(libusb_device_handle* handle, unsigned char endpoint) {
	std::string direction = endpoint & LIBUSB_ENDPOINT_IN ? "in" : "out";
	endpoint &= LIBUSB_ENDPOINT_ADDRESS_MASK;

	return WebUsbDevicePtr(handle)->awaitOnMain("clearHalt", direction,
												endpoint);
}

int em_reset_device(libusb_device_handle* handle) {
	return WebUsbDevicePtr(handle)->awaitOnMain("reset");
}

void em_destroy_device(libusb_device* dev) {
	WebUsbDevicePtr(dev).free();
}

int em_submit_transfer(usbi_transfer* itransfer) {
	return runOnMain([itransfer] {
		auto transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
		auto& web_usb_device = WebUsbDevicePtr(transfer->dev_handle)
								   ->getDeviceAssumingMainThread();
		val transfer_promise;
		switch (transfer->type) {
			case LIBUSB_TRANSFER_TYPE_CONTROL: {
				transfer_promise = makeControlTransferPromise(
					web_usb_device,
					libusb_control_transfer_get_setup(transfer));
				break;
			}
			case LIBUSB_TRANSFER_TYPE_BULK:
			case LIBUSB_TRANSFER_TYPE_INTERRUPT: {
				auto endpoint =
					transfer->endpoint & LIBUSB_ENDPOINT_ADDRESS_MASK;

				if (IS_XFERIN(transfer)) {
					transfer_promise = web_usb_device.call<val>(
						"transferIn", endpoint, transfer->length);
				} else {
					auto data = getUnsharedMemoryView(transfer->buffer,
													  transfer->length);
					transfer_promise =
						web_usb_device.call<val>("transferOut", endpoint, data);
				}

				break;
			}
			// TODO: add implementation for isochronous transfers too.
			default:
				return LIBUSB_ERROR_NOT_SUPPORTED;
		}
		// Not a coroutine because we don't want to block on this promise, just
		// schedule an asynchronous callback.
		promiseThen(CaughtPromise(std::move(transfer_promise)),
					[itransfer](auto&& result) {
						WebUsbTransferPtr(itransfer).emplace(std::move(result));
						usbi_signal_transfer_completion(itransfer);
					});
		return LIBUSB_SUCCESS;
	});
}

void em_clear_transfer_priv(usbi_transfer* itransfer) {
	WebUsbTransferPtr(itransfer).free();
}

int em_cancel_transfer(usbi_transfer* itransfer) {
	return LIBUSB_SUCCESS;
}

int em_handle_transfer_completion(usbi_transfer* itransfer) {
	libusb_transfer_status status = runOnMain([itransfer] {
		auto transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);

		// Take ownership of the transfer result, as `em_clear_transfer_priv` is
		// not called automatically for completed transfers and we must free it
		// to avoid leaks.

		auto result = WebUsbTransferPtr(itransfer).take();

		if (itransfer->state_flags & USBI_TRANSFER_CANCELLING) {
			return LIBUSB_TRANSFER_CANCELLED;
		}

		if (result.error) {
			return LIBUSB_TRANSFER_ERROR;
		}

		auto& value = result.value;

		void* dataDest;
		unsigned char endpointDir;

		if (transfer->type == LIBUSB_TRANSFER_TYPE_CONTROL) {
			dataDest = libusb_control_transfer_get_data(transfer);
			endpointDir =
				libusb_control_transfer_get_setup(transfer)->bmRequestType;
		} else {
			dataDest = transfer->buffer;
			endpointDir = transfer->endpoint;
		}

		if (endpointDir & LIBUSB_ENDPOINT_IN) {
			auto data = value["data"];
			if (!data.isNull()) {
				itransfer->transferred = data["byteLength"].as<int>();
				copyFromDataView(dataDest, data);
			}
		} else {
			itransfer->transferred = value["bytesWritten"].as<int>();
		}

		return getTransferStatus(value);
	});

	// Invoke user's handlers outside of the main thread to reduce pressure.
	return status == LIBUSB_TRANSFER_CANCELLED
		? usbi_handle_transfer_cancellation(itransfer)
		: usbi_handle_transfer_completion(itransfer, status);
}

}  // namespace

#pragma clang diagnostic ignored "-Wmissing-field-initializers"
extern "C" const usbi_os_backend usbi_backend = {
	.name = "Emscripten + WebUSB backend",
	.caps = 0,
	.get_device_list = em_get_device_list,
	.open = em_open,
	.close = em_close,
	.get_active_config_descriptor = em_get_active_config_descriptor,
	.get_config_descriptor = em_get_config_descriptor,
	.get_config_descriptor_by_value = em_get_config_descriptor_by_value,
	.get_configuration = em_get_configuration,
	.set_configuration = em_set_configuration,
	.claim_interface = em_claim_interface,
	.release_interface = em_release_interface,
	.set_interface_altsetting = em_set_interface_altsetting,
	.clear_halt = em_clear_halt,
	.reset_device = em_reset_device,
	.destroy_device = em_destroy_device,
	.submit_transfer = em_submit_transfer,
	.cancel_transfer = em_cancel_transfer,
	.clear_transfer_priv = em_clear_transfer_priv,
	.handle_transfer_completion = em_handle_transfer_completion,
	.device_priv_size = sizeof(CachedDevice),
	.transfer_priv_size = sizeof(PromiseResult),
};

#pragma clang diagnostic pop
