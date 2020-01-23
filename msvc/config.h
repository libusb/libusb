/* config.h.  Manual config for MSVC.  */

#ifndef _MSC_VER
#warn "msvc/config.h shouldn't be included for your development environment."
#error "Please make sure the msvc/ directory is removed from your build path."
#endif

/* Visual Studio 2013 or later is required */
#if (_MSC_VER < 1800)
#error "Visual Studio 2013 or later is required."
#endif

/* Visual Studio 2015 and later defines timespec */
#if (_MSC_VER >= 1900)
#define _TIMESPEC_DEFINED 1
#endif

/* Disable: warning C4200: nonstandard extension used : zero-sized array in struct/union */
#pragma warning(disable:4200)
/* Disable: warning C4324: structure was padded due to __declspec(align()) */
#pragma warning(disable:4324)
/* Disable: warning C4996: 'GetVersionA': was declared deprecated */
#pragma warning(disable:4996)

#if defined(_PREFAST_)
/* Disable "Banned API" errors when using the MS's WDK OACR/Prefast */
#pragma warning(disable:28719)
/* Disable "The function 'InitializeCriticalSection' must be called from within a try/except block" */
#pragma warning(disable:28125)
#endif

/* Default visibility */
#define DEFAULT_VISIBILITY /**/

/* Uncomment to start with debug message logging enabled */
// #define ENABLE_DEBUG_LOGGING 1

/* Message logging */
#define ENABLE_LOGGING 1

/* Windows backend */
#define OS_WINDOWS 1

/* Use Windows poll() implementation */
#define POLL_WINDOWS 1

/* Use Windows Threads */
#define THREADS_WINDOWS 1

/* Uncomment to enabling output to system log */
// #define USE_SYSTEM_LOGGING_FACILITY
