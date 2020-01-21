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
/* Disable: warning C6258: Using TerminateThread does not allow proper thread clean up */
#pragma warning(disable:6258)
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

/* Enable global message logging */
#define ENABLE_LOGGING 1

/* Uncomment to start with debug message logging enabled */
// #define ENABLE_DEBUG_LOGGING 1

/* Uncomment to enabling logging to system log */
// #define USE_SYSTEM_LOGGING_FACILITY

/* type of second poll() argument */
#define POLL_NFDS_TYPE unsigned int

/* Define to 1 if you have the <sys/types.h> header file.  */
#define HAVE_SYS_TYPES_H 1

/* Windows backend */
#define OS_WINDOWS 1
