/* config.h.  Manual config for MSVC.  */

#ifndef _MSC_VER
#warn "msvc/config.h shouldn't be included for your development environment."
#error "Please make sure the msvc/ directory is removed from your build path."
#endif

/* Disable: warning C4200: nonstandard extension used : zero-sized array in struct/union */
#pragma warning(disable:4200)
#if defined(_PREFAST_)
/* Disable "Banned API" errors when using the MS's WDK OACR/Prefast */
#pragma warning(disable:28719)
/* Disable "The function 'InitializeCriticalSection' must be called from within a try/except block" */
#pragma warning(disable:28125)
#endif

/* Default visibility */
#define DEFAULT_VISIBILITY /**/

/* Start with debug message logging enabled */
//#define ENABLE_DEBUG_LOGGING 1

/* Message logging */
#define ENABLE_LOGGING 1

/* Windows backend */
#define OS_WINDOWS 1

/* type of second poll() argument */
#define POLL_NFDS_TYPE unsigned int
