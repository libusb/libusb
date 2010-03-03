/* config.h.  Manual config for MSVC.  */

#ifndef _MSC_VER
#warn "msvc/config.h shouldn't be included for your development environment."
#error "Please make sure the msvc/ directory is removed from your build path."
#endif

/* Default visibility */
#define API_EXPORTED /**/

/* Debug message logging */
#define ENABLE_DEBUG_LOGGING 1

/* Message logging */
#define ENABLE_LOGGING 1

/* Windows backend */
#define OS_WINDOWS /**/

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Backend handles timeout */
/* #undef USBI_OS_HANDLES_TIMEOUT */

/* timerfd headers available */
/* #undef USBI_TIMERFD_AVAILABLE */
