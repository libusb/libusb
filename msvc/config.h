/* config.h.  Manual config for MSVC.  */

#ifndef _MSC_VER
#warn "msvc/config.h shouldn't be included for your development environment."
#error "Please make sure the msvc/ directory is removed from your build path."
#endif

/* Default visibility */
#define DEFAULT_VISIBILITY /**/

/* Debug message logging (forced) */
//#define ENABLE_DEBUG_LOGGING 1

/* Debug message logging (toggable) */
#define INCLUDE_DEBUG_LOGGING 1

/* Message logging */
#define ENABLE_LOGGING 1

/* Windows backend */
#define OS_WINDOWS /**/

/* type of second poll() argument */
#define POLL_NFDS_TYPE unsigned int
