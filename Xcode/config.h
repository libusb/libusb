/* config.h.  Manually generated for Xcode.  */

/* On 10.12 and later, use newly available clock_*() functions */
#include <AvailabilityMacros.h>
#if MAC_OS_X_VERSION_MIN_REQUIRED >= 101200
/* Define to 1 if you have the `clock_gettime' function. */
#define HAVE_CLOCK_GETTIME 1
#endif

/* Default visibility */
#define DEFAULT_VISIBILITY /**/

/* Message logging */
#define ENABLE_LOGGING 1

/* Define to 1 if the system has the type `nfds_t'. */
#define HAVE_NFDS_T 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Darwin backend */
#define OS_DARWIN 1

/* Use POSIX poll() implementation */
#define POLL_POSIX 1

/* Use POSIX Threads */
#define THREADS_POSIX 1

/* Use GNU extensions */
#define _GNU_SOURCE 1
