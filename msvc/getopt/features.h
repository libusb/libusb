/* Minimal features.h shim for standalone getopt build on MSVC. */
#ifndef _FEATURES_H
#define _FEATURES_H 1

#ifdef __cplusplus
# define __BEGIN_DECLS extern "C" {
# define __END_DECLS }
#else
# define __BEGIN_DECLS
# define __END_DECLS
#endif

#ifndef __THROW
# define __THROW
#endif

#ifndef __nonnull
# define __nonnull(params)
#endif

#endif /* _FEATURES_H */
