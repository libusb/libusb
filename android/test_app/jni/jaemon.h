/*
 * jaemon.h - C-side Jaeman definitions
 *
 * Jaemon is a library that allows to load and run what used to be an executable
 * within the Java process.
 *
 * Motivations.
 *
 * With release of Android 5.0 security measures where significantly increased.
 * A process, started by an Android app does not inherit all app's permissions,
 * file descriptors, etc. Therefore a process that could run normally on
 * Android 4.0 may fail due to insufficient permissions.
 * Such executable can be rebuilt as a shared library and run by Jaemon.
 * The original code needs no modifications. Only the build has to be altered,
 * as the following:
 *  1. this file has to be included with --include jaemon.h to intercept
 *     exit, abort and fork calls
 *  2. linker should be instructed to produce shared library
 *  3. Sources should be compiled with -fPIC and linked with -fPIE flags
 *
 * Copyright  ©  2016 Eugene Hutorny <eugene@hutorny.in.ua>
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

#ifndef JAEMON_H_
#define JAEMON_H_


#define fork jaemon_fork
#define abort jaemon_abort
#define exit jaemon_exit

extern int jaemon_fork();
extern void jaemon_abort() __attribute__ ((__noreturn__));
extern void jaemon_exit(int) __attribute__ ((__noreturn__));
void dbg(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));

#endif /* JAEMON_H_ */
