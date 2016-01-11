/*
 * jaemon.c - JNI part of Jaemon class
 *
 * Copyright © 2016 Eugene Hutorny <eugene@hutorny.in.ua>
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

#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <dlfcn.h>
#include <jni.h>
#include <string.h>
#include <errno.h>
#include <android/log.h>
#include <unistd.h>
#include <fcntl.h>
#include "jaemon.h"
#include "info_libusb_test_app_Jaemon.h"

extern char **environ;

typedef int (*main_t)(int, char**, char**);

struct jaemon {
	int argc;
	char** argv;
	char** env;
	char*  log;
	main_t main;
};

static jmp_buf saved;
static int result = 0;

int jaemon_fork() {
	return 0;
}

void jaemon_exit(int res) {
	result = res;
	longjmp(saved,1);
}

void jaemon_abort() {
	longjmp(saved,2);
}

static int jaemon_run(const struct jaemon* zis) {
	switch( setjmp(saved) ) {
	case 0:	return zis->main(zis->argc, zis->argv, environ);
	case 1:	return result;
	case 2:	return 201;
	}
	return result;
}

static void jaemon_putenv(struct jaemon* zis) {
	char ** env = zis->env;
	while( *env ) {
		putenv(*env);
		++env;
	}
}

static int jaemon_exec(struct jaemon* zis) {
	dbg("> %s (%d,[%s])\n", zis->argv[0], zis->argc, zis->argv[1]);
	void * so = dlopen(zis->argv[0], RTLD_NOW);
	if( ! so ) {
		dbg("dlopen failed '%s':%s\n", zis->argv[0], dlerror());
		return 202;
	}
	zis->main = (main_t) dlsym(so,"main");
	if( ! zis->main ) {
		dbg("Unable to locate main\n");
		return 203;
	}
	if( zis->env )
		jaemon_putenv(zis);
	int oldErr = -1, oldOut = -1;
	if( zis->log && *zis->log ) {
		FILE * out = freopen(zis->log, "a", stdout);
		if( out == NULL ) {
			dbg("Error %d redirecting to '%s': %s",
					errno, zis->log, strerror(errno));
		} else {
			fsync(2);
			fsync(1);
			oldErr=dup(2);
			oldOut=dup(1);
			dup2(fileno(out), 2);
			dup2(fileno(out), 1);
		}
	}

	int result = jaemon_run(zis);
	fflush(stdout);
	fflush(stderr);
	if( oldErr > 0 ) dup2(oldErr, 2);
	if( oldOut > 0 ) dup2(oldOut, 1);

	dlclose(so);
	return result;
}

void dbg(const char *fmt, ...)  {
	va_list args;
	va_start(args, fmt);
	__android_log_vprint(ANDROID_LOG_DEBUG,"Jaemon", fmt, args);
	va_end(args);
}

static char** unjoin(char* arr, int n) {
	if( n == 0 ) {
		char* curr = arr;
		while( *curr ) {
			++n;
			curr += strlen(curr) + 1;
		}
	}
	char** res = calloc(n+1,sizeof(char*));
	res[n] = NULL;
	for(int i = 0; i < n; ++i ) {
		res[i] = arr;
		arr += strlen(arr) + 1;
	}
	return res;
}

JNIEXPORT jint JNICALL Java_info_libusb_test_1app_Jaemon_exec(JNIEnv * jni,
	jclass clas, jint argc, jbyteArray argv, jbyteArray env, jbyteArray log) {
	struct jaemon call;
	jbyte * jenv	= (*jni)->GetByteArrayElements(jni, env,  0);
	jbyte * jargv	= (*jni)->GetByteArrayElements(jni, argv, 0);
	jbyte * jlog	= (*jni)->GetByteArrayElements(jni, log,  0);
	call.argc 		= argc;
	call.argv 		= unjoin((char*)jargv, argc);
	call.env  		= unjoin((char*)jenv, 0);
	call.log		= (char*) jlog;

	jint res 		= jaemon_exec(&call);

	(*jni)->ReleaseByteArrayElements(jni, log,  jlog,  JNI_ABORT);
	(*jni)->ReleaseByteArrayElements(jni, argv, jargv, JNI_ABORT);
	(*jni)->ReleaseByteArrayElements(jni, env,  jenv,  JNI_ABORT);
	return res;
}

