/*
 * Copyright © 2016 Eugene Hutorny <eugene@hutorny.in.ua>
 *
 * Jaemon.java - loads shared libraries and executes their main method
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
 * Copyright  © 2016 Eugene Hutorny <eugene@hutorny.in.ua>
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

package info.libusb.test_app;

import android.text.TextUtils;
import java.util.*;

class Jaemon implements Runnable {
    static {
        System.loadLibrary("jaemon");
    }

    public Jaemon(List<String> argv, String log) {
        this(argv, null, log);
    }
    public Jaemon(List<String> argv, Map<String, String> env, String log) {
        this.log = log == null ? "\0" : log + "\0";
        this.argv = argv;
        this.env = env;
    }


    @Override
    public void run() {
        final int argc = argv.size();
        final String argv = TextUtils.join("\0", this.argv) + "\0\0";
        final String env = join("\0", "=", this.env) + "\0\0";
        result = exec(argc, argv.getBytes(), env.getBytes(), log.getBytes());
    }

    public int getResult() {
        return result;
    }

    private static String join(String listSeparator, String keyDelimiter, Map<String,String> map) {
        if( map == null ) return "";
        StringBuilder string = new StringBuilder();
        for (String key : map.keySet()) {
            String value = map.get(key);
            if( value == null ) value = "";
            string.append(key);
            string.append(keyDelimiter);
            string.append(value);
            string.append(listSeparator);
        }
        return string.toString();
    }

    private native static int exec(int argc, byte[] argv, byte[] env, byte[] log);
    private final Map<String, String> env;
    private final List<String> argv;
    private final String log;
    private int result;
}
