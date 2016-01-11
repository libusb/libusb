/*
 * Main.java - main activity for libusb test app
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

package info.libusb.test_app;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbManager;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.widget.TextView;

import java.io.*;
import java.util.*;

public class Main extends Activity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        usbManager = (UsbManager) getSystemService(Context.USB_SERVICE);
        lib = getApplicationInfo().dataDir + "/lib/";
        textLog = (TextView) findViewById(R.id.textLog);
        setupLogging(savedInstanceState != null);
        if( savedInstanceState == null )
            textLog.post(permissionRequester);
        else
        new Thread(logUpdater).start();
    }

    private void setupLogging(boolean append) {
        try {
            testLog = getApplicationContext().getFilesDir().getAbsolutePath() + "/tmp.log";
            new FileOutputStream(testLog, append);
            new File(testLog).deleteOnExit();
            pump = new Pump(testLog);
            pump.start();
        } catch (Exception e) {
            textLog.setText(e.getMessage());
            Log.e("",e.getMessage());
        }
    }

    @Override
    protected void onDestroy() {
        if( pump != null ) pump.stop();
        super.onDestroy();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        super.onCreateOptionsMenu(menu);
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.main, menu);
        menuEnableDebug = menu.findItem(R.id.menu_enable_debug);
        if( menuEnableDebug != null ) menuEnableDebug.setChecked(debug);
        return true;
    }

    @Override
    protected void onRestoreInstanceState(Bundle savedInstanceState) {
        super.onRestoreInstanceState(savedInstanceState);
        debug = savedInstanceState.getBoolean("DEBUG");
        if( menuEnableDebug != null ) menuEnableDebug.setChecked(debug);
        HashMap<String, UsbDevice> list = (HashMap<String, UsbDevice>) savedInstanceState.getSerializable("LIST");
        deviceList.putAll(list);
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putBoolean("DEBUG", debug);
        outState.putSerializable("LIST", deviceList);
    }

    @Override
    protected void onPause() {
        unregisterReceiver(usbReceiver);
        super.onPause();
    }
    @Override
    protected void onResume() {
        super.onResume();
        IntentFilter filter = new IntentFilter(ACTION_USB_PERMISSION);
        filter.addAction(UsbManager.ACTION_USB_DEVICE_DETACHED);
        registerReceiver(usbReceiver, filter);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        if (UsbManager.ACTION_USB_DEVICE_ATTACHED.equals(intent.getAction())) {
            UsbDevice device = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
            if( device != null ) {
                print(formatDevice("+ %1$04x:%2$04x %3$s", device));
                deviceList.put(device.getDeviceName(), device);
            } else {
                print("- ?:?");
            }
        }
    }

    private void requestPermissions() {
        HashMap<String, UsbDevice> devices = usbManager.getDeviceList();
        for(UsbDevice device : devices.values()) {
            PendingIntent intent = PendingIntent.getBroadcast(this, 0, new Intent(ACTION_USB_PERMISSION), 0);
            if( usbManager.hasPermission(device) ) {
                print(formatDevice("+ %1$04x:%2$04x %3$s", device));
                deviceList.put(device.getDeviceName(), device);
            }
            else
                usbManager.requestPermission(device, intent);
        }
    }

    public void onClickMenuDebug(final MenuItem item) {
        item.setChecked(debug = ! item.isChecked());
    }

    public void onClickMenuClear(final MenuItem item) {
        if( pump != null ) {
            pump.stop();
            pump = null;
        }
        truncate();
        synchronized (log) { log.setLength(0); }
        textLog.setText("");
        try {
            pump = new Pump(testLog);
            pump.start();
        } catch (IOException e) {
            Log.e("",e.getMessage());
        }
        refreshLog();
    }

     public void onClickMenuTest(final MenuItem item) {
        if( ! item.isEnabled() ) return;
        item.setEnabled(false);
        Thread test = new Thread(new Runnable() {@Override public void run() {
            test();
            textLog.post(new Runnable() {@Override public void run() {
                item.setEnabled(true);
            }});
        }});
        test.start();
    }
    private static final List<List<String>> busTests = Arrays.asList(
            Arrays.asList("liblistdevs.so"), Arrays.asList("libstress.so")
    );
    private static final List<List<String>> devTests = Arrays.asList(Arrays.asList("libxusb.so", "-i", "%1$04x:%2$04x"));

    private void test() {
        for(String id : deviceList.keySet()) {
            UsbDevice device = deviceList.get(id);
            testDev(device);
        }
        testBus();
    }

    static private String formatDevice(String fmt, UsbDevice device) {
        return String.format(fmt, device.getVendorId(), device.getProductId(), device.getProductName());
    }

    private void testDev(UsbDevice device) {
        UsbDeviceConnection connection = usbManager.openDevice(device);
        device.getDeviceName();
        connection.getFileDescriptor();
        for(List<String> test : devTests) {
            List<String> exe = new ArrayList<>(test);
            for(int i = 1; i < exe.size(); ++i)
                exe.set(i, formatDevice(exe.get(i), device));
            print("\n> " + TextUtils.join(" ", exe));
            Jaemon tst = new Jaemon(exe, getEnv(), testLog);
            tst.run();
            print("  exit :" + tst.getResult() + "\n");
        }
    }

    private Map<String,String> getEnv() {
        HashMap<String,String> env = new HashMap<>();
        env.put("LIBUSB_DEBUG", debug ? "4" : "0");
        return env;
    }

    private void testBus() {
        for(List<String> exe : busTests) {
            print("\n> " + TextUtils.join(" ", exe));
            Jaemon tst = new Jaemon(exe, getEnv(), testLog);
            tst.run();
            print("  exit :" + tst.getResult() + "\n");
        }
    }

    private void truncate() {
        try {
            new FileOutputStream(testLog).getChannel().truncate(0);
        } catch (Exception ignored) { }
    }

    private class Pump implements Runnable {
        final BufferedReader reader;
        boolean terminated = false;

        private Pump(String path) throws IOException {
            reader = new BufferedReader(new InputStreamReader(new FileInputStream(path)));
        }
        private void stop() {
            if( terminated ) return;
            terminated = true;
            try {
                reader.close();
                synchronized (reader) { reader.notify(); }
            } catch (IOException e) {
                Log.w("PUMP", e.getMessage());
            }
        }

        @Override
        public void run() {
            while( ! terminated ) {
                try {
                    boolean done = false;
                    while ( reader.ready() ) {
                        int chr = reader.read();
                        if( chr < 0 ) {
                            terminated = true;
                            break;
                        } else {
                            synchronized (log) {
                                log.append((char) chr);
                            }
                            done = true;
                        }
                    }
                    if( done ) refreshLog();
                    synchronized (reader) { reader.wait(100); }
                } catch (IOException ignored) {
                } catch (InterruptedException e) {
                    terminated = true;
                }
            }
        }
        void start() {
            new Thread(this).start();
        }
    }

    private void refreshLog() {
        if( textLog.length() == log.length() ) return;
        if( getMainLooper().getThread() != Thread.currentThread() ) {
            textLog.post(refresher);
            return;
        }
        textLog.setText(log);
        textLog.postInvalidate();
        textLog.post(scroller);
    }

    private void print(String s) {
        try {
            FileWriter out = new FileWriter(new File(testLog), true);
            out.write(s);
            out.write('\n');
            out.close();
        } catch (Exception ignored) { }
    }

    private final BroadcastReceiver usbReceiver = new BroadcastReceiver() {
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if( ACTION_USB_PERMISSION.equals(action) ) {
                synchronized (this) {
                    final UsbDevice device = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
                    if (intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)) {
                        if(device != null){
                            print(formatDevice("= %1$04x:%2$04x %3$s", device));
                            deviceList.put(device.getDeviceName(), device);
                        }
                    } else {
                        print(formatDevice("Permission denied for %1$04x:%2$04x %3$s",device));
                    }
                }
            } else  if (UsbManager.ACTION_USB_DEVICE_DETACHED.equals(action)) {
                UsbDevice device = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
                if( device != null ) {
                    print(formatDevice("- %1$04x:%2$04x %3$s", device));
                    deviceList.remove(device.getDeviceName());
                }
            }
        }
    };

    private final Runnable refresher = new Runnable() {
        @Override
        public void run() {
            refreshLog();
        }
    };

    private final Runnable logUpdater = new Runnable() {
        @Override
        public void run() {
            try {
                while( ! Thread.currentThread().isInterrupted() ) {
                    Thread.sleep(100);
                    textLog.post(refresher);
                }
            } catch (InterruptedException ignored) {}
        }
    };

    private final Runnable permissionRequester = new Runnable() {
        @Override
        public void run() {
            requestPermissions();
        }
    };

    private final Runnable scroller = new Runnable() {
        @Override
        public void run() {
            final int scrollAmount = textLog.getLayout().getLineTop(textLog.getLineCount()) - textLog.getHeight();
            // if there is no need to scroll, scrollAmount will be <=0
            if (scrollAmount > 0)
                textLog.scrollTo(0, scrollAmount);
        }
    };

    private static final String ACTION_USB_PERMISSION = "info.libusb.test_app.USB_PERMISSION";
    private String testLog;
    private Pump pump;
    private TextView textLog;
    private final StringBuilder log = new StringBuilder();
    private final HashMap<String, UsbDevice> deviceList = new HashMap<>();
    private UsbManager usbManager;
    private String lib;
    private boolean debug;
    private MenuItem menuEnableDebug;
}
