package com.orng.maoer.utils;

import android.util.Log;

import com.jingle.hook.BuildConfig;

public class LogUtils {

    private static boolean enableLog =  BuildConfig.DEBUG;


    public static void D(String tag, String message) {
        if (enableLog) {
            Log.d(tag, message);
        }
    }

    public static void W(String tag, String message) {
        if (enableLog) {
            Log.w(tag, message);
        }
    }

    public static void I(String tag, String message) {
        if (enableLog) {
            Log.i(tag, message);
        }
    }

    public static void E(String tag, String message) {
        if (enableLog) {
            Log.e(tag, message);
        }
    }

    public static void E(String tag, Throwable message) {
        if (enableLog) {
            Log.e(tag, message != null ? message.toString() : " msg is null");
        }
    }

    public static void E(String tag, String msg, Throwable throwable) {
        if (enableLog) {
            Log.e(tag, msg, throwable);
        }
    }
}
