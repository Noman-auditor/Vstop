package com.nora.tunnel.core

import android.content.Context
import android.os.Build
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter

/** Saves any uncaught crash to crash.txt so the next launch can show it instead of the app silently closing. */
object CrashReporter {
    private fun file(ctx: Context) = File(ctx.filesDir, "crash.txt")

    fun install(ctx: Context) {
        val app = ctx.applicationContext
        val prev = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { t, e ->
            try {
                val sw = StringWriter(); e.printStackTrace(PrintWriter(sw))
                file(app).writeText(
                    "Nora Tunnel crash\nthread=${t.name}\nandroid=${Build.VERSION.SDK_INT} device=${Build.MODEL} abi=${Build.SUPPORTED_ABIS.joinToString()}\n\n$sw"
                )
            } catch (_: Throwable) {}
            prev?.uncaughtException(t, e)
        }
    }

    fun pending(ctx: Context): String? = file(ctx).takeIf { it.exists() }?.readText()
    fun clear(ctx: Context) { file(ctx).delete() }
}
