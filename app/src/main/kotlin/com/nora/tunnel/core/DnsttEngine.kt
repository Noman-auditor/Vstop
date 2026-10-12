package com.nora.tunnel.core

import android.content.Context
import com.nora.tunnel.data.Profile
import org.json.JSONObject
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

/**
 * LowDNS / DNSTT. Runs the dnstt-client binary (Go, from www.bamsoftware.com/software/dnstt) shipped as
 * jniLibs/<abi>/libdnstt.so, so Android extracts it to nativeLibraryDir where it can be executed.
 * dnstt only forwards ONE local TCP port to the far end, which is normally an SSH server. So a DNSTT profile is
 * "SSH over DNS tunnel": this engine opens 127.0.0.1:[LOCAL_PORT], then SshEngine logs in through it.
 *
 * Profile: address/port = resolver (UDP 53 / DoT 853 / DoH 443), secret = ssh "user:pass",
 * extra = {domain, pubkey (hex), mode: udp|dot|doh, resolver: "host:port" or DoH URL}.
 */
object DnsttEngine {
    const val LOCAL_PORT = 7000
    private var proc: Process? = null

    fun isAvailable(ctx: Context) = File(ctx.applicationInfo.nativeLibraryDir, "libdnstt.so").exists()

    fun start(ctx: Context, p: Profile) {
        val bin = File(ctx.applicationInfo.nativeLibraryDir, "libdnstt.so")
        if (!bin.exists()) throw IllegalStateException("libdnstt.so not found (see NATIVE.md)")
        val x = JSONObject(p.extra.ifBlank { "{}" })
        val domain = x.optString("domain").ifBlank { throw IllegalStateException("DNSTT profile has no domain") }
        val pubkey = x.optString("pubkey").ifBlank { throw IllegalStateException("DNSTT profile has no pubkey") }
        val resolver = x.optString("resolver").ifBlank { "${p.address}:${p.port}" }
        val flag = when (x.optString("mode", "udp")) { "doh" -> "-doh"; "dot" -> "-dot"; else -> "-udp" }

        val pb = ProcessBuilder(bin.absolutePath, flag, resolver, "-pubkey", pubkey, domain, "127.0.0.1:$LOCAL_PORT")
            .redirectErrorStream(true)
        val pr = pb.start()
        proc = pr
        Thread { try { pr.inputStream.bufferedReader().forEachLine { AppLog.add("DNSTT", it) } } catch (_: Exception) {} }.start()

        // wait for the local listener
        val end = System.currentTimeMillis() + 10_000
        while (System.currentTimeMillis() < end) {
            if (!pr.isAlive) throw IllegalStateException("dnstt-client exited (code ${pr.exitValue()})")
            try { Socket().use { it.connect(InetSocketAddress("127.0.0.1", LOCAL_PORT), 300) }; return }
            catch (_: Exception) { Thread.sleep(250) }
        }
        stop()
        throw IllegalStateException("dnstt-client did not open port $LOCAL_PORT")
    }

    fun stop() { try { proc?.destroy() } catch (_: Exception) {}; proc = null }
}
