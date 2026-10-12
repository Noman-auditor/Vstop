package com.nora.tunnel.core

import android.content.Context
import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.ParcelFileDescriptor
import com.nora.tunnel.data.Profile
import org.json.JSONObject
import java.io.File

/**
 * OpenVPN (UDP/TCP). Runs an openvpn binary as jniLibs/<abi>/libopenvpn.so and talks to it over its management
 * interface, the same way ics-openvpn does. The binary MUST be the ics-openvpn build (stock openvpn cannot ask an
 * app for a TUN fd). Flow: openvpn connects to our unix socket -> we send credentials -> when it asks to open the
 * tun (OPENTUN) we create it with VpnService.Builder and pass the fd over the socket (SCM_RIGHTS).
 * UNTESTED: written from the ics-openvpn management protocol; expect to adjust against your binary.
 *
 * Profile: extra = {config: full .ovpn text, user, pass}.
 */
/** (ip, prefix, mtu, routes[(net,prefix)], dns[]) -> tun fd. Provided by the service. */
typealias TunFactory = (String, Int, Int, List<Pair<String, Int>>, List<String>) -> ParcelFileDescriptor?

object OpenVpnEngine {
    @Volatile var rx = 0L
    @Volatile var tx = 0L
    @Volatile var connected = false
    @Volatile var lastError: String? = null
    private var proc: Process? = null
    private var server: LocalServerSocket? = null
    private var tun: ParcelFileDescriptor? = null

    fun isAvailable(ctx: Context) = File(ctx.applicationInfo.nativeLibraryDir, "libopenvpn.so").exists()

    fun start(ctx: Context, p: Profile, factory: TunFactory) {
        val bin = File(ctx.applicationInfo.nativeLibraryDir, "libopenvpn.so")
        if (!bin.exists()) throw IllegalStateException("libopenvpn.so not found (see NATIVE.md)")
        val x = JSONObject(p.extra.ifBlank { "{}" })
        rx = 0; tx = 0; connected = false; lastError = null

        val conf = File(ctx.filesDir, "ovpn.conf")
        // drop directives the app controls itself
        val body = x.optString("config").lines().filterNot { l ->
            val t = l.trim().lowercase()
            t.startsWith("dev ") || t.startsWith("dev-type") || t.startsWith("management") ||
                t.startsWith("daemon") || t.startsWith("script-security") || t.startsWith("up ") || t.startsWith("down ")
        }.joinToString("\n")
        conf.writeText(body + "\nmanagement-client\nmanagement-query-passwords\nmanagement-hold\nmanagement-signal\n")

        // The app listens on a filesystem unix socket; openvpn connects to it (management-client).
        val path = File(ctx.cacheDir, "ovpn_mgmt").absolutePath
        File(path).delete()
        val ls = LocalSocket()
        ls.bind(LocalSocketAddress(path, LocalSocketAddress.Namespace.FILESYSTEM))
        val srv = LocalServerSocket(ls.fileDescriptor)
        server = srv
        val pb = ProcessBuilder(bin.absolutePath, "--config", conf.absolutePath, "--management", path, "unix")
            .redirectErrorStream(true)
        val pr = pb.start()
        proc = pr
        Thread { try { pr.inputStream.bufferedReader().forEachLine { AppLog.add("OVPN", it) } } catch (_: Exception) {} }.start()

        val sock = srv.accept()
        Thread { manage(sock, x, factory) }.start()

        val end = System.currentTimeMillis() + 45_000
        while (System.currentTimeMillis() < end) {
            if (connected) return
            lastError?.let { stop(); throw IllegalStateException(it) }
            if (!pr.isAlive) throw IllegalStateException("openvpn exited (code ${pr.exitValue()})")
            Thread.sleep(300)
        }
        stop()
        throw IllegalStateException("OpenVPN connect timed out")
    }

    private fun manage(s: LocalSocket, x: JSONObject, factory: TunFactory) {
        val out = s.outputStream
        fun send(line: String) { out.write((line + "\n").toByteArray()); out.flush() }
        var ifIp = ""; var prefix = 32; var mtu = 1500
        val routes = mutableListOf<Pair<String, Int>>(); val dns = mutableListOf<String>()
        try {
            send("bytecount 2"); send("state on"); send("hold release")
            s.inputStream.bufferedReader().forEachLine { line ->
                when {
                    line.startsWith(">PASSWORD:Need 'Auth'") -> {
                        send("username \"Auth\" ${x.optString("user")}"); send("password \"Auth\" ${x.optString("pass")}")
                    }
                    line.startsWith(">PASSWORD:Verification Failed") -> lastError = "OpenVPN authentication failed"
                    line.startsWith(">BYTECOUNT:") -> line.substringAfter(':').split(',').let {
                        if (it.size == 2) { rx = it[0].toLongOrNull() ?: rx; tx = it[1].toLongOrNull() ?: tx }
                    }
                    line.startsWith(">STATE:") -> {
                        val st = line.substringAfter(':').split(',').getOrNull(1)
                        if (st == "CONNECTED") connected = true
                        if (st == "EXITING") connected = false
                    }
                    line.startsWith(">NEED-OK:Need '") -> {
                        val needed = line.substringAfter("Need '").substringBefore("'")
                        val extra = line.substringAfter("':", "").substringBefore(" MSG:").trim()
                        val parts = extra.split(" ")
                        when (needed) {
                            "IFCONFIG" -> { ifIp = parts[0]; prefix = maskToPrefix(parts.getOrElse(1) { "255.255.255.255" }); mtu = parts.getOrNull(2)?.toIntOrNull() ?: 1500 }
                            "ROUTE" -> routes += parts[0] to maskToPrefix(parts.getOrElse(1) { "255.255.255.255" })
                            "DNSSERVER" -> dns += parts[0]
                            "OPENTUN" -> {
                                val fd = factory(ifIp, prefix, mtu, routes, dns)
                                if (fd == null) { lastError = "VPN permission was revoked"; send("needok 'OPENTUN' cancel") }
                                else {
                                    tun = fd
                                    s.setFileDescriptorsForSend(arrayOf(fd.fileDescriptor))
                                    out.write(0); out.flush()
                                    send("needok 'OPENTUN' ok")
                                }
                                return@forEachLine
                            }
                        }
                        send("needok '$needed' ok")
                    }
                }
            }
        } catch (e: Exception) { if (!connected) lastError = e.message ?: "management error" }
    }

    private fun maskToPrefix(mask: String): Int =
        mask.split('.').sumOf { Integer.bitCount(it.toIntOrNull() ?: 0) }

    fun stop() {
        connected = false
        try { proc?.destroy() } catch (_: Exception) {}
        try { server?.close() } catch (_: Exception) {}
        try { tun?.close() } catch (_: Exception) {}
        proc = null; server = null; tun = null
    }
}
