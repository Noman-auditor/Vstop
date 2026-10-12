package com.nora.tunnel.core

import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Proxy
import com.jcraft.jsch.Session
import com.jcraft.jsch.SocketFactory
import com.nora.tunnel.data.Profile
import org.json.JSONObject
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * SSH tunnel engine: SSH direct, SSH + HTTP payload, SSH over TLS (SNI).
 * It exposes a local SOCKS5 (TCP CONNECT) on 127.0.0.1:[XrayConfig.SOCKS_PORT], the same port
 * hev-socks5-tunnel already feeds, and each connection becomes an SSH direct-tcpip channel.
 * UDP is not carried over SSH, so DNS must go over TCP (the app's DNS server setting is used by the OS).
 */
object SshEngine {
    private var session: Session? = null
    private var server: ServerSocket? = null
    @Volatile private var running = false

    /** Raw socket to the SSH server, with optional proxy hop, HTTP payload and TLS wrap. */
    private class PayloadProxy(private val ip: String, private val x: JSONObject) : Proxy {
        private var sock: Socket? = null
        private var inp: InputStream? = null
        private var out: OutputStream? = null

        override fun connect(sf: SocketFactory?, host: String, port: Int, timeout: Int) {
            val proxy = x.optString("proxy")
            val (cHost, cPort) = if (proxy.isNotBlank())
                proxy.substringBeforeLast(':') to proxy.substringAfterLast(':').toInt() else ip to port
            var s = Socket()
            s.tcpNoDelay = true
            s.connect(InetSocketAddress(cHost, cPort), timeout.coerceAtLeast(10_000))

            val sni = x.optString("sni")
            if (sni.isNotBlank()) {
                val ssl = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(s, sni, cPort, true) as SSLSocket
                ssl.sslParameters = ssl.sslParameters.apply { serverNames = listOf(SNIHostName(sni)) }
                ssl.startHandshake()
                s = ssl
            }
            val payload = x.optString("payload")
            if (payload.isNotBlank()) {
                val data = payload.replace("[crlf]", "\r\n").replace("[host]", host).replace("[port]", port.toString())
                    .replace("[lf]", "\n").replace("[cr]", "\r")
                s.getOutputStream().apply { write(data.toByteArray()); flush() }
                // Read the HTTP response head (e.g. "101 Switching Protocols" / "200 OK") and discard it.
                val ins = s.getInputStream()
                val head = StringBuilder()
                while (!head.endsWith("\r\n\r\n") && head.length < 8192) {
                    val b = ins.read()
                    if (b < 0) throw java.io.IOException("Payload: connection closed before response")
                    head.append(b.toChar())
                }
                val status = head.lineSequence().firstOrNull().orEmpty()
                if (!Regex("HTTP/1\\.[01] (101|200)").containsMatchIn(status))
                    throw java.io.IOException("Payload rejected: $status")
            }
            sock = s; inp = s.getInputStream(); out = s.getOutputStream()
        }
        override fun getInputStream() = inp
        override fun getOutputStream() = out
        override fun getSocket() = sock
        override fun close() { try { sock?.close() } catch (_: Exception) {} }
    }

    fun start(p: Profile, serverIp: String) {
        val x = JSONObject(p.extra.ifBlank { "{}" })
        val user = p.secret.substringBefore(':')
        val pass = p.secret.substringAfter(':', "")
        require(user.isNotBlank()) { "SSH profile needs user:password" }

        val jsch = JSch()
        val s = jsch.getSession(user, p.address, p.port)
        s.setPassword(pass)
        s.setConfig("StrictHostKeyChecking", "no") // user-supplied tunnel servers; no known_hosts store
        s.setConfig("compression.s2c", "zlib@openssh.com,zlib,none")
        s.setConfig("compression.c2s", "zlib@openssh.com,zlib,none")
        s.setServerAliveInterval(25_000)
        s.setProxy(PayloadProxy(serverIp, x))
        s.connect(20_000)
        session = s

        val ss = ServerSocket(XrayConfig.SOCKS_PORT, 64, InetAddress.getByName("127.0.0.1"))
        server = ss
        running = true
        Thread({ while (running) { try { val c = ss.accept(); Thread { handle(c, s) }.start() } catch (_: Exception) { break } } }, "ssh-socks").start()
    }

    /** Minimal SOCKS5: no auth, CONNECT only. */
    private fun handle(c: Socket, s: Session) {
        try {
            val i = c.getInputStream(); val o = c.getOutputStream()
            if (i.read() != 5) return
            i.skip(i.read().toLong()); o.write(byteArrayOf(5, 0))
            val h = rd(i, 4)
            if (h[1].toInt() != 1) { o.write(byteArrayOf(5, 7, 0, 1, 0, 0, 0, 0, 0, 0)); return }
            val host = when (h[3].toInt()) {
                1 -> InetAddress.getByAddress(rd(i, 4)).hostAddress!!
                3 -> String(rd(i, i.read()))
                4 -> InetAddress.getByAddress(rd(i, 16)).hostAddress!!
                else -> return
            }
            val port = (i.read() shl 8) or i.read()
            val ch = s.openChannel("direct-tcpip") as ChannelDirectTCPIP
            ch.setHost(host); ch.setPort(port)
            val cin = ch.inputStream; val cout = ch.outputStream
            ch.connect(10_000)
            o.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            val up = Thread { try { i.copyTo(cout) } catch (_: Exception) {} finally { ch.disconnect() } }
            up.start()
            try { cin.copyTo(o) } catch (_: Exception) {}
            ch.disconnect()
        } catch (_: Exception) {
        } finally { try { c.close() } catch (_: Exception) {} }
    }

    private fun rd(i: InputStream, n: Int): ByteArray {
        val b = ByteArray(n); var o = 0
        while (o < n) { val r = i.read(b, o, n - o); if (r < 0) throw java.io.IOException("eof"); o += r }
        return b
    }

    fun isAlive() = session?.isConnected == true

    fun stop() {
        running = false
        try { server?.close() } catch (_: Exception) {}
        try { session?.disconnect() } catch (_: Exception) {}
        server = null; session = null
    }
}
