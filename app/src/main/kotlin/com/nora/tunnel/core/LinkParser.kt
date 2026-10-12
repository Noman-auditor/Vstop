package com.nora.tunnel.core

import android.net.Uri
import android.util.Base64
import com.nora.tunnel.data.Profile
import org.json.JSONObject

object LinkParser {

    fun parse(link: String): Profile? = try {
        val l = link.trim()
        when {
            l.startsWith("vless://") -> parseUriStyle(l, "vless")
            l.startsWith("trojan://") -> parseUriStyle(l, "trojan")
            l.startsWith("vmess://") -> parseVmess(l)
            l.startsWith("ss://") -> parseSs(l)
            l.startsWith("socks://") || l.startsWith("socks5://") -> parseProxy(l, "socks")
            l.startsWith("http-proxy://") -> parseProxy(l, "http")
            l.startsWith("ssh://") -> parseSsh(l)
            l.startsWith("dnstt://") -> parseDnstt(l)
            else -> null
        }
    } catch (e: Exception) {
        null
    }

    /** Parses plain text or base64 subscription content into profiles. */
    fun parseSubscription(body: String): List<Profile> {
        if (looksLikeOvpn(body)) return listOfNotNull(parseOvpn(body))
        val text = if (body.contains("://")) body else decodeB64(body.trim())
        return text.lines().mapNotNull { parse(it) }
    }

    private fun parseUriStyle(link: String, proto: String): Profile? {
        val u = Uri.parse(link)
        val host = u.host ?: return null
        val port = if (u.port > 0) u.port else 443
        val extra = JSONObject()
        for (k in listOf("path", "host", "sni", "flow", "pbk", "sid", "fp", "alpn", "serviceName", "headerType",
            "allowInsecure", "mode", "method", "payload")) {
            u.getQueryParameter(k)?.let { extra.put(k, it) }
        }
        val name = u.fragment?.takeIf { it.isNotBlank() } ?: "$host:$port"
        return Profile(
            name = name, protocol = proto, address = host, port = port,
            secret = u.userInfo ?: "",
            transport = u.getQueryParameter("type") ?: "tcp",
            security = u.getQueryParameter("security") ?: if (proto == "trojan") "tls" else "none",
            extra = extra.toString(), country = CountryUtil.fromName(name), rawLink = link,
        )
    }

    private fun parseVmess(link: String): Profile? {
        val j = JSONObject(decodeB64(link.removePrefix("vmess://")))
        val extra = JSONObject()
        for (k in listOf("path", "host", "sni", "alpn", "fp", "type", "scy", "allowInsecure")) {
            j.optString(k).takeIf { it.isNotBlank() }?.let { extra.put(k, it) }
        }
        val name = j.optString("ps").ifBlank { j.optString("add") }
        return Profile(
            name = name, protocol = "vmess", address = j.getString("add"),
            port = j.get("port").toString().toInt(), secret = j.getString("id"),
            transport = j.optString("net", "tcp"),
            security = j.optString("tls").ifBlank { "none" },
            extra = extra.toString(), country = CountryUtil.fromName(name), rawLink = link,
        )
    }

    private fun parseSs(link: String): Profile? {
        val body = link.removePrefix("ss://")
        val name = body.substringAfter('#', "").let { Uri.decode(it) }
        val main = body.substringBefore('#').substringBefore('?')
        val (userInfo, hostPort) = if (main.contains('@')) {
            val ui = main.substringBeforeLast('@')
            val decoded = if (ui.contains(':')) ui else decodeB64(ui)
            decoded to main.substringAfterLast('@')
        } else {
            val d = decodeB64(main)
            d.substringBeforeLast('@') to d.substringAfterLast('@')
        }
        val method = userInfo.substringBefore(':')
        val password = userInfo.substringAfter(':')
        val host = hostPort.substringBeforeLast(':')
        val port = hostPort.substringAfterLast(':').toInt()
        val extra = JSONObject().put("method", method.ifBlank { "aes-256-gcm" })
        var transport = "tcp"
        var security = "none"
        // SIP003 plugin: ?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Btls%3Bhost%3Dexample.com%3Bpath%3D%2Fws
        val plugin = Uri.parse("ss://x?" + body.substringBefore('#').substringAfter('?', "")).getQueryParameter("plugin")
        if (plugin != null && (plugin.startsWith("v2ray-plugin") || plugin.startsWith("xray-plugin"))) {
            val opts = plugin.split(';').drop(1)
            transport = "ws"
            for (o in opts) {
                val k = o.substringBefore('=')
                val v = o.substringAfter('=', "")
                when (k) {
                    "tls" -> security = "tls"
                    "host" -> { extra.put("host", v); extra.put("sni", v) }
                    "path" -> extra.put("path", v)
                    "mode" -> if (v == "quic") return null // not supported by Xray
                }
            }
        }
        val n = name.ifBlank { "$host:$port" }
        return Profile(
            name = n, protocol = "ss", address = host, port = port, secret = password,
            transport = transport, security = security,
            extra = extra.toString(), country = CountryUtil.fromName(n), rawLink = link,
        )
    }

    /** socks5://[user:pass@]host:port#name  and  http-proxy://[user:pass@]host:port#name (outbound proxy via Xray). */
    private fun parseProxy(link: String, proto: String): Profile? {
        val u = Uri.parse(link)
        val host = u.host ?: return null
        val port = if (u.port > 0) u.port else if (proto == "socks") 1080 else 8080
        val name = u.fragment?.takeIf { it.isNotBlank() } ?: "$host:$port"
        // secret holds "user:pass" (empty when the proxy has no auth)
        return Profile(
            name = name, protocol = proto, address = host, port = port, secret = u.userInfo ?: "",
            country = CountryUtil.fromName(name), rawLink = link,
        )
    }

    /**
     * ssh://user:pass@host:port#name
     *   ?payload=GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]   (SSH + HTTP payload)
     *   &proxy=host:port   (optional HTTP proxy the payload is sent through)
     *   &sni=example.com   (optional: wrap the connection in TLS first = SSH over SSL)
     */
    private fun parseSsh(link: String): Profile? {
        val u = Uri.parse(link)
        val host = u.host ?: return null
        val port = if (u.port > 0) u.port else 22
        val extra = JSONObject()
        for (k in listOf("payload", "proxy", "sni")) u.getQueryParameter(k)?.let { extra.put(k, it) }
        val name = u.fragment?.takeIf { it.isNotBlank() } ?: "$host:$port"
        return Profile(
            name = name, protocol = "ssh", address = host, port = port, secret = u.userInfo ?: "",
            transport = if (extra.has("payload")) "payload" else "direct",
            security = if (extra.has("sni")) "tls" else "none",
            extra = extra.toString(), country = CountryUtil.fromName(name), rawLink = link,
        )
    }

    /**
     * dnstt://user:pass@t.example.com?pubkey=HEX&mode=udp|dot|doh&resolver=1.1.1.1:53#name
     * user:pass are the SSH login at the far end of the DNS tunnel. For doh, resolver is the full https URL.
     */
    private fun parseDnstt(link: String): Profile? {
        val u = Uri.parse(link)
        val domain = u.host ?: return null
        val pubkey = u.getQueryParameter("pubkey") ?: return null
        val mode = u.getQueryParameter("mode") ?: "udp"
        val resolver = u.getQueryParameter("resolver") ?: "1.1.1.1:53"
        val (rHost, rPort) = if (mode == "doh") {
            val r = Uri.parse(resolver); (r.host ?: return null) to (if (r.port > 0) r.port else 443)
        } else resolver.substringBeforeLast(':') to (resolver.substringAfterLast(':', "53").toIntOrNull() ?: 53)
        val extra = JSONObject().put("domain", domain).put("pubkey", pubkey).put("mode", mode).put("resolver", resolver)
        val name = u.fragment?.takeIf { it.isNotBlank() } ?: "DNSTT $domain"
        return Profile(
            name = name, protocol = "dnstt", address = rHost, port = rPort, secret = u.userInfo ?: "",
            transport = mode, extra = extra.toString(), country = CountryUtil.fromName(name), rawLink = "",
        )
    }

    private val remoteRe = Regex("(?m)^\\s*remote\\s+(\\S+)(?:\\s+(\\d+))?(?:\\s+(udp|tcp)\\S*)?")

    fun looksLikeOvpn(body: String) =
        remoteRe.containsMatchIn(body) && (body.contains("<ca>") || Regex("(?m)^\\s*(client|ca|dev)\\b").containsMatchIn(body))

    /** Whole .ovpn text is stored in extra.config; user/pass can be set on the profile later. */
    fun parseOvpn(body: String): Profile? {
        val m = remoteRe.find(body) ?: return null
        val host = m.groupValues[1]
        val protoLine = Regex("(?m)^\\s*proto\\s+(\\S+)").find(body)?.groupValues?.get(1) ?: "udp"
        val proto = m.groupValues[3].ifBlank { protoLine }.lowercase().let { if (it.startsWith("tcp")) "tcp" else "udp" }
        val port = m.groupValues[2].toIntOrNull()
            ?: Regex("(?m)^\\s*port\\s+(\\d+)").find(body)?.groupValues?.get(1)?.toIntOrNull() ?: 1194
        val extra = JSONObject().put("config", body)
        val name = "OpenVPN $host"
        return Profile(
            name = name, protocol = "openvpn", address = host, port = port, secret = "",
            transport = proto, extra = extra.toString(), country = CountryUtil.fromName(host), rawLink = "",
        )
    }

    private fun decodeB64(s: String): String {
        var t = s.replace('-', '+').replace('_', '/').trim()
        while (t.length % 4 != 0) t += "="
        return String(Base64.decode(t, Base64.DEFAULT), Charsets.UTF_8)
    }
}

object CountryUtil {
    private val codes = mapOf(
        "united states" to "US", "usa" to "US", "germany" to "DE", "singapore" to "SG",
        "japan" to "JP", "united kingdom" to "GB", "uk" to "GB", "canada" to "CA",
        "france" to "FR", "netherlands" to "NL", "india" to "IN", "bangladesh" to "BD",
    )

    /** Returns ISO country code guessed from a server name, or "". */
    fun fromName(name: String): String {
        val n = name.lowercase()
        codes.forEach { (k, v) -> if (n.contains(k)) return v }
        Regex("\\b([A-Z]{2})\\b").find(name)?.value?.let { return it }
        // Flag emoji: two regional indicator symbols
        val cps = name.codePoints().toArray()
        for (i in 0 until cps.size - 1) {
            if (cps[i] in 0x1F1E6..0x1F1FF && cps[i + 1] in 0x1F1E6..0x1F1FF) {
                return "" + ('A' + (cps[i] - 0x1F1E6)) + ('A' + (cps[i + 1] - 0x1F1E6))
            }
        }
        return ""
    }

    fun flag(code: String): String {
        if (code.length != 2) return "\uD83C\uDF10"
        return code.uppercase().map { String(Character.toChars(0x1F1E6 + (it - 'A'))) }.joinToString("")
    }
}
