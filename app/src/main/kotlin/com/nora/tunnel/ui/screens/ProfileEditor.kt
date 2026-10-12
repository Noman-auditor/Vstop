package com.nora.tunnel.ui.screens

import android.net.Uri
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.text.KeyboardOptions
import com.nora.tunnel.MainViewModel
import com.nora.tunnel.core.CountryUtil
import com.nora.tunnel.core.LinkParser
import com.nora.tunnel.data.Profile
import com.nora.tunnel.ui.components.*
import com.nora.tunnel.ui.theme.NoraColors
import org.json.JSONObject

private val protocols = listOf(
    "vless" to "VLESS", "vmess" to "VMess", "trojan" to "Trojan", "ss" to "Shadowsocks",
    "ssh" to "SSH", "dnstt" to "DNSTT / LowDNS", "openvpn" to "OpenVPN", "socks" to "SOCKS5", "http" to "HTTP Proxy",
)
private val transports = mapOf(
    "vless" to listOf("tcp", "ws", "grpc", "httpupgrade", "xhttp"),
    "vmess" to listOf("tcp", "ws", "grpc", "httpupgrade"),
    "trojan" to listOf("tcp", "ws", "grpc"),
    "ss" to listOf("tcp", "ws"),
)
private val securities = mapOf(
    "vless" to listOf("none", "tls", "reality"), "vmess" to listOf("none", "tls"),
    "trojan" to listOf("tls", "none"), "ss" to listOf("none", "tls"),
)
private val extraFields = mapOf(
    "vless" to listOf("host" to "Host (WS/HTTP payload host)", "path" to "Path", "sni" to "SNI", "flow" to "Flow", "fp" to "Fingerprint", "pbk" to "Reality public key", "sid" to "Reality short id", "serviceName" to "gRPC service name"),
    "vmess" to listOf("host" to "Host (WS/HTTP payload host)", "path" to "Path", "sni" to "SNI", "scy" to "Cipher (auto)"),
    "trojan" to listOf("host" to "Host", "path" to "Path", "sni" to "SNI"),
    "ss" to listOf("method" to "Method (aes-256-gcm)", "host" to "WS host / SNI", "path" to "WS path"),
    "ssh" to listOf("payload" to "Payload  ([crlf] [host] [port])", "proxy" to "HTTP proxy host:port", "sni" to "SNI (SSH over SSL)"),
    "dnstt" to listOf("domain" to "Tunnel domain (NS)", "pubkey" to "Public key (hex)", "resolver" to "Resolver (1.1.1.1:53 or DoH URL)"),
    "openvpn" to listOf("user" to "Username", "pass" to "Password"),
)
private fun secretLabel(p: String) = when (p) {
    "vless", "vmess" -> "UUID"; "trojan", "ss" -> "Password"
    "ssh", "dnstt", "socks", "http" -> "user:pass"; else -> ""
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ProfileEditorScreen(vm: MainViewModel, id: Long, onBack: () -> Unit) {
    val profiles by vm.profiles.collectAsState()
    val existing = profiles.firstOrNull { it.id == id }
    var loaded by remember { mutableStateOf(false) }
    var proto by remember { mutableStateOf("vless") }
    var name by remember { mutableStateOf("") }
    var address by remember { mutableStateOf("") }
    var port by remember { mutableStateOf("443") }
    var secret by remember { mutableStateOf("") }
    var transport by remember { mutableStateOf("tcp") }
    var security by remember { mutableStateOf("none") }
    var httpHeader by remember { mutableStateOf(false) }
    var insecure by remember { mutableStateOf(false) }
    var config by remember { mutableStateOf("") }
    var mode by remember { mutableStateOf("udp") }
    val extra = remember { mutableStateMapOf<String, String>() }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(existing?.id) {
        val p = existing
        if (p != null && !loaded) {
            loaded = true
            proto = p.protocol; name = p.name; address = p.address; port = p.port.toString(); secret = p.secret
            transport = p.transport; security = p.security
            val x = JSONObject(p.extra.ifBlank { "{}" })
            x.keys().forEach { k -> extra[k] = x.optString(k) }
            httpHeader = x.optString("headerType") == "http"
            insecure = x.optString("allowInsecure") in listOf("1", "true")
            config = x.optString("config"); mode = x.optString("mode").ifBlank { p.transport.takeIf { proto == "dnstt" } ?: "udp" }
        }
    }

    fun save() {
        error = null
        val x = JSONObject()
        extraFields[proto].orEmpty().forEach { (k, _) -> extra[k]?.takeIf { it.isNotBlank() }?.let { x.put(k, it) } }
        var p: Profile? = when (proto) {
            "openvpn" -> LinkParser.parseOvpn(config)?.let {
                val xo = JSONObject(it.extra); extra["user"]?.let { u -> xo.put("user", u) }; extra["pass"]?.let { w -> xo.put("pass", w) }
                it.copy(name = name.ifBlank { it.name }, extra = xo.toString())
            }
            "dnstt" -> {
                if (extra["domain"].isNullOrBlank() || extra["pubkey"].isNullOrBlank()) null
                else LinkParser.parse(
                    "dnstt://${secret}@${extra["domain"]}?pubkey=${extra["pubkey"]}&mode=$mode" +
                        "&resolver=${Uri.encode(extra["resolver"].orEmpty().ifBlank { "1.1.1.1:53" })}#${Uri.encode(name)}"
                )
            }
            else -> {
                val prt = port.toIntOrNull()
                if (address.isBlank() || prt == null) null else {
                    if (proto in listOf("vless", "vmess", "trojan")) {
                        if (httpHeader) { x.put("headerType", "http") }
                        if (insecure) x.put("allowInsecure", "1")
                    }
                    Profile(
                        name = name.ifBlank { "$address:$prt" }, protocol = proto, address = address.trim(), port = prt,
                        secret = secret.trim(),
                        transport = when (proto) { "ssh" -> if (x.has("payload")) "payload" else "direct"; in transports -> transport; else -> "tcp" },
                        security = when (proto) { "ssh" -> if (x.has("sni")) "tls" else "none"; in securities -> security; else -> "none" },
                        extra = x.toString(), country = CountryUtil.fromName(name.ifBlank { address }),
                    )
                }
            }
        }
        if (p == null) { error = "Fill the required fields (address, port, and protocol-specific values)"; return }
        if (proto == "dnstt") p = p.copy(name = name.ifBlank { p.name })
        if (existing != null) p = p.copy(id = existing.id, createdAt = existing.createdAt)
        vm.save(p) { onBack() }
    }

    Column(Modifier.fillMaxSize().padding(horizontal = 16.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        ScreenHeader(if (existing == null) "New Profile" else "Edit Profile", onBack)
        Text("Protocol", color = NoraColors.TextDim, fontSize = 12.sp)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            protocols.forEach { (k, label) ->
                FilterChip(selected = proto == k, onClick = {
                    proto = k
                    port = when (k) { "ssh" -> "22"; "socks" -> "1080"; "http" -> "8080"; "openvpn" -> "1194"; "dnstt" -> "53"; else -> "443" }
                    transport = "tcp"; security = if (k == "trojan") "tls" else "none"
                }, label = { Text(label) })
            }
        }
        Field("Name", name) { name = it }
        if (proto != "openvpn" && proto != "dnstt") {
            Field("Address / Host", address) { address = it }
            Field("Port", port, number = true) { port = it }
        }
        if (secretLabel(proto).isNotEmpty()) Field(secretLabel(proto), secret) { secret = it }
        if (proto == "dnstt") {
            Text("Mode", color = NoraColors.TextDim, fontSize = 12.sp)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf("udp", "dot", "doh").forEach { m -> FilterChip(selected = mode == m, onClick = { mode = m }, label = { Text(m.uppercase()) }) }
            }
        }
        transports[proto]?.let { list ->
            Text("Transport", color = NoraColors.TextDim, fontSize = 12.sp)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                list.forEach { t -> FilterChip(selected = transport == t, onClick = { transport = t }, label = { Text(t.uppercase()) }) }
            }
        }
        securities[proto]?.let { list ->
            Text("Security", color = NoraColors.TextDim, fontSize = 12.sp)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                list.forEach { s -> FilterChip(selected = security == s, onClick = { security = s }, label = { Text(s.uppercase()) }) }
            }
        }
        if (proto in listOf("vless", "vmess", "trojan")) {
            ToggleRow("HTTP payload header", "TCP + fake HTTP request (Direct / Payload)", httpHeader) { httpHeader = it }
            ToggleRow("Allow insecure TLS", "Skip certificate check", insecure) { insecure = it }
        }
        extraFields[proto].orEmpty().forEach { (k, label) ->
            Field(label, extra[k].orEmpty(), password = k == "pass") { extra[k] = it }
        }
        if (proto == "openvpn") {
            OutlinedTextField(
                value = config, onValueChange = { config = it }, label = { Text(".ovpn config (paste full text)") },
                minLines = 6, maxLines = 12, modifier = Modifier.fillMaxWidth(),
            )
        }
        error?.let { Text(it, color = NoraColors.Red, fontSize = 12.sp) }
        PrimaryButton("Save") { save() }
        Spacer(Modifier.height(16.dp))
    }
}

@Composable
private fun Field(label: String, value: String, number: Boolean = false, password: Boolean = false, onChange: (String) -> Unit) {
    OutlinedTextField(
        value = value, onValueChange = onChange, label = { Text(label) }, singleLine = true,
        modifier = Modifier.fillMaxWidth(),
        keyboardOptions = KeyboardOptions(keyboardType = if (number) KeyboardType.Number else if (password) KeyboardType.Password else KeyboardType.Text),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = NoraColors.Mint, unfocusedBorderColor = NoraColors.Border,
            focusedLabelColor = NoraColors.Mint, unfocusedLabelColor = NoraColors.TextDim,
            focusedTextColor = Color.White, unfocusedTextColor = Color.White, cursorColor = NoraColors.Mint,
        ),
    )
}
