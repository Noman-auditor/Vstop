# Native components (not bundled)

The app compiles without these, but **Connect will fail with a clear error until both are added.**

## 1. Xray core (AAR)
Put a gomobile build of Xray (e.g. the AndroidLibXrayLite project's `libv2ray.aar`) into `app/libs/`.
`core/XrayEngine.kt` calls it by reflection and expects `libv2ray.Libv2ray.newCoreController(handler)`
and `CoreController.startLoop(config, fd)` / `stopLoop()`. If your AAR exposes a different API,
adjust only `XrayEngine.kt`. Xray-core is MPL-2.0.

## 2. hev-socks5-tunnel (.so)
Build `libhev-socks5-tunnel.so` from the heiher/hev-socks5-tunnel project with the Android NDK and
place each ABI under `app/src/main/jniLibs/<abi>/` (arm64-v8a, armeabi-v7a, x86_64, x86).
The Kotlin binding is `hev/htproxy/TProxyService.kt`; its package and class name must not change.
hev-socks5-tunnel is MIT licensed.

## Not implemented
WireGuard profiles (the parser accepts none yet and XrayConfig rejects the protocol), per-app routing,
split-tunnel and custom rules (only Default and Bypass LAN are applied).

## Protocol support
| Protocol | Engine | Link format |
|---|---|---|
| Shadowsocks (+ v2ray-plugin ws/tls) | Xray | `ss://` |
| VMess / VLESS / Trojan (TCP, WS, WSS, gRPC, HTTPUpgrade, XHTTP, Reality, TLS) | Xray | `vmess://` `vless://` `trojan://` |
| Direct / HTTP payload (TCP header obfuscation) | Xray | `vless://...?type=tcp&headerType=http&host=...&path=...` |
| SOCKS5 / HTTP proxy outbound | Xray | `socks5://user:pass@h:p`, `http-proxy://` |
| SSH direct / payload / SSL (SNI) | SshEngine (JSch, in-app) | `ssh://user:pass@h:22?payload=...&proxy=h:p&sni=...` |
| OpenVPN UDP/TCP | OpenVpnEngine (management interface, **untested**) + `libopenvpn.so` | import a `.ovpn` file or paste its text |
| DNSTT / LowDNS (SSH over DNS) | DnsttEngine + SshEngine + `libdnstt.so` | `dnstt://user:pass@t.example.com?pubkey=HEX&mode=udp&resolver=1.1.1.1:53` |

SSH payload placeholders: `[crlf] [lf] [cr] [host] [port]`. SSH carries TCP only (no UDP).

## 3. libdnstt.so (LowDNS)
Build `dnstt-client` from www.bamsoftware.com/software/dnstt with the Go toolchain for each Android ABI and place it as
`app/src/main/jniLibs/<abi>/libdnstt.so`. Modes: `udp`, `dot`, `doh` (resolver = https URL). The far end must be an SSH server.

## 4. libopenvpn.so
Use the openvpn binary built by ics-openvpn (its fork speaks the OPENTUN/IFCONFIG management commands), placed as
`app/src/main/jniLibs/<abi>/libopenvpn.so`. Stock openvpn will not work. Username/password: `extra.user` / `extra.pass`
in the profile (no UI field yet). OpenVPN bypasses hev and Xray; stats come from its bytecount.
