# NORA TUNNEL v1.1

Android VPN client (Kotlin, Compose). Package `com.nora.tunnel`.

Protocols: VLESS / VMess / Trojan (TCP, WS/WSS, gRPC, HTTPUpgrade, XHTTP, Reality, TLS, HTTP payload), Shadowsocks (+ws/tls plugin),
SOCKS5, HTTP proxy, SSH (direct / payload / SSL), DNSTT (LowDNS), OpenVPN (UDP/TCP, untested). See NATIVE.md.

v1.1: new animated Home, manual profile editor for every protocol, crash reporter (a crash is shown on next launch instead of silent exit),
all native-library errors caught (no more process kill on Connect), FGS type specialUse (vpn).
