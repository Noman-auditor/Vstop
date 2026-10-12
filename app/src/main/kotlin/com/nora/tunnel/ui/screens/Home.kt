package com.nora.tunnel.ui.screens

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.drawscope.Stroke
import com.nora.tunnel.ui.components.Badge
import kotlinx.coroutines.delay
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.nora.tunnel.NoraApp
import com.nora.tunnel.core.AppLog
import com.nora.tunnel.core.VpnController
import com.nora.tunnel.core.VpnState
import com.nora.tunnel.ui.components.NoraCard
import com.nora.tunnel.ui.components.formatBytes
import com.nora.tunnel.ui.theme.NoraColors
import kotlinx.coroutines.flow.first

@Composable
fun HomeScreen(profileName: String?, profileProto: String?, recent: List<AppLog.Entry>, onServers: () -> Unit, onSettings: () -> Unit) {
    val ctx = LocalContext.current
    val state by VpnController.state.collectAsState()
    val live by VpnController.live.collectAsState()
    val error by VpnController.error.collectAsState()

    val vpnPermission = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == Activity.RESULT_OK) VpnController.start(ctx)
    }
    val notifPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {}

    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)

        if (!VpnController.autoTried) {
            VpnController.autoTried = true
            val auto = (ctx.applicationContext as NoraApp).settings.autoConnectOn.first()
            if (auto && VpnController.state.value == VpnState.DISCONNECTED && VpnService.prepare(ctx) == null) {
                VpnController.start(ctx)
            }
        }
    }

    fun onPower() {
        if (state == VpnState.CONNECTED || state == VpnState.CONNECTING) { VpnController.stop(ctx); return }
        val i = VpnService.prepare(ctx)
        if (i != null) vpnPermission.launch(i) else VpnController.start(ctx)
    }

    val accent = when (state) {
        VpnState.CONNECTED -> NoraColors.Mint
        VpnState.ERROR -> NoraColors.Red
        VpnState.CONNECTING -> NoraColors.Orange
        else -> NoraColors.Blue
    }
    val title = when (state) {
        VpnState.CONNECTED -> "Connected"; VpnState.CONNECTING -> "Connecting…"
        VpnState.ERROR -> "Connection failed"; else -> "Disconnected"
    }
    val hint = when (state) {
        VpnState.CONNECTED, VpnState.CONNECTING -> "Tap to disconnect"
        VpnState.ERROR -> "Tap to retry"; else -> "Tap to connect"
    }

    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(state) { while (state == VpnState.CONNECTED) { now = System.currentTimeMillis(); delay(1000) } }
    val uptime = if (state == VpnState.CONNECTED && live.since > 0) {
        val sec = ((now - live.since) / 1000).coerceAtLeast(0)
        "%02d:%02d:%02d".format(sec / 3600, (sec / 60) % 60, sec % 60)
    } else null

    val active = state == VpnState.CONNECTED || state == VpnState.CONNECTING
    val inf = rememberInfiniteTransition(label = "pulse")
    val ring by inf.animateFloat(0f, 1f, infiniteRepeatable(tween(2400, easing = LinearEasing)), label = "ring")
    val breathe by inf.animateFloat(0.96f, 1.04f, infiniteRepeatable(tween(1600, easing = FastOutSlowInEasing), RepeatMode.Reverse), label = "breathe")
    val accentAnim = accent

    Box(Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Color(0xFF0A1628), Color(0xFF0B2236), Color(0xFF0A1628))))) {
    Column(
        Modifier.fillMaxSize().padding(horizontal = 16.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.Shield, null, tint = NoraColors.Mint)
            Spacer(Modifier.width(8.dp))
            Text("NORA TUNNEL", color = Color.White, fontWeight = FontWeight.Bold, letterSpacing = 1.sp, modifier = Modifier.weight(1f))
            Icon(Icons.Filled.Settings, null, tint = NoraColors.Mint, modifier = Modifier.clickable { onSettings() })
        }

        // ---- hero: pulsing power button ----
        Column(Modifier.fillMaxWidth().padding(top = 8.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Box(Modifier.size(240.dp), contentAlignment = Alignment.Center) {
                Canvas(Modifier.fillMaxSize()) {
                    val c = center; val base = size.minDimension * 0.27f
                    drawCircle(Brush.radialGradient(listOf(accentAnim.copy(alpha = if (active) 0.28f else 0.12f), Color.Transparent), c, size.minDimension / 2), radius = size.minDimension / 2)
                    if (active) for (i in 0..2) {
                        val t = (ring + i / 3f) % 1f
                        drawCircle(accentAnim.copy(alpha = (1f - t) * 0.5f), radius = base + (size.minDimension / 2 - base) * t, center = c, style = Stroke(2.dp.toPx()))
                    }
                }
                Box(
                    Modifier.size(128.dp).scale(if (state == VpnState.CONNECTING) breathe else 1f).clip(CircleShape)
                        .background(Brush.radialGradient(listOf(accent.copy(alpha = 0.35f), Color(0xFF0F2038))))
                        .border(BorderStroke(3.dp, accent), CircleShape)
                        .clickable { onPower() },
                    contentAlignment = Alignment.Center,
                ) { Icon(Icons.Filled.PowerSettingsNew, null, tint = Color.White, modifier = Modifier.size(52.dp)) }
            }
            Text(title, color = accent, fontSize = 20.sp, fontWeight = FontWeight.Bold)
            Text(uptime ?: hint, color = if (uptime != null) Color.White else NoraColors.TextDim, fontSize = if (uptime != null) 26.sp else 13.sp,
                fontWeight = if (uptime != null) FontWeight.Light else FontWeight.Normal, letterSpacing = if (uptime != null) 2.sp else 0.sp)
            if (profileProto != null) { Spacer(Modifier.height(8.dp)); Badge(profileProto, accent) }
            if (state == VpnState.ERROR && error != null) {
                Spacer(Modifier.height(8.dp))
                Text(error ?: "", color = NoraColors.Red, fontSize = 12.sp, textAlign = androidx.compose.ui.text.style.TextAlign.Center)
            }
        }

        NoraCard(Modifier.fillMaxWidth(), onClick = onServers) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier.size(40.dp).clip(CircleShape).background(NoraColors.Blue.copy(alpha = 0.2f)),
                    contentAlignment = Alignment.Center,
                ) { Text("\uD83C\uDF10") }
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(live.name ?: profileName ?: "Auto Select", color = Color.White, fontWeight = FontWeight.SemiBold)
                    Text(
                        if (live.name != null || profileName != null) "Selected profile" else "Best location",
                        color = NoraColors.TextDim, fontSize = 12.sp,
                    )
                }
                Icon(Icons.Filled.ChevronRight, null, tint = NoraColors.TextDim)
            }
        }

        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            StatTile(formatBytes(live.rx), "Download", Modifier.weight(1f))
            StatTile(formatBytes(live.tx), "Upload", Modifier.weight(1f))
            StatTile(live.pingMs?.let { "$it ms" } ?: "--", "Ping", Modifier.weight(1f))
        }
        if (state == VpnState.CONNECTED) {
            Text(
                "↓ ${formatBytes(live.downBps)}/s   ↑ ${formatBytes(live.upBps)}/s",
                color = NoraColors.TextDim, fontSize = 12.sp, modifier = Modifier.align(Alignment.CenterHorizontally),
            )
        }

        NoraCard(Modifier.fillMaxWidth()) {
            Text("Recent Activity", color = Color.White, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(8.dp))
            if (recent.isEmpty()) {
                Text("No recent logs", color = NoraColors.TextDim, fontSize = 12.sp)
            } else {
                recent.take(3).forEach {
                    Text("${it.type}: ${it.message}", color = NoraColors.TextDim, fontSize = 12.sp, maxLines = 1)
                }
            }
        }
        Spacer(Modifier.height(16.dp))
    }
    }
}

@Composable
private fun StatTile(value: String, label: String, modifier: Modifier) {
    NoraCard(modifier) {
        Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
            Text(value, color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
            Text(label, color = NoraColors.TextDim, fontSize = 11.sp)
        }
    }
}
