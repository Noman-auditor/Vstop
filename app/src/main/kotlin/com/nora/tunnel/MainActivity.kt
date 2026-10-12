package com.nora.tunnel

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.sp
import com.nora.tunnel.core.CrashReporter
import com.nora.tunnel.ui.nav.NoraNav
import com.nora.tunnel.ui.theme.NoraTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val settings = (application as NoraApp).settings
        setContent { NoraTheme { NoraNav(settings); CrashDialog() } }
    }
}

@Composable
private fun CrashDialog() {
    val ctx = LocalContext.current
    val clip = LocalClipboardManager.current
    var report by remember { mutableStateOf(CrashReporter.pending(ctx)) }
    val r = report ?: return
    AlertDialog(
        onDismissRequest = { CrashReporter.clear(ctx); report = null },
        title = { Text("App crashed last time") },
        text = { Text(r.take(2500), fontSize = 11.sp, modifier = androidx.compose.ui.Modifier.verticalScroll(rememberScrollState())) },
        confirmButton = { TextButton(onClick = { clip.setText(AnnotatedString(r)); CrashReporter.clear(ctx); report = null }) { Text("Copy & close") } },
        dismissButton = { TextButton(onClick = { CrashReporter.clear(ctx); report = null }) { Text("Close") } },
    )
}
