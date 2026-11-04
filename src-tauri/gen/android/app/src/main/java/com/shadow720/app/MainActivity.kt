package com.shadow720.app

import android.os.Bundle
import android.view.View
import android.webkit.WebView
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import kotlin.math.max

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    // The UI is always dark. Light system-bar icons would vanish on it.
    WindowCompat.getInsetsController(window, window.decorView).apply {
      isAppearanceLightStatusBars = false
      isAppearanceLightNavigationBars = false
    }
  }

  /**
   * Keep the page above the status bar, navigation buttons, and keyboard.
   *
   * Android 15 draws targetSdk 35+ apps edge-to-edge, so the webview otherwise
   * extends under the system navigation bar and the bottom tabs cannot be tapped.
   * Padding the webview's parent shrinks the page instead of painting buttons in
   * a region the system owns.
   */
  override fun onWebViewCreate(webView: WebView) {
    webView.setBackgroundColor(0xFF0B1020.toInt())
    // Posted so this runs after setContentView attaches the webview.
    webView.post { applySystemBarInsets(webView) }
  }

  private fun applySystemBarInsets(webView: WebView) {
    val host = (webView.parent as? View) ?: findViewById(android.R.id.content)
    host.setBackgroundColor(0xFF0B1020.toInt())
    ViewCompat.setOnApplyWindowInsetsListener(host) { view, insets ->
      val bars = insets.getInsets(
        WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout(),
      )
      val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
      view.setPadding(bars.left, bars.top, bars.right, max(bars.bottom, ime.bottom))
      WindowInsetsCompat.CONSUMED
    }
    ViewCompat.requestApplyInsets(host)
  }
}
