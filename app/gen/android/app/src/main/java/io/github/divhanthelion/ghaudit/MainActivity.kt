package io.github.divhanthelion.ghaudit

import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
  }

  // The page draws edge to edge, but Android WebView does not report the system bars
  // or the keyboard through env(safe-area-inset-*), so hand the page the insets in CSS
  // pixels. ui/js/app.js reads them and sets --native-inset-* on the root element.
  private val insets = Insets()

  class Insets {
    @Volatile var json = "{\"top\":0,\"right\":0,\"bottom\":0,\"left\":0}"

    @JavascriptInterface
    fun get(): String = json
  }

  override fun onWebViewCreate(webView: WebView) {
    webView.addJavascriptInterface(insets, "AndroidInsets")
    ViewCompat.setOnApplyWindowInsetsListener(webView) { view, windowInsets ->
      val bars = windowInsets.getInsets(
        WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
      )
      val ime = windowInsets.getInsets(WindowInsetsCompat.Type.ime())
      val density = view.resources.displayMetrics.density
      fun css(px: Int) = px / density
      insets.json = "{\"top\":${css(bars.top)},\"right\":${css(bars.right)}," +
        "\"bottom\":${css(maxOf(bars.bottom, ime.bottom))},\"left\":${css(bars.left)}}"
      view.post { webView.evaluateJavascript("window.dispatchEvent(new Event('androidinsets'))", null) }
      windowInsets
    }
  }
}
