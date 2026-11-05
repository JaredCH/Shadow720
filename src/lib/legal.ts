/**
 * Canonical URLs for the public legal documents.
 *
 * Play requires the privacy policy to be reachable both from the listing and from
 * inside the app, so these are referenced from the consent gate and from Settings
 * rather than being typed at each call site.
 *
 * The documents live in a separate public repository so the URL stays stable across
 * app releases: https://github.com/JaredCH/shadow720-legal
 */

/** Public privacy policy. */
export const PRIVACY_POLICY_URL =
  "https://jaredch.github.io/shadow720-legal/PRIVACY.md";

/** Public terms of use. */
export const TERMS_URL = "https://jaredch.github.io/shadow720-legal/TERMS.md";

/**
 * Open a URL in the platform's browser.
 *
 * Uses the shell plugin, which is the only way to leave the webview on Android.
 * Returns `false` when the platform refused, so the caller can fall back to showing
 * the URL as selectable text rather than leaving the user with a dead button.
 */
export async function openExternal(url: string): Promise<boolean> {
  const internals = (globalThis as { __TAURI_INTERNALS__?: unknown })
    .__TAURI_INTERNALS__;
  if (!internals) {
    // A plain browser tab can just navigate.
    window.open(url, "_blank", "noopener,noreferrer");
    return true;
  }
  try {
    const { open } = await import("@tauri-apps/plugin-shell");
    await open(url);
    return true;
  } catch {
    return false;
  }
}
