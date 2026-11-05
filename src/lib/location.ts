/**
 * On-device location polling and permission handling.
 *
 * The Tauri geolocation plugin is used on Android, where it is backed by the real
 * platform provider. On desktop the plugin is a documented no-op that resolves to
 * a zeroed position without prompting, so the browser Geolocation API is used
 * instead; that is what makes the map work in a desktop preview.
 */

import * as api from "./api";

export interface PositionFix {
  lat: number;
  lon: number;
  /** Ground speed in metres per second, when the platform reports it. */
  speedMps?: number;
  /** Direction of travel in degrees clockwise from north. */
  headingDeg?: number;
  /** Horizontal accuracy radius in metres. */
  accuracyM?: number;
}

/** Why a position could not be obtained. */
export type LocationFailure =
  | "permission-denied"
  | "permission-prompt"
  | "system-disabled"
  | "unavailable"
  | "timeout"
  | "runtime-unavailable";

/**
 * What the user has to change, if anything.
 *
 * `permission` means the app itself lacks access and the system prompt can still
 * be shown. `app-settings` means the permission was permanently denied, so only
 * the app's settings page can fix it. `system-settings` means the device-wide
 * location switch is off.
 */
export type LocationRemedy = "permission" | "app-settings" | "system-settings";

export interface LocationResult {
  fix?: PositionFix;
  failure?: LocationFailure;
  /** Human-readable detail, safe to show. */
  detail?: string;
}

/** The geolocation plugin's own error shape. */
interface PluginPosition {
  coords: {
    latitude: number;
    longitude: number;
    accuracy?: number | null;
    speed?: number | null;
    heading?: number | null;
  };
}

/** What the geolocation plugin actually returns. It is not a bare string. */
interface PluginPermissionStatus {
  /** Fine + coarse. Denied when the user picked approximate location only. */
  location?: string;
  /** Coarse only. Enough to put a pin on the map. */
  coarseLocation?: string;
}

type PluginPermission =
  | "granted"
  | "denied"
  | "prompt"
  | "prompt-with-rationale";

async function loadPlugin(): Promise<
  | {
      checkPermissions: () => Promise<PluginPermissionStatus>;
      requestPermissions: (
        permissions: Array<"location" | "coarseLocation"> | null,
      ) => Promise<PluginPermissionStatus>;
      getCurrentPosition: (options: {
        enableHighAccuracy: boolean;
        timeout: number;
        maximumAge: number;
      }) => Promise<PluginPosition>;
    }
  | null
> {
  const internals = (globalThis as { __TAURI_INTERNALS__?: unknown })
    .__TAURI_INTERNALS__;
  if (!internals) return null;
  // The plugin's desktop implementation is a stub that resolves to a zeroed
  // position, so using it there would silently report 0,0 as a real fix.
  if (!(await isAndroid())) return null;
  try {
    const module = await import("@tauri-apps/plugin-geolocation");
    return module as unknown as {
      checkPermissions: () => Promise<PluginPermissionStatus>;
      requestPermissions: (
        permissions: Array<"location" | "coarseLocation"> | null,
      ) => Promise<PluginPermissionStatus>;
      getCurrentPosition: (options: {
        enableHighAccuracy: boolean;
        timeout: number;
        maximumAge: number;
      }) => Promise<PluginPosition>;
    };
  } catch {
    return null;
  }
}

/**
 * Collapse the plugin's permission object into one state.
 *
 * Comparing the object to `"granted"` is always false, which made a successful
 * prompt look like a denial and stopped the map from ever reading a fix.
 * Approximate location grants only `coarseLocation`, and that is still a fix.
 */
function summarizePermission(value: unknown): PluginPermission | null {
  if (typeof value === "string") {
    return value === "granted" ||
      value === "denied" ||
      value === "prompt" ||
      value === "prompt-with-rationale"
      ? value
      : null;
  }
  if (!value || typeof value !== "object") return null;
  const status = value as PluginPermissionStatus;
  const states = [status.location, status.coarseLocation];
  if (states.includes("granted")) return "granted";
  if (states.includes("prompt-with-rationale")) return "prompt-with-rationale";
  if (states.includes("prompt")) return "prompt";
  if (states.includes("denied")) return "denied";
  return null;
}

function isLocationServicesDisabled(error: unknown): boolean {
  const detail = error instanceof Error ? error.message : String(error);
  return /location services are disabled|location is turned off/i.test(detail);
}

/** Cached platform check, so the OS plugin is queried at most once. */
let androidCache: boolean | null = null;

/** True when running inside the Android app. */
async function isAndroid(): Promise<boolean> {
  if (androidCache !== null) return androidCache;
  const internals = (globalThis as { __TAURI_INTERNALS__?: unknown })
    .__TAURI_INTERNALS__;
  if (!internals) {
    androidCache = false;
    return false;
  }
  try {
    const os = await import("@tauri-apps/plugin-os");
    androidCache = os.platform() === "android";
  } catch {
    // Fall back to the user agent, which is accurate enough for this decision.
    androidCache = /android/i.test(navigator.userAgent);
  }
  return androidCache;
}

/**
 * Current permission state, or `"runtime-unavailable"` when there is no native
 * bridge and the browser API cannot report it.
 */
export async function locationPermissionState(): Promise<
  | "granted"
  | "denied"
  | "prompt"
  | "prompt-with-rationale"
  | "system-disabled"
  | "runtime-unavailable"
> {
  const plugin = await loadPlugin();
  if (!plugin) {
    if (typeof navigator !== "undefined" && navigator.geolocation) return "prompt";
    return "runtime-unavailable";
  }
  try {
    return summarizePermission(await plugin.checkPermissions()) ?? "prompt";
  } catch (error) {
    if (isLocationServicesDisabled(error)) return "system-disabled";
    return "runtime-unavailable";
  }
}

/**
 * Ask for location permission.
 *
 * Call this only after the in-app disclosure has been acknowledged: Play requires
 * the disclosure to precede the system prompt.
 */
export async function requestLocationPermission(): Promise<boolean> {
  const plugin = await loadPlugin();
  if (!plugin) return true; // The browser prompt happens on first read instead.
  try {
    // `location` covers both fine and coarse. Do not request background here:
    // "ask every time" is a valid foreground grant, and background is a separate
    // settings action.
    const state = await plugin.requestPermissions(["location"]);
    return summarizePermission(state) === "granted";
  } catch {
    return false;
  }
}

/** Read one position fix. */
export async function currentPosition(): Promise<LocationResult> {
  const plugin = await loadPlugin();

  if (plugin) {
    try {
      const position = await plugin.getCurrentPosition({
        enableHighAccuracy: true,
        timeout: 15_000,
        maximumAge: 5_000,
      });
      return {
        fix: {
          lat: position.coords.latitude,
          lon: position.coords.longitude,
          speedMps: position.coords.speed ?? undefined,
          headingDeg: position.coords.heading ?? undefined,
          accuracyM: position.coords.accuracy ?? undefined,
        },
      };
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      if (isLocationServicesDisabled(error)) {
        return { failure: "system-disabled", detail };
      }
      // The plugin reports refusals in prose rather than a code, so the message
      // is the only signal available.
      if (/denied|not allowed|permission/i.test(detail)) {
        return { failure: "permission-denied", detail };
      }
      if (/timeout/i.test(detail)) return { failure: "timeout", detail };
      // A granted permission with the device switch off reports as a generic
      // failure, so the switch is the only way to tell the two apart.
      if (await isSystemLocationDisabled()) return { failure: "system-disabled", detail };
      return { failure: "unavailable", detail };
    }
  }

  if (typeof navigator === "undefined" || !navigator.geolocation) {
    return { failure: "runtime-unavailable" };
  }

  return new Promise<LocationResult>((resolve) => {
    navigator.geolocation.getCurrentPosition(
      (position) =>
        resolve({
          fix: {
            lat: position.coords.latitude,
            lon: position.coords.longitude,
            speedMps: position.coords.speed ?? undefined,
            headingDeg: position.coords.heading ?? undefined,
            accuracyM: position.coords.accuracy ?? undefined,
          },
        }),
      (error) => {
        switch (error.code) {
          case error.PERMISSION_DENIED:
            resolve({ failure: "permission-denied", detail: error.message });
            break;
          case error.TIMEOUT:
            resolve({ failure: "timeout", detail: error.message });
            break;
          default:
            resolve({ failure: "unavailable", detail: error.message });
        }
      },
      { enableHighAccuracy: true, timeout: 15_000, maximumAge: 5_000 },
    );
  });
}

/**
 * Read the device's battery level and charging state.
 *
 * The native plugin is asked first, because the webview's Battery Status API is
 * missing on some Android WebView builds. The browser API is the desktop
 * fallback. Returning `null` rather than a fake `0` lets the UI say "battery
 * unknown" instead of claiming the phone is dead.
 */
export async function readBattery(): Promise<{ pct: number; charging: boolean } | null> {
  try {
    const native = await api.batteryStatus();
    if (typeof native.pct === "number" && native.pct > 0) {
      return { pct: native.pct, charging: native.charging };
    }
  } catch {
    // No native bridge, or the platform declined; fall through to the webview.
  }

  if (typeof navigator === "undefined") return null;
  const battery = (navigator as Navigator & {
    getBattery?: () => Promise<{ level: number; charging: boolean }>;
  }).getBattery;
  if (typeof battery !== "function") return null;
  try {
    const status = await battery.call(navigator);
    if (!Number.isFinite(status.level)) return null;
    return {
      pct: Math.round(Math.min(1, Math.max(0, status.level)) * 100),
      charging: Boolean(status.charging),
    };
  } catch {
    return null;
  }
}

/** A message suitable for display, or `null` when nothing useful can be said. */
export function describeLocationFailure(failure: LocationFailure): string {
  switch (failure) {
    case "permission-denied":
      return "Location permission was denied. Enable it in system settings to share your position.";
    case "permission-prompt":
      return "Location permission has not been granted yet.";
    case "system-disabled":
      return "Location is turned off for this device. Turn it on in system settings to share your position.";
    case "timeout":
      return "Timed out waiting for a GPS fix. Move somewhere with a clearer view of the sky.";
    case "unavailable":
      return "No location is available on this device right now.";
    case "runtime-unavailable":
      return "This build has no location provider; the map still shows your group.";
  }
}

/**
 * The action that would actually fix a failure, or `null` when none would.
 *
 * A timeout or a missing provider is not something a settings screen can solve, so
 * offering one there would only send the user on a pointless trip.
 */
export function locationRemedy(failure: LocationFailure): LocationRemedy | null {
  switch (failure) {
    case "permission-denied":
      return "app-settings";
    case "permission-prompt":
      return "permission";
    case "system-disabled":
      return "system-settings";
    default:
      return null;
  }
}

/** Label for the button that applies a remedy. */
export function locationRemedyLabel(remedy: LocationRemedy): string {
  switch (remedy) {
    case "permission":
      return "Allow location";
    case "app-settings":
      return "Open app settings";
    case "system-settings":
      return "Open location settings";
  }
}

/**
 * Whether the device-wide location switch is off.
 *
 * Returns `false` when the platform cannot report it, so an unknown state never
 * blocks a fix attempt that might have worked.
 */
export async function isSystemLocationDisabled(): Promise<boolean> {
  const internals = (globalThis as { __TAURI_INTERNALS__?: unknown })
    .__TAURI_INTERNALS__;
  if (!internals) return false;
  try {
    const { invoke } = await import("@tauri-apps/api/core");
    const access = await invoke<{ systemLocationEnabled: boolean }>("location_access");
    return !access.systemLocationEnabled;
  } catch {
    return false;
  }
}

/**
 * Open the system screen that fixes the given remedy.
 *
 * Returns false when the platform has no such screen, so the caller can fall back
 * to explaining the steps instead of pretending something happened.
 */
export async function openLocationRemedy(remedy: LocationRemedy): Promise<boolean> {
  if (remedy === "permission") {
    // The system prompt is the fix here, not a settings screen.
    return requestLocationPermission();
  }
  const internals = (globalThis as { __TAURI_INTERNALS__?: unknown })
    .__TAURI_INTERNALS__;
  if (!internals) return false;
  try {
    const { invoke } = await import("@tauri-apps/api/core");
    await invoke("open_location_settings", { appPage: remedy === "app-settings" });
    return true;
  } catch {
    return false;
  }
}