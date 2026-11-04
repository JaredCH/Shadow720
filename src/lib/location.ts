/**
 * On-device location polling and permission handling.
 *
 * The Tauri geolocation plugin is used on Android, where it is backed by the real
 * platform provider. On desktop the plugin is a documented no-op that resolves to
 * a zeroed position without prompting, so the browser Geolocation API is used
 * instead; that is what makes the map work in a desktop preview.
 */

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

async function loadPlugin(): Promise<
  | {
      checkPermissions: () => Promise<string>;
      requestPermissions: () => Promise<string>;
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
      checkPermissions: () => Promise<string>;
      requestPermissions: () => Promise<string>;
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
  "granted" | "denied" | "prompt" | "prompt-with-rationale" | "runtime-unavailable"
> {
  const plugin = await loadPlugin();
  if (!plugin) {
    if (typeof navigator !== "undefined" && navigator.geolocation) return "prompt";
    return "runtime-unavailable";
  }
  try {
    const state = await plugin.checkPermissions();
    if (state === "granted" || state === "denied" || state === "prompt") return state;
    return "prompt-with-rationale";
  } catch {
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
    const state = await plugin.requestPermissions();
    return state === "granted";
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