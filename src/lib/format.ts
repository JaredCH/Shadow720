/** Small formatting helpers shared across the UI. */

/** Two-letter initials for an avatar, derived from a display name. */
export function initials(displayName: string): string {
  const parts = displayName.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "?";
  if (parts.length === 1) {
    const only = parts[0] ?? "";
    return only.slice(0, 2).toUpperCase();
  }
  const first = parts[0] ?? "";
  const last = parts[parts.length - 1] ?? "";
  return `${first.slice(0, 1)}${last.slice(0, 1)}`.toUpperCase();
}

/** Relative age, e.g. "just now", "4m ago". */
export function relativeAge(unixMs: number, nowMs = Date.now()): string {
  if (unixMs <= 0) return "unknown";
  const seconds = Math.max(0, Math.floor((nowMs - unixMs) / 1000));
  if (seconds < 10) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

/** Clock time, e.g. "14:03". */
export function clockTime(unixMs: number): string {
  if (unixMs <= 0) return "";
  const date = new Date(unixMs);
  return date.toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** Byte count in the largest sensible unit. */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "?";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} kB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

/** Shorten a Base64 public key for display. */
export function shortKey(pubkeyB64: string): string {
  if (pubkeyB64.length <= 12) return pubkeyB64;
  return `${pubkeyB64.slice(0, 6)}…${pubkeyB64.slice(-4)}`;
}

/** Format a duration in seconds as a compact phrase. */
export function formatDuration(seconds: number): string {
  if (seconds <= 0) return "now";
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  if (minutes < 60) {
    return remainder > 0 ? `${minutes}m ${remainder}s` : `${minutes}m`;
  }
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}

/** Pick a readable foreground colour for text drawn on `background`. */
export function readableOn(background: string): string {
  const hex = background.replace("#", "");
  if (hex.length !== 6) return "#ffffff";
  const r = parseInt(hex.slice(0, 2), 16);
  const g = parseInt(hex.slice(2, 4), 16);
  const b = parseInt(hex.slice(4, 6), 16);
  if ([r, g, b].some((value) => Number.isNaN(value))) return "#ffffff";
  // Rec. 709 luma.
  const luma = (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255;
  return luma > 0.6 ? "#0b1020" : "#ffffff";
}

/** Total distance between two coordinates, using the haversine formula. */
export function distanceMetres(
  lat1: number,
  lon1: number,
  lat2: number,
  lon2: number,
): number {
  const earthRadius = 6_371_008.8;
  const toRad = (degrees: number) => (degrees * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return 2 * earthRadius * Math.asin(Math.min(1, Math.sqrt(a)));
}

/** Human-readable distance. */
export function formatDistance(metres: number): string {
  if (metres < 1000) return `${Math.round(metres)} m`;
  return `${(metres / 1000).toFixed(1)} km`;
}

/**
 * Convert a `Blob`/`File` to the `number[]` shape the Rust command expects.
 *
 * `Array.from` on an `ArrayBuffer` needs the byte view, not the buffer itself,
 * otherwise the numbers come back as typed-array indices.
 */
export async function fileToBytes(file: File): Promise<number[]> {
  const buffer = await file.arrayBuffer();
  return Array.from(new Uint8Array(buffer));
}

/** Turn decrypted bytes back into a downloadable object URL. */
export function bytesToObjectUrl(bytes: number[], mime: string): string {
  const view = new Uint8Array(bytes);
  return URL.createObjectURL(new Blob([view], { type: mime }));
}