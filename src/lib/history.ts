/**
 * Grouping and summarising helpers for the location history view.
 *
 * The track log is a flat list of points. Everything the history panel shows —
 * "today", "yesterday", "week of 3 Nov", "mostly driving" — is derived here, so
 * the panel itself stays a rendering concern.
 */

import type { Activity, TrackPoint } from "./api";

/** One day's worth of a member's track. */
export interface HistoryDay {
  /** Local midnight for the day, in milliseconds. */
  startMs: number;
  /** Points for the day, oldest first. */
  points: TrackPoint[];
  /** Total distance travelled that day, in metres. */
  distanceM: number;
  /** The activity the member spent the most time doing. */
  dominantActivity: Activity;
  /** Lowest battery reading seen that day, or `null` when never reported. */
  lowestBatteryPct: number | null;
  /** True when the member was charging at any point that day. */
  charged: boolean;
  /** First and last fix, for a "09:12 – 17:40" summary. */
  firstMs: number;
  lastMs: number;
}

/** A week of days, for the collapsed history list. */
export interface HistoryWeek {
  /** Local midnight of the Monday that starts the week. */
  startMs: number;
  days: HistoryDay[];
  distanceM: number;
}

const DAY_MS = 24 * 60 * 60 * 1_000;

/** Local midnight for the day containing `unixMs`. */
export function startOfDay(unixMs: number): number {
  const date = new Date(unixMs);
  date.setHours(0, 0, 0, 0);
  return date.getTime();
}

/** Local midnight of the Monday that starts the week containing `unixMs`. */
export function startOfWeek(unixMs: number): number {
  const date = new Date(startOfDay(unixMs));
  // `getDay()` is 0 for Sunday, so Sunday belongs to the week that started six
  // days earlier rather than to the next one.
  const offset = (date.getDay() + 6) % 7;
  date.setDate(date.getDate() - offset);
  return date.getTime();
}

/** Great-circle distance in metres. */
function haversine(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const earthRadius = 6_371_008.8;
  const toRad = (degrees: number) => (degrees * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return 2 * earthRadius * Math.asin(Math.min(1, Math.sqrt(a)));
}

/**
 * Total distance along a track.
 *
 * Segments longer than `maxGapM` are skipped: a member who was offline for six
 * hours did not teleport, and counting the gap would invent kilometres they never
 * travelled.
 */
export function trackDistance(points: TrackPoint[], maxGapM = 5_000): number {
  let total = 0;
  for (let index = 1; index < points.length; index += 1) {
    const previous = points[index - 1];
    const current = points[index];
    if (!previous || !current) continue;
    const segment = haversine(previous.lat, previous.lon, current.lat, current.lon);
    if (segment <= maxGapM) total += segment;
  }
  return total;
}

/** The activity with the most points, ignoring `still` unless it is all there is. */
function dominantActivity(points: TrackPoint[]): Activity {
  const counts = new Map<Activity, number>();
  for (const point of points) {
    counts.set(point.activity, (counts.get(point.activity) ?? 0) + 1);
  }
  let best: Activity = "still";
  let bestCount = -1;
  for (const [activity, count] of counts) {
    // Moving beats stationary on a tie, because "walking" is the more useful
    // answer for a day that was half one and half the other.
    const weight = activity === "still" ? count - 0.5 : count;
    if (weight > bestCount) {
      best = activity;
      bestCount = weight;
    }
  }
  return best;
}

/** Summarise one day's points. */
function summariseDay(startMs: number, points: TrackPoint[]): HistoryDay {
  const batteries = points
    .map((point) => point.batteryPct)
    .filter((pct) => pct > 0);
  return {
    startMs,
    points,
    distanceM: trackDistance(points),
    dominantActivity: dominantActivity(points),
    lowestBatteryPct: batteries.length > 0 ? Math.min(...batteries) : null,
    charged: points.some((point) => point.isCharging),
    firstMs: points[0]?.unixMs ?? startMs,
    lastMs: points[points.length - 1]?.unixMs ?? startMs,
  };
}

/** Group a track into days, newest day first. */
export function groupByDay(points: TrackPoint[]): HistoryDay[] {
  const buckets = new Map<number, TrackPoint[]>();
  for (const point of points) {
    const day = startOfDay(point.unixMs);
    const bucket = buckets.get(day);
    if (bucket) bucket.push(point);
    else buckets.set(day, [point]);
  }
  return [...buckets.entries()]
    .sort((a, b) => b[0] - a[0])
    .map(([startMs, dayPoints]) => summariseDay(startMs, dayPoints));
}

/** Group days into weeks, newest week first. */
export function groupByWeek(days: HistoryDay[]): HistoryWeek[] {
  const buckets = new Map<number, HistoryDay[]>();
  for (const day of days) {
    const week = startOfWeek(day.startMs);
    const bucket = buckets.get(week);
    if (bucket) bucket.push(day);
    else buckets.set(week, [day]);
  }
  return [...buckets.entries()]
    .sort((a, b) => b[0] - a[0])
    .map(([startMs, weekDays]) => ({
      startMs,
      days: weekDays.sort((a, b) => b.startMs - a.startMs),
      distanceM: weekDays.reduce((total, day) => total + day.distanceM, 0),
    }));
}

/** "Today", "Yesterday", or a short date. */
export function describeDay(startMs: number, nowMs = Date.now()): string {
  const today = startOfDay(nowMs);
  if (startMs === today) return "Today";
  if (startMs === today - DAY_MS) return "Yesterday";
  return new Date(startMs).toLocaleDateString(undefined, {
    weekday: "short",
    day: "numeric",
    month: "short",
  });
}

/** "This week", "Last week", or a date range. */
export function describeWeek(startMs: number, nowMs = Date.now()): string {
  const thisWeek = startOfWeek(nowMs);
  if (startMs === thisWeek) return "This week";
  if (startMs === thisWeek - 7 * DAY_MS) return "Last week";
  const start = new Date(startMs);
  const end = new Date(startMs + 6 * DAY_MS);
  const sameMonth = start.getMonth() === end.getMonth();
  const startLabel = start.toLocaleDateString(undefined, {
    day: "numeric",
    month: sameMonth ? undefined : "short",
  });
  const endLabel = end.toLocaleDateString(undefined, { day: "numeric", month: "short" });
  return `${startLabel} – ${endLabel}`;
}

/** Icon and label for an activity, shared with the map. */
export function describeActivity(activity: Activity): { icon: string; label: string } {
  switch (activity) {
    case "walking":
      return { icon: "🚶", label: "Walking" };
    case "running":
      return { icon: "🏃", label: "Running" };
    case "cycling":
      return { icon: "🚴", label: "Cycling" };
    case "driving":
      return { icon: "🚗", label: "Driving" };
    default:
      return { icon: "📍", label: "Stationary" };
  }
}

/** Colour for a battery level, so a dying phone is obvious at a glance. */
export function batteryTone(pct: number): string {
  if (pct <= 0) return "text-slate-500";
  if (pct <= 15) return "text-rose-400";
  if (pct <= 30) return "text-amber-400";
  return "text-emerald-400";
}
