import { useEffect, useMemo, useRef, useState } from "react";
import type { Activity, MemberView, TrailPoint } from "../lib/api";
import { formatDistance, readableOn, relativeAge } from "../lib/format";
import { PeerMap } from "./PeerMap";

/**
 * Track the operating system's colour scheme.
 *
 * The map basemap follows this rather than a manual toggle, so the app matches
 * whatever the phone or desktop is already doing.
 */
function useColorScheme(): "dark" | "streets" {
  const query = "(prefers-color-scheme: light)";
  const [light, setLight] = useState(
    () => typeof window !== "undefined" && window.matchMedia(query).matches,
  );

  useEffect(() => {
    const media = window.matchMedia(query);
    const onChange = (event: MediaQueryListEvent) => setLight(event.matches);
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, []);

  return light ? "streets" : "dark";
}

/** Icon and label for a member's activity. */
function describeActivity(activity: Activity): { icon: string; label: string } {
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

interface MapPanelProps {
  members: MemberView[];
  /** This device's own fix, from the local cache rather than the network. */
  selfFix: { lat: number; lon: number } | null;
  /** Recent positions per member public key, oldest first. */
  trails: Record<string, TrailPoint[]>;
  selectedPubkey: string | null;
  onSelect: (pubkeyB64: string | null) => void;
}

/**
 * Map tab: an OpenStreetMap canvas plus a roster list.
 *
 * The basemap follows the operating system's colour scheme rather than offering a
 * manual switch: a map that ignores the user's theme is the odd one out on a phone
 * that is otherwise entirely light or entirely dark.
 */
export function MapPanel({
  members,
  selfFix,
  trails,
  selectedPubkey,
  onSelect,
}: MapPanelProps) {
  const basemap = useColorScheme();
  const [followSelf, setFollowSelf] = useState(true);
  const listRef = useRef<HTMLDivElement | null>(null);

  // The reference point is this device's fix when known, otherwise the median of
  // the group. A world view is the fallback so the map is always visible: an empty
  // canvas with no explanation was the previous behaviour, and it read as broken.
  const anchor = useMemo(() => {
    if (selfFix) return selfFix;
    if (members.length === 0) return { lat: 20, lon: 0 };
    const lats = members.map((member) => member.lat).sort((a, b) => a - b);
    const lons = members.map((member) => member.lon).sort((a, b) => a - b);
    const middle = Math.floor(members.length / 2);
    return {
      lat: lats[middle] ?? 0,
      lon: lons[middle] ?? 0,
    };
  }, [members, selfFix]);

  /** True when the view is a placeholder rather than a real position. */
  const hasPosition = selfFix !== null || members.length > 0;

  const distances = useMemo(() => {
    const map = new Map<string, number>();
    if (!selfFix) return map;
    for (const member of members) {
      const metres = haversine(
        selfFix.lat,
        selfFix.lon,
        member.lat,
        member.lon,
      );
      map.set(member.pubkeyB64, metres);
    }
    return map;
  }, [members, selfFix]);

  // Keep the selected member scrolled into view when selection changes from the
  // map, so the two panes cannot disagree about what is focused.
  useEffect(() => {
    if (!selectedPubkey || !listRef.current) return;
    const target = listRef.current.querySelector<HTMLElement>(
      `[data-pubkey="${CSS.escape(selectedPubkey)}"]`,
    );
    target?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [selectedPubkey]);

  return (
    <div className="flex h-full flex-col gap-3">
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs text-slate-500">
          {members.length === 0
            ? "No positions yet"
            : `${members.length} ${members.length === 1 ? "member" : "members"}`}
        </span>

        <button
          type="button"
          onClick={() => setFollowSelf((previous) => !previous)}
          className={`rounded-xl border px-3 py-1.5 text-xs font-medium ${
            followSelf
              ? "border-accent bg-accent/15 text-accent"
              : "border-surface-border bg-surface-raised text-slate-400"
          }`}
          title="Keep the view centred on your own position"
        >
          {followSelf ? "Following you" : "Free view"}
        </button>
      </div>

      <div className="relative h-[46vh] min-h-[240px] overflow-hidden rounded-2xl border border-surface-border bg-surface">
        <PeerMap
          members={members}
          selfFix={selfFix}
          trails={trails}
          anchor={anchor}
          followSelf={followSelf}
          selectedPubkey={selectedPubkey}
          onSelect={onSelect}
          basemap={basemap}
          placeholderZoom={hasPosition ? undefined : 2}
        />

        {!hasPosition ? (
          <div className="pointer-events-none absolute inset-x-0 bottom-0 bg-gradient-to-t from-surface to-transparent p-4 text-center text-xs text-slate-400">
            Waiting for the first location update. Pan and zoom to explore.
          </div>
        ) : null}
      </div>

      <div ref={listRef} className="min-h-0 flex-1 space-y-2 overflow-y-auto pb-2">
        {members.length === 0 ? (
          <p className="card text-center text-sm text-slate-400">
            Nobody has shared a position yet.
          </p>
        ) : (
          members.map((member) => {
            const selected = member.pubkeyB64 === selectedPubkey;
            const foreground = readableOn(member.avatarColor);
            const distanceM = distances.get(member.pubkeyB64);

            return (
              <button
                key={member.pubkeyB64}
                data-pubkey={member.pubkeyB64}
                type="button"
                onClick={() =>
                  onSelect(selected ? null : member.pubkeyB64)
                }
                className={`flex w-full items-center gap-3 rounded-xl border p-3 text-left ${
                  selected
                    ? "border-accent bg-surface"
                    : "border-surface-border bg-surface-raised"
                }`}
              >
                <span
                  className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-xs font-bold"
                  style={{ backgroundColor: member.avatarColor, color: foreground }}
                  aria-hidden
                >
                  {member.displayName.slice(0, 2).toUpperCase() || "?"}
                </span>

                <span className="min-w-0 flex-1">
                  <span className="flex items-center gap-2">
                    <span className="truncate text-sm font-semibold text-slate-100">
                      {member.displayName || "Unnamed"}
                    </span>
                    {member.isSelf ? (
                      <span className="pill bg-accent/20 text-accent">you</span>
                    ) : null}
                    {member.isStale ? (
                      <span className="pill bg-amber-950 text-amber-300">stale</span>
                    ) : null}
                  </span>
                  <span className="mt-0.5 flex flex-wrap items-center gap-x-2 text-xs text-slate-400">
                    <span title={describeActivity(member.activity).label}>
                      {describeActivity(member.activity).icon}{" "}
                      {describeActivity(member.activity).label}
                    </span>
                    <span aria-hidden>·</span>
                    <span>{relativeAge(member.unixMs)}</span>
                    {typeof distanceM === "number" ? (
                      <>
                        <span aria-hidden>·</span>
                        <span>{formatDistance(distanceM)}</span>
                      </>
                    ) : null}
                    <span aria-hidden>·</span>
                    <span>
                      {member.batteryPct}%{member.isCharging ? " ⚡" : ""}
                    </span>
                  </span>
                </span>

                <span className="shrink-0 text-right font-mono text-[10px] text-slate-500">
                  {member.lat.toFixed(3)}
                  <br />
                  {member.lon.toFixed(3)}
                </span>
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}

/** Great-circle distance in metres. Duplicated deliberately from `format.ts`. */
function haversine(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const earthRadius = 6_371_008.8;
  const toRad = (degrees: number) => (degrees * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return 2 * earthRadius * Math.asin(Math.min(1, Math.sqrt(a)));
}