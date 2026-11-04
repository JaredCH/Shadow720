import type { MemberView } from "../lib/api";
import { formatDistance, initials, readableOn, relativeAge } from "../lib/format";

interface MemberPinProps {
  member: MemberView;
  /** Metres from this device, when a self fix is available. */
  distanceM?: number;
  selected: boolean;
  onSelect: () => void;
}

/**
 * One member chip in the roster strip.
 *
 * Colour comes from the member's own `avatar_color`, which is generated on their
 * device; the readable-foreground helper keeps the initials legible against it.
 */
export function MemberPin({
  member,
  distanceM,
  selected,
  onSelect,
}: MemberPinProps) {
  const foreground = readableOn(member.avatarColor);

  return (
    <button
      type="button"
      onClick={onSelect}
      className={`flex w-full items-center gap-3 rounded-xl border p-3 text-left transition-colors ${
        selected
          ? "border-accent bg-surface"
          : "border-surface-border bg-surface-raised hover:border-accent-muted"
      }`}
    >
      <span
        className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-xs font-bold"
        style={{ backgroundColor: member.avatarColor, color: foreground }}
        aria-hidden
      >
        {initials(member.displayName)}
      </span>

      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-2">
          <span className="truncate text-sm font-semibold text-slate-100">
            {member.displayName || "Unnamed"}
          </span>
          {member.isSelf ? (
            <span className="pill bg-accent/20 text-accent">you</span>
          ) : null}
        </span>

        <span className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs text-slate-400">
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

      {member.isStale ? (
        <span className="pill bg-amber-950 text-amber-300" title="No update for 5+ minutes">
          stale
        </span>
      ) : (
        <span
          className="h-2 w-2 shrink-0 rounded-full bg-emerald-400"
          title="Recently updated"
          aria-label="Recently updated"
        />
      )}
    </button>
  );
}