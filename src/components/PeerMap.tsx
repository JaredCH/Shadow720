import { useEffect, useRef } from "react";
import type { MemberView, TrailPoint } from "../lib/api";
import {
  TILE_SIZE,
  latToWorldY,
  lonToWorldX,
  tileUrl,
  worldXToLon,
  worldYToLat,
  wrapTileX,
} from "../lib/tiles";

interface PeerMapProps {
  members: MemberView[];
  selfFix: { lat: number; lon: number } | null;
  /** Recent positions per member public key, oldest first. */
  trails: Record<string, TrailPoint[]>;
  /** Centre of the viewport when not following self. */
  anchor: { lat: number; lon: number };
  followSelf: boolean;
  selectedPubkey: string | null;
  onSelect: (pubkeyB64: string | null) => void;
  basemap: "streets" | "dark";
  /** Zoom to use when there is no real position to centre on. */
  placeholderZoom?: number;
  /**
   * A member to fly to. Changing this value re-centres the map on that member
   * and zooms in, which is what makes tapping a name in the roster useful.
   */
  focus?: { pubkeyB64: string; nonce: number } | null;
  /** Extra track to draw under the pins, e.g. a selected member's history. */
  historyTrack?: { points: TrailPoint[]; colour: string } | null;
}

/** Hit-test radius for tapping a pin, in CSS pixels. */
const PIN_HIT_RADIUS_PX = 26;
/** Zoom used before the user has interacted. */
const DEFAULT_ZOOM = 14;
/** Zoom used when flying to a member from the roster. */
const FOCUS_ZOOM = 16;
const MIN_ZOOM = 2;
const MAX_ZOOM = 19;

/**
 * Canvas map with an OpenStreetMap raster basemap.
 *
 * Tiles are drawn on a canvas rather than through a map library so the app keeps
 * one projection, one gesture model, and no extra dependency. The `none` basemap
 * skips the network entirely, which is the offline and privacy-preserving mode.
 */
export function PeerMap({
  members,
  selfFix,
  trails,
  anchor,
  followSelf,
  selectedPubkey,
  onSelect,
  basemap,
  placeholderZoom,
  focus,
  historyTrack,
}: PeerMapProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const stateRef = useRef({
    centreLat: anchor.lat,
    centreLon: anchor.lon,
    zoom: placeholderZoom ?? DEFAULT_ZOOM,
    dragging: false,
    lastX: 0,
    lastY: 0,
    movedDuringDrag: false,
    /** Every pointer currently down, so a second finger can start a pinch. */
    pointers: new Map<number, { x: number; y: number }>(),
    /** Finger separation when the current pinch began, in CSS pixels. */
    pinchDistance: 0,
    /** Zoom when the current pinch began. */
    pinchZoom: 0,
    /** Map point under the pinch midpoint, held fixed while the fingers move. */
    pinchAnchor: null as { lon: number; lat: number } | null,
  });
  /** Decoded tiles, keyed by `z/x/y`, so a redraw does not refetch. */
  const tileCache = useRef(new Map<string, HTMLImageElement>());
  const renderRef = useRef<() => void>(() => {});

  // Reset the viewport when the anchor moves and following is enabled.
  useEffect(() => {
    if (!followSelf) return;
    const state = stateRef.current;
    state.centreLat = anchor.lat;
    state.centreLon = anchor.lon;
    renderRef.current();
  }, [anchor.lat, anchor.lon, followSelf]);

  // Fly to a member when the roster asks for it.
  //
  // The `nonce` is what makes this fire on every tap: selecting the same member
  // twice must re-centre the map, and a bare pubkey would not change.
  useEffect(() => {
    if (!focus) return;
    const member = members.find((candidate) => candidate.pubkeyB64 === focus.pubkeyB64);
    if (!member) return;
    const state = stateRef.current;
    state.centreLat = member.lat;
    state.centreLon = member.lon;
    // Zoom in far enough to see streets, but never zoom *out* on a user who had
    // already zoomed in further.
    state.zoom = Math.max(state.zoom, FOCUS_ZOOM);
    renderRef.current();
  }, [focus, members]);

  // The placeholder zoom is only a starting point. Once a real position arrives
  // the view has to zoom in, otherwise the first fix leaves the map at world scale.
  useEffect(() => {
    stateRef.current.zoom = placeholderZoom ?? DEFAULT_ZOOM;
    renderRef.current();
  }, [placeholderZoom]);

  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    const render = () => {
      const state = stateRef.current;
      const rect = container.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);

      const width = Math.max(1, Math.floor(rect.width * dpr));
      const height = Math.max(1, Math.floor(rect.height * dpr));
      if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width;
        canvas.height = height;
      }
      canvas.style.width = `${rect.width}px`;
      canvas.style.height = `${rect.height}px`;

      const context = canvas.getContext("2d");
      if (!context) return;

      const cssWidth = rect.width;
      const cssHeight = rect.height;

      // Exposed for the gesture harness in scripts/pinch-harness, which drives
      // real touch events and needs to assert on the resulting zoom.
      (canvas as HTMLCanvasElement & { dataset: DOMStringMap }).dataset.zoom =
        state.zoom.toFixed(3);

      // Fractional zoom keeps wheel and pinch smooth; tiles only exist at integer
      // levels, so the nearest one is scaled to fit.
      const tileZoom = Math.round(state.zoom);
      const scale = 2 ** (state.zoom - tileZoom);

      const centreX = lonToWorldX(state.centreLon, tileZoom);
      const centreY = latToWorldY(state.centreLat, tileZoom);
      const left = centreX - cssWidth / 2 / scale;
      const top = centreY - cssHeight / 2 / scale;

      context.fillStyle = basemap === "streets" ? "#e8eef5" : "#0b1020";
      context.fillRect(0, 0, width, height);

      {
        const firstX = Math.floor(left / TILE_SIZE);
        const lastX = Math.floor((left + cssWidth / scale) / TILE_SIZE);
        const firstY = Math.floor(top / TILE_SIZE);
        const lastY = Math.floor((top + cssHeight / scale) / TILE_SIZE);
        const maxTile = 2 ** tileZoom;

        for (let tileY = firstY; tileY <= lastY; tileY += 1) {
          if (tileY < 0 || tileY >= maxTile) continue;
          for (let tileX = firstX; tileX <= lastX; tileX += 1) {
            const wrappedX = wrapTileX(tileX, tileZoom);
            const key = `${tileZoom}/${wrappedX}/${tileY}`;
            const screenX = (tileX * TILE_SIZE - left) * scale * dpr;
            const screenY = (tileY * TILE_SIZE - top) * scale * dpr;
            const size = TILE_SIZE * scale * dpr;

            const cached = tileCache.current.get(key);
            if (cached?.complete && cached.naturalWidth > 0) {
              context.drawImage(cached, screenX, screenY, size, size);
              continue;
            }
            if (!cached) {
              const image = new Image();
              image.crossOrigin = "anonymous";
              image.decoding = "async";
              image.src = tileUrl(wrappedX, tileY, tileZoom);
              // A late tile only needs a repaint, not a state change.
              image.onload = () => renderRef.current();
              tileCache.current.set(key, image);
            }
          }
        }

        // Dark mode is a filter over the tiles rather than a second tile source,
        // so there is only one provider to credit and rate-limit against.
        if (basemap === "dark") {
          context.fillStyle = "rgba(8,12,24,0.62)";
          context.fillRect(0, 0, width, height);
        }
      }

      const metresPerPixel =
        (156_543 * Math.cos((state.centreLat * Math.PI) / 180)) /
        (TILE_SIZE * 2 ** tileZoom * scale * dpr);

      const toScreen = (lat: number, lon: number) => ({
        x: (lonToWorldX(lon, tileZoom) - left) * scale * dpr,
        y: (latToWorldY(lat, tileZoom) - top) * scale * dpr,
      });

      // Range rings around this device's position, at 1/2 and 2 km.
      if (selfFix) {
        const origin = toScreen(selfFix.lat, selfFix.lon);
        const ringColour =
          basemap === "streets" ? "rgba(15,23,42,0.22)" : "rgba(148,163,184,0.30)";

        for (const ringM of [500, 1_000, 2_000]) {
          const radius = ringM / metresPerPixel;
          if (radius < 12 || radius > Math.max(width, height)) continue;
          context.beginPath();
          context.arc(origin.x, origin.y, radius, 0, Math.PI * 2);
          context.strokeStyle = ringColour;
          context.lineWidth = 1 * dpr;
          context.setLineDash([4 * dpr, 4 * dpr]);
          context.stroke();
          context.setLineDash([]);
        }
      }

      // A selected member's longer history sits under everything else, so the
      // recent trail and the pin stay readable on top of it.
      if (historyTrack && historyTrack.points.length >= 2) {
        const points = historyTrack.points;
        context.beginPath();
        for (let index = 0; index < points.length; index += 1) {
          const point = points[index];
          if (!point) continue;
          const screen = toScreen(point.lat, point.lon);
          if (index === 0) context.moveTo(screen.x, screen.y);
          else context.lineTo(screen.x, screen.y);
        }
        context.strokeStyle = withAlpha(historyTrack.colour, 0.28);
        context.lineWidth = 2 * dpr;
        context.lineCap = "round";
        context.lineJoin = "round";
        context.stroke();
      }

      // Trails sit under the pins so a pin is never obscured by its own history.
      // Each segment fades with age, which is what makes the direction of travel
      // readable at a glance: the bright end is where the member is now.
      for (const member of members) {
        const points = trails[member.pubkeyB64];
        if (!points || points.length < 2) continue;
        const selected = member.pubkeyB64 === selectedPubkey;
        const baseWidth = (selected ? 3.5 : 2.5) * dpr;

        for (let index = 1; index < points.length; index += 1) {
          const previous = points[index - 1];
          const current = points[index];
          if (!previous || !current) continue;
          const from = toScreen(previous.lat, previous.lon);
          const to = toScreen(current.lat, current.lon);
          // 0 at the oldest point, 1 at the newest.
          const progress = index / (points.length - 1);
          context.beginPath();
          context.moveTo(from.x, from.y);
          context.lineTo(to.x, to.y);
          context.strokeStyle = withAlpha(member.avatarColor, 0.08 + progress * 0.72);
          context.lineWidth = baseWidth * (0.45 + progress * 0.55);
          context.lineCap = "round";
          context.stroke();
        }

        // A heading arrow on the newest segment, so a moving member's direction
        // is readable without tracing the whole line.
        const newest = points[points.length - 1];
        const previous = points[points.length - 2];
        if (newest && previous && member.speedMps > 1.0) {
          const from = toScreen(previous.lat, previous.lon);
          const to = toScreen(newest.lat, newest.lon);
          drawArrow(context, from, to, member.avatarColor, dpr);
        }
      }

      // Stale members first, so a fresh pin is never hidden behind an old one.
      const ordered = [...members].sort(
        (a, b) => Number(b.isStale) - Number(a.isStale),
      );

      for (const member of ordered) {
        const point = toScreen(member.lat, member.lon);
        const radius = (member.isSelf ? 11 : 9) * dpr;
        const selected = member.pubkeyB64 === selectedPubkey;

        // Accuracy halo.
        if (member.accuracyM > 0) {
          const accuracyRadius = member.accuracyM / metresPerPixel;
          if (accuracyRadius > radius && accuracyRadius < Math.max(width, height)) {
            context.beginPath();
            context.arc(point.x, point.y, accuracyRadius, 0, Math.PI * 2);
            context.fillStyle = `${member.avatarColor}22`;
            context.fill();
          }
        }

        if (selected) {
          context.beginPath();
          context.arc(point.x, point.y, radius + 5 * dpr, 0, Math.PI * 2);
          context.strokeStyle = "#5b8cff";
          context.lineWidth = 2.5 * dpr;
          context.stroke();
        }

        context.beginPath();
        context.arc(point.x, point.y, radius, 0, Math.PI * 2);
        context.fillStyle = member.isStale
          ? withAlpha(member.avatarColor, 0.45)
          : member.avatarColor;
        context.fill();
        context.strokeStyle = "#0b1020";
        context.lineWidth = 2 * dpr;
        context.stroke();

        // Initials.
        const label = (member.displayName.slice(0, 2) || "?").toUpperCase();
        context.fillStyle = "#0b1020";
        context.font = `bold ${9 * dpr}px ui-sans-serif, system-ui, sans-serif`;
        context.textAlign = "center";
        context.textBaseline = "middle";
        context.fillText(label, point.x, point.y + 0.5 * dpr);

        // Name plate when selected or when the pin is this device.
        if (selected || member.isSelf) {
          const name = member.isSelf ? "You" : member.displayName || "Member";
          context.font = `${10 * dpr}px ui-sans-serif, system-ui, sans-serif`;
          const textWidth = context.measureText(name).width;
          const padding = 5 * dpr;
          const boxWidth = textWidth + padding * 2;
          const boxHeight = 16 * dpr;
          const boxX = point.x - boxWidth / 2;
          const boxY = point.y - radius - boxHeight - 3 * dpr;

          context.fillStyle = "rgba(11,16,32,0.92)";
          roundRect(context, boxX, boxY, boxWidth, boxHeight, 5 * dpr);
          context.fill();

          context.fillStyle = "#e2e8f0";
          context.fillText(name, point.x, boxY + boxHeight / 2);
        }
      }
    };

    renderRef.current = render;
    render();

    const observer = new ResizeObserver(render);
    observer.observe(container);

    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      const state = stateRef.current;
      const factor = event.deltaY < 0 ? 1.2 : 1 / 1.2;
      state.zoom = clamp(state.zoom + Math.log2(factor), MIN_ZOOM, MAX_ZOOM);
      render();
    };

    container.addEventListener("wheel", onWheel, { passive: false });
    return () => {
      observer.disconnect();
      container.removeEventListener("wheel", onWheel);
    };
  }, [members, selfFix, trails, selectedPubkey, basemap, historyTrack]);

  // -- pointer interaction --------------------------------------------------

  /** The two pointers driving a pinch, or `null` when fewer than two are down. */
  const pinchPair = (): [{ x: number; y: number }, { x: number; y: number }] | null => {
    const pointers = [...stateRef.current.pointers.values()];
    const [first, second] = pointers;
    if (!first || !second) return null;
    return [first, second];
  };

  /** Convert a client-space point into a lon/lat under the current viewport. */
  const pointToLonLat = (clientX: number, clientY: number) => {
    const container = containerRef.current;
    if (!container) return null;
    const rect = container.getBoundingClientRect();
    const state = stateRef.current;
    const tileZoom = Math.round(state.zoom);
    const scale = 2 ** (state.zoom - tileZoom);
    const left = lonToWorldX(state.centreLon, tileZoom) - rect.width / 2 / scale;
    const top = latToWorldY(state.centreLat, tileZoom) - rect.height / 2 / scale;

    return {
      lon: worldXToLon(left + (clientX - rect.left) / scale, tileZoom),
      lat: worldYToLat(top + (clientY - rect.top) / scale, tileZoom),
    };
  };

  const handlePointerDown = (event: React.PointerEvent<HTMLCanvasElement>) => {
    const state = stateRef.current;
    state.pointers.set(event.pointerId, { x: event.clientX, y: event.clientY });
    event.currentTarget.setPointerCapture(event.pointerId);

    const pair = pinchPair();
    if (pair) {
      // A second finger turns the drag into a pinch. The map point under the
      // midpoint stays put, so the map zooms around the fingers rather than
      // around the centre of the screen.
      state.dragging = false;
      state.movedDuringDrag = true;
      state.pinchDistance = Math.hypot(pair[0].x - pair[1].x, pair[0].y - pair[1].y);
      state.pinchZoom = state.zoom;
      state.pinchAnchor = pointToLonLat(
        (pair[0].x + pair[1].x) / 2,
        (pair[0].y + pair[1].y) / 2,
      );
      return;
    }

    state.dragging = true;
    state.movedDuringDrag = false;
    state.lastX = event.clientX;
    state.lastY = event.clientY;
  };

  const handlePointerMove = (event: React.PointerEvent<HTMLCanvasElement>) => {
    const state = stateRef.current;
    if (!state.pointers.has(event.pointerId)) return;
    state.pointers.set(event.pointerId, { x: event.clientX, y: event.clientY });

    const pair = pinchPair();
    if (pair) {
      const container = containerRef.current;
      if (!container || state.pinchDistance <= 0) return;

      const distance = Math.hypot(pair[0].x - pair[1].x, pair[0].y - pair[1].y);
      if (distance <= 0) return;

      // Fingers further apart means a larger scale, which is a higher zoom.
      const next = clamp(
        state.pinchZoom + Math.log2(distance / state.pinchDistance),
        MIN_ZOOM,
        MAX_ZOOM,
      );
      state.zoom = next;

      // Re-centre so the anchored point stays under the midpoint, which also
      // makes a two-finger drag pan while it zooms.
      const anchor = state.pinchAnchor;
      if (anchor) {
        const rect = container.getBoundingClientRect();
        const tileZoom = Math.round(next);
        const scale = 2 ** (next - tileZoom);
        const midX = (pair[0].x + pair[1].x) / 2 - rect.left;
        const midY = (pair[0].y + pair[1].y) / 2 - rect.top;

        const centreX = lonToWorldX(anchor.lon, tileZoom) - (midX - rect.width / 2) / scale;
        const centreY = latToWorldY(anchor.lat, tileZoom) - (midY - rect.height / 2) / scale;
        state.centreLon = worldXToLon(centreX, tileZoom);
        state.centreLat = worldYToLat(centreY, tileZoom);
      }

      renderRef.current();
      return;
    }

    if (!state.dragging) return;

    const tileZoom = Math.round(state.zoom);
    const scale = 2 ** (state.zoom - tileZoom);

    const dx = event.clientX - state.lastX;
    const dy = event.clientY - state.lastY;
    if (Math.abs(dx) + Math.abs(dy) > 2) state.movedDuringDrag = true;

    // Convert the drag in CSS pixels back into world pixels at the tile zoom.
    const centreX = lonToWorldX(state.centreLon, tileZoom) - dx / scale;
    const centreY = latToWorldY(state.centreLat, tileZoom) - dy / scale;

    state.centreLon = worldXToLon(centreX, tileZoom);
    state.centreLat = worldYToLat(centreY, tileZoom);

    state.lastX = event.clientX;
    state.lastY = event.clientY;
    renderRef.current();
  };

  const handlePointerUp = (event: React.PointerEvent<HTMLCanvasElement>) => {
    const state = stateRef.current;
    const wasPinching = state.pointers.size > 1;
    state.pointers.delete(event.pointerId);

    // Lifting one finger of a pinch must not be read as a tap on a pin, and the
    // remaining finger must not jump the map by the distance it moved.
    if (wasPinching) {
      state.pinchAnchor = null;
      state.pinchDistance = 0;
      const remaining = [...state.pointers.values()][0];
      if (remaining) {
        // Hand the gesture back to the surviving finger so the map keeps
        // panning instead of freezing until it is lifted and pressed again.
        state.dragging = true;
        state.movedDuringDrag = true;
        state.lastX = remaining.x;
        state.lastY = remaining.y;
      } else {
        state.dragging = false;
      }
      return;
    }

    state.dragging = false;
    if (!state.movedDuringDrag) {
      onSelect(hitTest(event));
    }
  };

  /** A cancelled pointer must not be treated as a tap. */
  const handlePointerCancel = (event: React.PointerEvent<HTMLCanvasElement>) => {
    const state = stateRef.current;
    state.pointers.delete(event.pointerId);
    state.dragging = false;
    state.pinchAnchor = null;
    state.pinchDistance = 0;
  };

  const hitTest = (event: React.PointerEvent<HTMLCanvasElement>): string | null => {
    const container = containerRef.current;
    if (!container) return null;
    const rect = container.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;

    const state = stateRef.current;
    const tileZoom = Math.round(state.zoom);
    const scale = 2 ** (state.zoom - tileZoom);
    const left = lonToWorldX(state.centreLon, tileZoom) - rect.width / 2 / scale;
    const top = latToWorldY(state.centreLat, tileZoom) - rect.height / 2 / scale;

    for (const member of members) {
      const px = (lonToWorldX(member.lon, tileZoom) - left) * scale;
      const py = (latToWorldY(member.lat, tileZoom) - top) * scale;
      if (Math.hypot(px - x, py - y) <= PIN_HIT_RADIUS_PX) return member.pubkeyB64;
    }
    return null;
  };

  // Double-tap to zoom, matching map conventions.
  const handleDoubleClick = () => {
    const state = stateRef.current;
    state.zoom = clamp(state.zoom + 1, MIN_ZOOM, MAX_ZOOM);
    renderRef.current();
  };

  return (
    <div ref={containerRef} className="relative h-full w-full touch-none">
      <canvas
        ref={canvasRef}
        className="h-full w-full cursor-grab active:cursor-grabbing"
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
        onPointerCancel={handlePointerCancel}
        onDoubleClick={handleDoubleClick}
      />
      <a
        href="https://www.openstreetmap.org/copyright"
        target="_blank"
        rel="noreferrer"
        className="absolute bottom-1 right-1 rounded bg-black/55 px-1.5 py-0.5 text-[9px] text-slate-300 hover:text-white"
      >
        © OpenStreetMap
      </a>
    </div>
  );
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

/**
 * Draw a small arrowhead at the end of a segment.
 *
 * A fading line shows where someone has been; the arrow shows which way they are
 * going right now, which is the question a live map is usually asked.
 */
function drawArrow(
  context: CanvasRenderingContext2D,
  from: { x: number; y: number },
  to: { x: number; y: number },
  colour: string,
  dpr: number,
) {
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const length = Math.hypot(dx, dy);
  // Too short to have a meaningful direction.
  if (length < 6 * dpr) return;

  const angle = Math.atan2(dy, dx);
  const size = 7 * dpr;
  const spread = Math.PI / 7;

  context.beginPath();
  context.moveTo(to.x, to.y);
  context.lineTo(
    to.x - size * Math.cos(angle - spread),
    to.y - size * Math.sin(angle - spread),
  );
  context.lineTo(
    to.x - size * Math.cos(angle + spread),
    to.y - size * Math.sin(angle + spread),
  );
  context.closePath();
  context.fillStyle = withAlpha(colour, 0.95);
  context.fill();
}

/** Apply an alpha to a `#rrggbb` colour. */
function withAlpha(colour: string, alpha: number): string {
  const hex = colour.replace("#", "");
  if (hex.length !== 6) return colour;
  const r = parseInt(hex.slice(0, 2), 16);
  const g = parseInt(hex.slice(2, 4), 16);
  const b = parseInt(hex.slice(4, 6), 16);
  if ([r, g, b].some((value) => Number.isNaN(value))) return colour;
  return `rgba(${r},${g},${b},${alpha})`;
}

function roundRect(
  context: CanvasRenderingContext2D,
  x: number,
  y: number,
  width: number,
  height: number,
  radius: number,
) {
  context.beginPath();
  context.moveTo(x + radius, y);
  context.lineTo(x + width - radius, y);
  context.quadraticCurveTo(x + width, y, x + width, y + radius);
  context.lineTo(x + width, y + height - radius);
  context.quadraticCurveTo(x + width, y + height, x + width - radius, y + height);
  context.lineTo(x + radius, y + height);
  context.quadraticCurveTo(x, y + height, x, y + height - radius);
  context.lineTo(x, y + radius);
  context.quadraticCurveTo(x, y, x + radius, y);
  context.closePath();
}
