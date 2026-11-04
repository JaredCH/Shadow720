/**
 * Web Mercator helpers for the raster tile layer.
 *
 * The map draws OpenStreetMap tiles directly on a canvas rather than using a map
 * library: the app already owns its own pan/zoom gestures, and a library would
 * pull in a second projection, a second event model, and a licence notice for
 * code that is not needed.
 */

/** Edge length of one tile, in CSS pixels. */
export const TILE_SIZE = 256;

/** Mercator cannot represent the poles, so latitude is clamped to this. */
const MAX_LAT = 85.05112878;

/** World pixel width at a (possibly fractional) zoom level. */
function worldSize(zoom: number): number {
  return TILE_SIZE * 2 ** zoom;
}

/** Horizontal world pixel position of a longitude. */
export function lonToWorldX(lon: number, zoom: number): number {
  return ((lon + 180) / 360) * worldSize(zoom);
}

/** Vertical world pixel position of a latitude. */
export function latToWorldY(lat: number, zoom: number): number {
  const clamped = Math.max(-MAX_LAT, Math.min(MAX_LAT, lat));
  const radians = (clamped * Math.PI) / 180;
  const mercator = Math.log(Math.tan(Math.PI / 4 + radians / 2));
  return ((1 - mercator / Math.PI) / 2) * worldSize(zoom);
}

/** Longitude at a horizontal world pixel position. */
export function worldXToLon(x: number, zoom: number): number {
  return (x / worldSize(zoom)) * 360 - 180;
}

/** Latitude at a vertical world pixel position. */
export function worldYToLat(y: number, zoom: number): number {
  const n = Math.PI - (2 * Math.PI * y) / worldSize(zoom);
  return (180 / Math.PI) * Math.atan(Math.sinh(n));
}

/** Tile URL for a slippy-map coordinate. */
export function tileUrl(x: number, y: number, z: number): string {
  return `https://tile.openstreetmap.org/${z}/${x}/${y}.png`;
}

/** Wrap a tile column index around the antimeridian. */
export function wrapTileX(x: number, z: number): number {
  const count = 2 ** z;
  return ((x % count) + count) % count;
}
