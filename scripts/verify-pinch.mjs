/**
 * Drives real touch gestures against PeerMap to prove pinch zoom works.
 *
 * The map is a canvas with its own gesture model, so a unit test cannot see the
 * bug this guards against: a second finger being ignored, or a pinch that only
 * ever zooms in. This dispatches genuine CDP touch events at a mobile viewport.
 *
 * The full app cannot reach the map without the Tauri runtime (the vault has to
 * open first), so this renders the component through scripts/pinch-harness.
 *
 * Usage:
 *   npx vite --config scripts/pinch-harness/vite.config.ts   # in one shell
 *   npm run test:pinch                                       # in another
 *
 * Playwright is not a project dependency; install it on demand with
 * `npm i -D playwright && npx playwright install chromium`.
 */
import { chromium, devices } from "playwright";

const url = process.argv[2] ?? "http://localhost:4174/";

/** The zoom the map is currently drawing at. */
async function readZoom(page) {
  const raw = await page.evaluate(
    () => document.querySelector("canvas")?.dataset.zoom ?? null,
  );
  return raw === null ? null : Number(raw);
}

/** Two-finger pinch via CDP, which is the only way to get real touch events. */
async function pinch(page, { from, to, steps = 12 }) {
  const client = await page.context().newCDPSession(page);
  const box = await page.locator("canvas").boundingBox();
  const cx = box.x + box.width / 2;
  const cy = box.y + box.height / 2;

  const points = (spread) => [
    { x: cx - spread, y: cy, id: 1 },
    { x: cx + spread, y: cy, id: 2 },
  ];

  await client.send("Input.dispatchTouchEvent", {
    type: "touchStart",
    touchPoints: points(from),
  });

  for (let i = 1; i <= steps; i += 1) {
    const spread = from + ((to - from) * i) / steps;
    await client.send("Input.dispatchTouchEvent", {
      type: "touchMove",
      touchPoints: points(spread),
    });
  }

  await client.send("Input.dispatchTouchEvent", {
    type: "touchEnd",
    touchPoints: [],
  });
  await client.detach();
}

/** One-finger drag, to confirm panning still works alongside pinch. */
async function drag(page, { dx, dy, steps = 10 }) {
  const client = await page.context().newCDPSession(page);
  const box = await page.locator("canvas").boundingBox();
  const cx = box.x + box.width / 2;
  const cy = box.y + box.height / 2;

  await client.send("Input.dispatchTouchEvent", {
    type: "touchStart",
    touchPoints: [{ x: cx, y: cy, id: 1 }],
  });
  for (let i = 1; i <= steps; i += 1) {
    await client.send("Input.dispatchTouchEvent", {
      type: "touchMove",
      touchPoints: [{ x: cx + (dx * i) / steps, y: cy + (dy * i) / steps, id: 1 }],
    });
  }
  await client.send("Input.dispatchTouchEvent", {
    type: "touchEnd",
    touchPoints: [],
  });
  await client.detach();
}

const browser = await chromium.launch();
const context = await browser.newContext({
  ...devices["Pixel 7"],
  hasTouch: true,
  isMobile: true,
});
const page = await context.newPage();

const errors = [];
page.on("pageerror", (error) => errors.push(String(error)));

await page.goto(url, { waitUntil: "networkidle" });
await page.waitForSelector("canvas");
await page.waitForTimeout(500);

const results = [];
const check = (name, ok, detail) => {
  results.push({ name, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}: ${name}${detail ? ` (${detail})` : ""}`);
};

const start = await readZoom(page);
check("map renders and reports a zoom", start !== null, `zoom ${start}`);

// Pinch out: fingers move apart, so the map must zoom in.
await pinch(page, { from: 40, to: 160 });
await page.waitForTimeout(300);
const zoomedIn = await readZoom(page);
check(
  "pinch out zooms in",
  start !== null && zoomedIn !== null && zoomedIn > start,
  `${start} -> ${zoomedIn}`,
);

// Pinch in: fingers move together, so the map must zoom out. This is the case
// that was broken.
await pinch(page, { from: 160, to: 40 });
await page.waitForTimeout(300);
const zoomedOut = await readZoom(page);
check(
  "pinch in zooms out",
  zoomedIn !== null && zoomedOut !== null && zoomedOut < zoomedIn,
  `${zoomedIn} -> ${zoomedOut}`,
);

// Repeated pinches must keep working, not just the first one.
await pinch(page, { from: 150, to: 30 });
await page.waitForTimeout(300);
const zoomedOutAgain = await readZoom(page);
check(
  "a second pinch in zooms out further",
  zoomedOut !== null && zoomedOutAgain !== null && zoomedOutAgain < zoomedOut,
  `${zoomedOut} -> ${zoomedOutAgain}`,
);

// Zoom must clamp rather than run away.
for (let i = 0; i < 6; i += 1) {
  await pinch(page, { from: 170, to: 20 });
  await page.waitForTimeout(120);
}
const floor = await readZoom(page);
check("zoom clamps at the minimum", floor !== null && floor >= 2, `zoom ${floor}`);

// Panning must still work after a pinch.
const beforePan = await page.evaluate(() => document.querySelector("canvas").dataset.zoom);
await drag(page, { dx: 120, dy: 0 });
await page.waitForTimeout(200);
const afterPan = await page.evaluate(() => document.querySelector("canvas").dataset.zoom);
check("panning after a pinch does not change zoom", beforePan === afterPan, `${beforePan}`);

check("no page errors", errors.length === 0, errors.join("; ") || "none");

// The viewport must not forbid page zoom, which is an accessibility failure.
const viewport = await page.evaluate(
  () => document.querySelector('meta[name="viewport"]')?.content ?? "",
);
check(
  "viewport allows user scaling",
  !/user-scalable\s*=\s*no/i.test(viewport) && !/maximum-scale\s*=\s*1(\.0)?\b/i.test(viewport),
  viewport,
);

await browser.close();

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
