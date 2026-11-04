/**
 * Mounts PeerMap on its own so the pinch gesture can be driven by a real browser.
 *
 * The full app cannot reach the map without the Tauri runtime (the vault has to
 * open first), so this harness renders the component with a fixed viewport and
 * exposes the zoom it is drawing at on `window.__mapZoom`.
 */
import { createRoot } from "react-dom/client";
// The map relies on Tailwind classes (`h-full`, `touch-none`), so the harness
// must load the same stylesheet the app does or the layout is meaningless.
import "../../src/styles.css";
import { PeerMap } from "../../src/components/PeerMap";

const root = createRoot(document.getElementById("root")!);

root.render(
  <div style={{ position: "fixed", top: 0, left: 0, width: "100vw", height: "100vh", overflow: "hidden" }}>
    <PeerMap
      members={[]}
      selfFix={{ lat: 40.7128, lon: -74.006 }}
      trails={{}}
      anchor={{ lat: 40.7128, lon: -74.006 }}
      followSelf={false}
      selectedPubkey={null}
      onSelect={() => {}}
      basemap="dark"
      placeholderZoom={14}
    />
  </div>,
);
