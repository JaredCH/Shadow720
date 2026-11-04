import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./styles.css";

const container = document.getElementById("root");

if (!container) {
  // A missing root element means index.html was altered; fail loudly rather than
  // rendering nothing and leaving the user with a blank screen.
  throw new Error("root element is missing from index.html");
}

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

/**
 * Last-resort crash reporter.
 *
 * A render error otherwise leaves an empty window with no clue why, which is
 * indistinguishable from a hang. Showing the message keeps the failure visible
 * and copyable instead of silent.
 */
function showFatal(detail: string) {
  const root = document.getElementById("root");
  if (!root) return;
  root.innerHTML = "";
  const panel = document.createElement("div");
  panel.style.cssText =
    "padding:16px;font:12px/1.5 ui-monospace,monospace;color:#fca5a5;white-space:pre-wrap;word-break:break-word";
  panel.textContent = `Shadow720 hit an unexpected error:\n\n${detail}`;
  root.appendChild(panel);
}

window.addEventListener("error", (event) => {
  showFatal(event.error?.stack ?? event.message);
});

window.addEventListener("unhandledrejection", (event) => {
  const reason = event.reason;
  showFatal(reason instanceof Error ? (reason.stack ?? reason.message) : String(reason));
});