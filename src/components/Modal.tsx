import { useEffect, useState } from "react";

interface ModalProps {
  /** Heading shown at the top of the sheet. */
  title: string;
  /** Body copy. */
  children: React.ReactNode;
  /** Primary action label. Omit to render an informational sheet. */
  primaryLabel?: string;
  onPrimary?: () => void;
  secondaryLabel?: string;
  onSecondary?: () => void;
  /**
   * When true the sheet cannot be dismissed: no close button, no backdrop tap.
   * Used by the EULA and location-disclosure gates, which Play requires to be
   * acknowledged rather than skipped.
   */
  blocking?: boolean;
  /** Disables the primary action while an async step runs. */
  busy?: boolean;
}

/**
 * A bottom sheet, sized for one-handed phone use.
 *
 * The blocking mode exists because the consent gates must not be dismissable,
 * while every other sheet should be easy to back out of.
 */
export function Modal({
  title,
  children,
  primaryLabel,
  onPrimary,
  secondaryLabel,
  onSecondary,
  blocking = false,
  busy = false,
}: ModalProps) {
  useEffect(() => {
    if (blocking) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onSecondary?.();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [blocking, onSecondary]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-end justify-center bg-black/70 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      onClick={blocking ? undefined : onSecondary}
    >
      <div
        className="w-full max-w-md rounded-t-3xl border-t border-surface-border bg-surface-raised p-5 pb-7 shadow-2xl"
        onClick={(event) => event.stopPropagation()}
      >
        <h2 className="mb-3 text-base font-semibold text-slate-100">{title}</h2>
        <div className="mb-5 space-y-3 text-sm leading-relaxed text-slate-300">
          {children}
        </div>
        <div className="flex gap-3">
          {secondaryLabel && onSecondary ? (
            <button
              type="button"
              className="btn-secondary flex-1"
              onClick={onSecondary}
              disabled={busy}
            >
              {secondaryLabel}
            </button>
          ) : null}
          {primaryLabel && onPrimary ? (
            <button
              type="button"
              className="btn-primary flex-1"
              onClick={onPrimary}
              disabled={busy}
            >
              {busy ? "Working…" : primaryLabel}
            </button>
          ) : null}
        </div>
      </div>
    </div>
  );
}

/** Inline error banner. */
export function ErrorBanner({
  message,
  onDismiss,
  action,
}: {
  message: string;
  onDismiss?: () => void;
  action?: { label: string; onClick: () => void };
}) {
  return (
    <div className="flex items-start gap-3 rounded-xl border border-red-800 bg-red-950/70 p-3 text-sm text-red-100">
      <span className="flex-1">{message}</span>
      {action ? (
        <button
          type="button"
          className="rounded-lg border border-red-700 px-2 py-1 text-xs font-semibold hover:bg-red-900"
          onClick={action.onClick}
        >
          {action.label}
        </button>
      ) : null}
      {onDismiss ? (
        <button
          type="button"
          className="rounded-lg border border-red-700 px-2 py-1 text-xs hover:bg-red-900"
          onClick={onDismiss}
          aria-label="Dismiss"
        >
          ✕
        </button>
      ) : null}
    </div>
  );
}

/** Non-blocking informational banner. */
export function InfoBanner({
  message,
  tone = "info",
  action,
}: {
  message: string;
  tone?: "info" | "warn";
  /** Optional fix the user can apply without leaving the screen. */
  action?: { label: string; onClick: () => void };
}) {
  const classes =
    tone === "warn"
      ? "border-amber-800 bg-amber-950/60 text-amber-100"
      : "border-surface-border bg-surface-raised text-slate-300";
  return (
    <div className={`rounded-xl border p-3 text-xs leading-relaxed ${classes}`}>
      <div className="flex items-start gap-3">
        <span className="flex-1">{message}</span>
        {action ? (
          <button
            type="button"
            className="shrink-0 rounded-lg border border-amber-700 px-2 py-1 text-xs font-semibold hover:bg-amber-900"
            onClick={action.onClick}
          >
            {action.label}
          </button>
        ) : null}
      </div>
    </div>
  );
}

/** A labelled text input with an optional hint. */
export function Field({
  label,
  value,
  onChange,
  placeholder,
  type = "text",
  hint,
  autoComplete,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  type?: "text" | "password";
  hint?: string;
  autoComplete?: string;
}) {
  return (
    <label className="block">
      <span className="label">{label}</span>
      <input
        className="field"
        type={type}
        value={value}
        placeholder={placeholder}
        autoComplete={autoComplete}
        onChange={(event) => onChange(event.target.value)}
      />
      {hint ? (
        <span className="mt-1 block text-xs text-slate-500">{hint}</span>
      ) : null}
    </label>
  );
}

/** A labelled multi-line input. */
export function TextArea({
  label,
  value,
  onChange,
  placeholder,
  rows = 3,
  hint,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  rows?: number;
  hint?: string;
}) {
  return (
    <label className="block">
      <span className="label">{label}</span>
      <textarea
        className="field resize-none font-mono text-xs"
        rows={rows}
        value={value}
        placeholder={placeholder}
        onChange={(event) => onChange(event.target.value)}
      />
      {hint ? (
        <span className="mt-1 block text-xs text-slate-500">{hint}</span>
      ) : null}
    </label>
  );
}

/**
 * Copy-to-clipboard button.
 *
 * Falls back to `document.execCommand` because the Tauri clipboard plugin is not
 * always available in a browser preview.
 */
export function CopyButton({
  text,
  label = "Copy",
}: {
  text: string;
  label?: string;
}) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const area = document.createElement("textarea");
        area.value = text;
        document.body.appendChild(area);
        area.select();
        document.execCommand("copy");
        document.body.removeChild(area);
      }
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1_500);
    } catch {
      setCopied(false);
    }
  };

  return (
    <button type="button" className="btn-secondary" onClick={copy}>
      {copied ? "Copied" : label}
    </button>
  );
}

/** A simple confirmation sheet for destructive actions. */
export function ConfirmSheet({
  title,
  body,
  confirmLabel,
  onConfirm,
  onCancel,
  busy,
  danger = true,
}: {
  title: string;
  body: string;
  confirmLabel: string;
  onConfirm: () => void;
  onCancel: () => void;
  busy?: boolean;
  danger?: boolean;
}) {
  return (
    <Modal
      title={title}
      primaryLabel={confirmLabel}
      onPrimary={onConfirm}
      secondaryLabel="Cancel"
      onSecondary={onCancel}
      busy={busy}
    >
      <p>{body}</p>
      {danger ? (
        <p className="text-red-300">This cannot be undone.</p>
      ) : null}
    </Modal>
  );
}