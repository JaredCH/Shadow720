/**
 * One-button account sign-in using the OAuth device flow.
 *
 * The user never leaves the app to create a token: they press a button, get a
 * short code, approve on whatever device they already have, and the app polls
 * until the token appears. The token itself stays in Rust and never reaches this
 * component.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import * as api from "../lib/api";
import { ErrorBanner, InfoBanner } from "./Modal";

type Phase = "idle" | "waiting" | "signed-in";

export function SignInPanel({
  onSignedIn,
  allowDestroy,
  onAllowDestroyChange,
}: {
  onSignedIn: (result: api.SignInResponse) => void;
  allowDestroy: boolean;
  onAllowDestroyChange: (value: boolean) => void;
}) {
  const [phase, setPhase] = useState<Phase>("idle");
  const [code, setCode] = useState<api.BeginSignInResponse | null>(null);
  const [result, setResult] = useState<api.SignInResponse | null>(null);
  const [error, setError] = useState<api.AppError | null>(null);
  const [busy, setBusy] = useState(false);
  const cancelled = useRef(false);

  useEffect(() => {
    return () => {
      cancelled.current = true;
    };
  }, []);

  const start = useCallback(async () => {
    setError(null);
    setBusy(true);
    cancelled.current = false;
    try {
      const response = await api.beginSignIn(allowDestroy);
      setCode(response);
      setPhase("waiting");
    } catch (thrown) {
      setError(api.toAppError(thrown));
    } finally {
      setBusy(false);
    }
  }, [allowDestroy]);

  // Poll while waiting. The interval comes from the server, and a `slow_down`
  // response is handled in Rust, so this loop only needs to keep asking.
  useEffect(() => {
    if (phase !== "waiting" || !code) return;

    let timer = 0;
    const intervalMs = Math.max(code.interval, 5) * 1000;

    const tick = async () => {
      if (cancelled.current) return;
      try {
        const signedIn = await api.pollSignIn();
        if (cancelled.current) return;
        if (signedIn) {
          setResult(signedIn);
          setPhase("signed-in");
          onSignedIn(signedIn);
          return;
        }
      } catch (thrown) {
        if (cancelled.current) return;
        setError(api.toAppError(thrown));
        setPhase("idle");
        return;
      }
      timer = window.setTimeout(() => void tick(), intervalMs);
    };

    timer = window.setTimeout(() => void tick(), intervalMs);
    return () => window.clearTimeout(timer);
  }, [phase, code, onSignedIn]);

  if (phase === "signed-in" && result) {
    return (
      <InfoBanner
        message={`Signed in as ${result.login}.${
          result.canDestroy
            ? ""
            : " Destroy Group will be unavailable because the delete scope was not granted."
        }`}
      />
    );
  }

  if (phase === "waiting" && code) {
    return (
      <div className="space-y-3 rounded-xl border border-surface-border bg-surface-raised p-3">
        <p className="text-xs text-slate-400">
          Open{" "}
          <a
            className="text-accent underline"
            href={code.verificationUri}
            target="_blank"
            rel="noreferrer"
          >
            {code.verificationUri}
          </a>{" "}
          and enter this code:
        </p>
        <p className="text-center font-mono text-2xl font-bold tracking-[0.2em] text-slate-100">
          {code.userCode}
        </p>
        <p className="text-center text-xs text-slate-500">
          Waiting for approval… this screen updates on its own.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {error ? (
        <ErrorBanner message={api.describeError(error)} onDismiss={() => setError(null)} />
      ) : null}
      <label className="flex items-start gap-2 text-xs text-slate-400">
        <input
          type="checkbox"
          className="mt-0.5"
          checked={allowDestroy}
          onChange={(event) => onAllowDestroyChange(event.target.checked)}
        />
        <span>
          Also allow deleting the repository, so "Destroy Group" works. This grants
          the destructive <code>delete_repo</code> scope.
        </span>
      </label>
      <button
        type="button"
        className="btn-primary w-full"
        disabled={busy}
        onClick={() => void start()}
      >
        {busy ? "Starting…" : "Sign in to GitHub"}
      </button>
    </div>
  );
}
