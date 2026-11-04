import { useEffect, useState } from "react";
import type { AppError } from "../lib/api";
import { describeError } from "../lib/api";
import { CopyButton, Field, Modal } from "./Modal";

/**
 * The EULA text.
 *
 * Play requires an in-app gate that prohibits illegal content, harassment, and
 * copyright infringement before the user can proceed, so the wording is treated
 * as a compliance artefact rather than a copy detail.
 */
const TERMS = [
  "You must not use this app to share content that is illegal where you or your group members are located.",
  "Harassment, threats, and targeted abuse toward any group member are prohibited.",
  "Do not share material you do not have the right to distribute; you are responsible for what you send.",
  "Location sharing is voluntary and can be stopped at any time by leaving the group.",
  "Every message, position, and file is encrypted on your device before it is stored. Nobody operating the storage can read it — including the app's authors.",
  "You are responsible for who you invite: the join password and invite string are the only things protecting your group's data.",
];

/**
 * The location disclosure, verbatim from the plan.
 *
 * Play requires this text to be shown prominently *before* the OS permission
 * prompt, so it has to appear exactly here and not be paraphrased elsewhere.
 */
const LOCATION_DISCLOSURE =
  "This app collects location data to enable live group sharing with your connected group members, even when the app is in use. All location telemetry is end-to-end encrypted locally before transmission. No location data is ever stored on third-party servers.";

interface ConsentGateProps {
  /** True once the EULA has been acknowledged. */
  eulaAccepted: boolean;
  /** True once the location disclosure has been acknowledged. */
  disclosureAccepted: boolean;
  /** Called once both stages are complete, with the chosen display name. */
  onComplete: (displayName: string) => Promise<void>;
}

/**
 * First-launch consent flow: EULA, then location disclosure, then a display name.
 *
 * Modelled as an explicit stage machine rather than a boolean so the two gates
 * cannot be skipped by a state reset, and so the ordering that Play requires is
 * visible in the code.
 */
export function ConsentGate({
  eulaAccepted,
  disclosureAccepted,
  onComplete,
}: ConsentGateProps) {
  const [stage, setStage] = useState<"eula" | "disclosure" | "name">(
    eulaAccepted ? (disclosureAccepted ? "name" : "disclosure") : "eula",
  );
  const [scrolledToEnd, setScrolledToEnd] = useState(false);
  const [displayName, setDisplayName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<AppError | null>(null);

  useEffect(() => {
    setScrolledToEnd(false);
  }, [stage]);

  const finish = async () => {
    setError(null);
    setBusy(true);
    try {
      await onComplete(displayName.trim());
    } catch (thrown) {
      setError(thrown as AppError);
    } finally {
      setBusy(false);
    }
  };

  if (stage === "eula") {
    return (
      <Modal
        title="Terms of use"
        blocking
        primaryLabel={scrolledToEnd ? "I agree" : "Scroll to continue"}
        onPrimary={
          scrolledToEnd
            ? () => setStage("disclosure")
            : () => setScrolledToEnd(true)
        }
      >
        <div
          className="max-h-56 space-y-3 overflow-y-auto rounded-xl border border-surface-border bg-surface p-3 text-xs leading-relaxed"
          onScroll={(event) => {
            const element = event.currentTarget;
            const atEnd =
              element.scrollTop + element.clientHeight >= element.scrollHeight - 12;
            if (atEnd) setScrolledToEnd(true);
          }}
        >
          {TERMS.map((term) => (
            <p key={term}>{term}</p>
          ))}
          <p className="text-slate-500">
            Accepting is required to use the app. You can leave the group and erase
            your data at any time from Settings.
          </p>
        </div>
      </Modal>
    );
  }

  if (stage === "disclosure") {
    return (
      <Modal
        title="Location sharing"
        blocking
        primaryLabel="I understand and agree"
        onPrimary={() => setStage("name")}
      >
        <p>{LOCATION_DISCLOSURE}</p>
        <ul className="ml-4 list-disc space-y-1 text-xs text-slate-400">
          <li>Your position is visible to members of your group only.</li>
          <li>Tracking continues while the app is in the background, if you enable it.</li>
          <li>You can turn location sharing off at any time.</li>
        </ul>
      </Modal>
    );
  }

  return (
    <Modal
      title="Choose a display name"
      blocking
      primaryLabel="Continue"
      onPrimary={() => void finish()}
      busy={busy || displayName.trim().length === 0}
    >
      <Field
        label="Display name"
        value={displayName}
        onChange={setDisplayName}
        placeholder="Jared"
        hint="Shown to your group members. Encrypted like everything else."
      />
      {error ? (
        <p className="text-xs text-red-300">{describeError(error)}</p>
      ) : null}
    </Modal>
  );
}

interface InviteDisplayProps {
  invite: string;
  fingerprint: string;
  label: string;
  onDone: () => void;
  /** Short explanation of what the recipient must do. */
  hint?: string;
  /** GitHub invites embed the group token. Nostr invites do not. */
  containsToken?: boolean;
}

/**
 * Shows an invite string with a copy button.
 *
 * The invite carries the group's PAT, so it is displayed only on request and with
 * a warning rather than being left on screen.
 */
export function InviteDisplay({
  invite,
  fingerprint,
  label,
  onDone,
  hint,
  containsToken = true,
}: InviteDisplayProps) {
  const [revealed, setRevealed] = useState(false);

  return (
    <Modal title={label} primaryLabel="Done" onPrimary={onDone}>
      <p className="text-xs text-slate-400">
        Your device fingerprint is <span className="font-mono">{fingerprint}</span>.
        Read it aloud so others can confirm which entry is yours.
      </p>

      {revealed ? (
        <>
          <textarea
            readOnly
            className="field h-28 font-mono text-[10px]"
            value={invite}
            onFocus={(event) => event.currentTarget.select()}
          />
          <div className="flex gap-2">
            <CopyButton text={invite} label="Copy invite" />
          </div>
          {containsToken ? (
            <p className="text-xs text-amber-300">
              This string contains the group's GitHub token. Anyone holding it can read
              the group and delete the repository. Share it only with people you trust,
              over a channel you trust.
            </p>
          ) : (
            <p className="text-xs text-amber-300">
              Anyone with this code and the join password can join the group. Share it
              only with people you trust.
            </p>
          )}
        </>
      ) : (
        <button
          type="button"
          className="btn-secondary w-full"
          onClick={() => setRevealed(true)}
        >
          Reveal invite string
        </button>
      )}

      {hint ? <p className="text-xs text-slate-500">{hint}</p> : null}
    </Modal>
  );
}