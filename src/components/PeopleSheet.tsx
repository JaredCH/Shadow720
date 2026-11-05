import { useState } from "react";
import type { MemberView, RotateResponse } from "../lib/api";
import { describeError, toAppError } from "../lib/api";
import { shortKey } from "../lib/format";
import { CopyButton, Modal } from "./Modal";

interface PeopleSheetProps {
  roster: MemberView[];
  isHost: boolean;
  /** Nostr groups cannot delete another member's old pin. */
  accountless: boolean;
  onClose: () => void;
  onSetRole: (pubkey: string, role: "admin" | "member") => Promise<void>;
  onKick: (pubkey: string) => Promise<RotateResponse>;
}

/**
 * Roster with owner moderation.
 *
 * Kick rotates the group key. Admins cannot kick: only the owner can sign a
 * rotation. Anyone can still copy the group code from the header.
 */
export function PeopleSheet({
  roster,
  isHost,
  accountless,
  onClose,
  onSetRole,
  onKick,
}: PeopleSheetProps) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [kick, setKick] = useState<MemberView | null>(null);
  const [result, setResult] = useState<RotateResponse | null>(null);

  const run = async (action: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (thrown) {
      setError(describeError(toAppError(thrown)));
    } finally {
      setBusy(false);
    }
  };

  if (result) {
    return (
      <Modal title="Member removed" primaryLabel="Done" onPrimary={onClose}>
        <p>
          The group key was rotated. Share this new group code with everyone who
          should stay.
        </p>
        {accountless ? (
          <p className="text-xs text-slate-400">
            New messages are cut off now. Their old location pin may stay visible
            for up to an hour, because a relay cannot delete another person's post.
          </p>
        ) : null}
        <textarea
          readOnly
          className="field h-24 font-mono text-[10px]"
          value={result.groupInvite}
          onFocus={(event) => event.currentTarget.select()}
        />
        <CopyButton text={result.groupInvite} label="Copy group code" />
        {result.invites.length > 0 ? (
          <ul className="space-y-2">
            {result.invites.map((invite) => (
              <li key={invite.pubkeyB64} className="space-y-1">
                <p className="text-xs text-slate-400">
                  {invite.displayName || shortKey(invite.pubkeyB64)}
                </p>
                <CopyButton text={invite.invite} label="Copy their invite" />
              </li>
            ))}
          </ul>
        ) : null}
      </Modal>
    );
  }

  if (kick) {
    return (
      <Modal
        title={`Remove ${kick.displayName || "this member"}?`}
        primaryLabel="Kick and rotate key"
        onPrimary={() => {
          void run(async () => {
            setResult(await onKick(kick.pubkeyB64));
          });
        }}
        secondaryLabel="Back"
        onSecondary={() => {
          setKick(null);
          setError(null);
        }}
        busy={busy}
      >
        <p>
          This rotates the group key. They lose access to new messages. Everyone
          who stays needs the new group code.
        </p>
        {error ? <p className="text-xs text-red-300">{error}</p> : null}
      </Modal>
    );
  }

  return (
    <Modal title="People" secondaryLabel="Close" onSecondary={onClose}>
      {roster.length === 0 ? (
        <p className="text-xs text-slate-500">Nobody has joined yet.</p>
      ) : (
        <ul className="space-y-2">
          {roster.map((member) => {
            const canModerate =
              isHost && !member.isSelf && member.role !== "owner";
            return (
              <li
                key={member.pubkeyB64}
                className="rounded-xl border border-surface-border bg-surface p-3"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="min-w-0">
                    <span className="block truncate text-sm text-slate-100">
                      {member.displayName || "Unnamed"}
                      {member.isSelf ? " (you)" : ""}
                    </span>
                    <span className="block font-mono text-[10px] text-slate-500">
                      {shortKey(member.pubkeyB64)}
                    </span>
                  </span>
                  <span className="pill shrink-0 bg-surface-raised text-slate-300">
                    {member.role || "member"}
                  </span>
                </div>
                {canModerate ? (
                  <div className="mt-2 flex flex-wrap gap-2">
                    {member.role === "admin" ? (
                      <button
                        type="button"
                        className="btn-secondary px-2 py-1 text-[10px]"
                        disabled={busy}
                        onClick={() =>
                          void run(() => onSetRole(member.pubkeyB64, "member"))
                        }
                      >
                        Demote to member
                      </button>
                    ) : (
                      <button
                        type="button"
                        className="btn-secondary px-2 py-1 text-[10px]"
                        disabled={busy}
                        onClick={() =>
                          void run(() => onSetRole(member.pubkeyB64, "admin"))
                        }
                      >
                        Promote to admin
                      </button>
                    )}
                    <button
                      type="button"
                      className="btn-danger px-2 py-1 text-[10px]"
                      disabled={busy}
                      onClick={() => setKick(member)}
                    >
                      Kick
                    </button>
                  </div>
                ) : null}
              </li>
            );
          })}
        </ul>
      )}
      <p className="text-xs text-slate-500">
        {isHost
          ? "Only the owner can kick or change roles. Admins cannot rotate the key."
          : "Ask the owner to change roles or remove someone."}
      </p>
      {error ? <p className="text-xs text-red-300">{error}</p> : null}
    </Modal>
  );
}
