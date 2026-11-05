import { useState } from "react";
import type {
  AppError,
  DiagnosticsResponse,
  MemberInvite,
  MemberView,
  VaultReport,
} from "../lib/api";
import { describeError } from "../lib/api";
import { formatBytes, relativeAge, shortKey } from "../lib/format";
import { ConfirmSheet, CopyButton, Field, Modal } from "./Modal";

interface SettingsPanelProps {
  diagnostics: DiagnosticsResponse | null;
  roster: MemberView[];
  blockedPubkeys: Set<string>;
  vault: VaultReport | null;
  isHost: boolean;
    /** True when background location sharing is currently running. */
    backgroundEnabled: boolean;
    onToggleBackground: () => Promise<void>;
    /** Present when location access is blocked, with the fix to offer. */
    locationIssue: { message: string; actionLabel: string } | null;
    onFixLocation: () => void;
    onBlock: (pubkeyB64: string, blocked: boolean) => Promise<void>;
  onRefreshVault: () => Promise<void>;
  onDeleteNostrBlob: (sha256: string) => Promise<string>;
  onRotate: (joinPassword: string, removePubkeys: string[]) => Promise<MemberInvite[]>;
  onLeave: () => Promise<void>;
  onDestroy: () => Promise<void>;
  onClose: () => void;
}

type Sheet =
  | { kind: "none" }
  | { kind: "rotate" }
  | { kind: "leave" }
  | { kind: "destroy" }
  | { kind: "delete-file"; sha256: string; status: string }
  | { kind: "invites"; title: string; invites: MemberInvite[] };

/**
 * Settings and host controls.
 *
 * Split into two halves: things any member can do (block list, storage view,
 * leaving) and host-only operations (rotation, re-keying, destroying). The host
 * controls are hidden for guests because the group would reject them anyway, and
 * offering a button that always fails is worse than not offering it.
 */
export function SettingsPanel({
  diagnostics,
  roster,
  blockedPubkeys,
  vault,
  isHost,
    backgroundEnabled,
    onToggleBackground,
    locationIssue,
    onFixLocation,
    onBlock,
  onRefreshVault,
  onDeleteNostrBlob,
  onRotate,
  onLeave,
  onDestroy,
  onClose,
}: SettingsPanelProps) {
  const [sheet, setSheet] = useState<Sheet>({ kind: "none" });
  const [joinPassword, setJoinPassword] = useState("");
  const [removePubkeys, setRemovePubkeys] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<AppError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const blockedList = [...blockedPubkeys];

  const runRotate = async () => {
    setError(null);
    setBusy(true);
    try {
      const invites = await onRotate(joinPassword, [...removePubkeys]);
      setJoinPassword("");
      setRemovePubkeys(new Set());
      setSheet({
        kind: "invites",
        title: "Re-issued invites",
        invites,
      });
      setNotice("Group key rotated. Hand each member their new invite.");
    } catch (thrown) {
      setError(thrown as AppError);
    } finally {
      setBusy(false);
    }
  };

  const runLeave = async () => {
    setError(null);
    setBusy(true);
    try {
      await onLeave();
    } catch (thrown) {
      setError(thrown as AppError);
      setBusy(false);
    }
  };

  const runDestroy = async () => {
    setError(null);
    setBusy(true);
    try {
      await onDestroy();
    } catch (thrown) {
      setError(thrown as AppError);
      setBusy(false);
    }
  };

  const runDeleteFile = async () => {
    if (sheet.kind !== "delete-file") return;
    setError(null);
    setBusy(true);
    try {
      setNotice(await onDeleteNostrBlob(sheet.sha256));
      setSheet({ kind: "none" });
      await onRefreshVault();
    } catch (thrown) {
      setError(thrown as AppError);
      setSheet({ kind: "none" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto flex h-full w-full max-w-3xl flex-col">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-base font-semibold text-slate-100">Settings</h2>
        <button
          type="button"
          className="btn-secondary px-3 py-1.5 text-xs"
          onClick={onClose}
        >
          Close
        </button>
      </div>

      {error ? (
        <div className="mb-3 rounded-xl border border-red-800 bg-red-950/70 p-2 text-xs text-red-100">
          {describeError(error)}
        </div>
      ) : null}
      {notice ? (
        <div className="mb-3 rounded-xl border border-surface-border bg-surface-raised p-2 text-xs text-slate-300">
          {notice}
        </div>
      ) : null}

      <div className="min-h-0 flex-1 space-y-3 overflow-y-auto pb-3">
        {/* -- Group -- */}
        <section className="card space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">
            Group
          </h3>
          {diagnostics ? (
            <dl className="space-y-1 text-xs text-slate-300">
              <Row label="Group" value={diagnostics.groupRef} />
              <Row
                label="Storage"
                value={
                  diagnostics.accountless
                    ? `${diagnostics.backend} · no account`
                    : diagnostics.backend
                }
              />
              <Row
                label="Role"
                value={diagnostics.isHost ? "Host" : "Guest"}
              />
              <Row label="Your fingerprint" value={diagnostics.fingerprint} />
              <Row
                label="Key epoch"
                value={`${diagnostics.currentEpoch} (held: ${diagnostics.knownEpochs.join(", ")})`}
              />
              <Row label="Members" value={String(diagnostics.rosterLen)} />
              <Row label="Messages" value={String(diagnostics.chatLen)} />
              <Row
                label="Vault"
                value={
                  vault
                    ? `${formatBytes(vault.totalBytes)} in known uploads; server quota unknown`
                    : "loading…"
                }
              />
              <Row
                label="Cadence"
                value={`messages ${diagnostics.chatIntervalS}s · positions ${diagnostics.rosterIntervalS}s`}
              />
              {diagnostics.haltedUntilUnixS ? (
                <p className="rounded-lg border border-amber-800 bg-amber-950/50 p-2 text-amber-200">
              Sync paused until the relay rate limit resets. Everything resumes
                  automatically.
                </p>
              ) : null}
            </dl>
          ) : (
            <p className="text-xs text-slate-500">No diagnostics available yet.</p>
          )}

          <button
            type="button"
            className="btn-secondary w-full text-xs"
            onClick={() => void onRefreshVault()}
          >
            Refresh storage report
          </button>
        </section>

        {/* -- Storage -- */}
        {vault && vault.assets.length > 0 ? (
          <section className="card space-y-2">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">
              Shared files ({vault.assets.length})
            </h3>
            <p className="text-xs text-slate-500">
              {diagnostics?.backend === "nostr"
                ? "Only uploads recorded on this device are listed. Copies or mirrors may exist elsewhere."
                : "The oldest files are deleted automatically when the vault is full, so recent shares always fit."}
            </p>
            <ul className="space-y-1 text-xs">
              {(diagnostics?.backend === "nostr" ? vault.assets : vault.assets.slice(-8)).slice().reverse().map((asset) => (
                <li
                  key={asset.name}
                  className="flex items-center justify-between gap-2 rounded-lg border border-surface-border bg-surface px-2 py-1.5"
                >
                  <span className="truncate font-mono text-[10px] text-slate-400">
                    {asset.name}
                  </span>
                  <span className="shrink-0 text-slate-500">
                    {formatBytes(asset.size)} · {relativeAge(asset.createdAtMs)}
                  </span>
                  {asset.deletionStatus ? (
                    <button
                      type="button"
                      className="text-[10px] text-red-400"
                      disabled={busy}
                      onClick={() => setSheet({ kind: "delete-file", sha256: asset.name, status: asset.deletionStatus ?? "available" })}
                    >
                      {asset.deletionStatus === "available" ? "Delete" : "Retry notice"}
                    </button>
                  ) : null}
                </li>
              ))}
            </ul>
          </section>
        ) : null}

        {/* -- Members -- */}
        <section className="card space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">
            Members ({roster.length})
          </h3>
          {roster.length === 0 ? (
            <p className="text-xs text-slate-500">Nobody has joined yet.</p>
          ) : (
            <ul className="space-y-1">
              {roster.map((member) => {
                const blocked = blockedPubkeys.has(member.pubkeyB64);
                const marked = removePubkeys.has(member.pubkeyB64);
                return (
                  <li
                    key={member.pubkeyB64}
                    className="flex items-center gap-2 rounded-lg border border-surface-border bg-surface px-2 py-1.5"
                  >
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-xs text-slate-200">
                        {member.displayName || "Unnamed"}
                        {member.isSelf ? " (you)" : ""}
                        {member.role ? ` · ${member.role}` : ""}
                      </span>
                      <span className="block font-mono text-[10px] text-slate-500">
                        {shortKey(member.pubkeyB64)}
                      </span>
                    </span>

                    {!member.isSelf ? (
                      <>
                        {isHost ? (
                          <label className="flex items-center gap-1 text-[10px] text-slate-400">
                            <input
                              type="checkbox"
                              checked={marked}
                              onChange={(event) => {
                                const next = new Set(removePubkeys);
                                if (event.target.checked) {
                                  next.add(member.pubkeyB64);
                                } else {
                                  next.delete(member.pubkeyB64);
                                }
                                setRemovePubkeys(next);
                              }}
                            />
                            remove
                          </label>
                        ) : null}
                        <button
                          type="button"
                          className="text-[10px] font-medium text-slate-400 hover:text-slate-200"
                          onClick={() => void onBlock(member.pubkeyB64, !blocked)}
                        >
                          {blocked ? "Unblock" : "Block"}
                        </button>
                      </>
                    ) : null}
                  </li>
                );
              })}
            </ul>
          )}

          {blockedList.length > 0 ? (
            <p className="text-[10px] text-slate-500">
              {blockedList.length} member
              {blockedList.length === 1 ? "" : "s"} blocked locally. Blocking is not
              reported to anyone.
            </p>
          ) : null}
        </section>

        {/* -- Host controls -- */}
        {isHost ? (
          <section className="card space-y-2">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">
              Host controls
            </h3>
            <p className="text-xs text-slate-500">
              Rotating the key cuts off anyone who is removed. Each remaining member
              needs their new invite string, so only rotate when you can hand them out.
            </p>
            <button
              type="button"
              className="btn-secondary w-full text-xs"
              onClick={() => setSheet({ kind: "rotate" })}
            >
              {removePubkeys.size > 0
                ? `Rotate key and remove ${removePubkeys.size} member${
                    removePubkeys.size === 1 ? "" : "s"
                  }`
                : "Rotate group key"}
            </button>
          </section>
        ) : null}

        {/* -- Location -- */}
        <section className="card space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">
            Location sharing
          </h3>
          <p className="text-xs text-slate-500">
            Sharing keeps your group's map current. Turning on background sharing keeps
            it updating while the screen is off, and shows a permanent notification the
            whole time.
          </p>
          {locationIssue ? (
            <div className="rounded-xl border border-amber-800 bg-amber-950/60 p-3 text-xs leading-relaxed text-amber-100">
              <p>{locationIssue.message}</p>
              <button
                type="button"
                className="mt-2 rounded-lg border border-amber-700 px-2 py-1 text-xs font-semibold hover:bg-amber-900"
                onClick={onFixLocation}
              >
                {locationIssue.actionLabel}
              </button>
            </div>
          ) : (
            <p className="text-xs text-slate-400">
              This device can share its position while the app is open. The button
              below only controls updates after you leave the app.
            </p>
          )}
          <button
            type="button"
            className={backgroundEnabled ? "btn-secondary w-full text-xs" : "btn-primary w-full text-xs"}
            onClick={() => void onToggleBackground()}
          >
            {backgroundEnabled ? "Stop background sharing" : "Keep sharing when the app is closed"}
          </button>
          <p className="text-[10px] text-slate-500">
            Turning this off does not leave the group; it only stops position updates
            while the app is closed.
          </p>
        </section>

        {/* -- Danger zone -- */}
        <section className="card space-y-2 border-red-900/60">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-red-300">
            Erase
          </h3>
          <p className="text-xs text-slate-400">
            Leaving deletes your entry from the group and removes every key from
            this device.
          </p>
          <button
            type="button"
            className="btn-danger w-full text-xs"
            onClick={() => setSheet({ kind: "leave" })}
          >
            Leave group and wipe my data
          </button>
          {isHost ? (
            <>
              <button
                type="button"
                className="btn-danger w-full text-xs"
                onClick={() => setSheet({ kind: "destroy" })}
              >
                Destroy group
              </button>
              <p className="text-[10px] text-slate-500">
                Sends a closure request and wipes this device. Other devices wipe when
                they receive and verify it; relay copies may remain.
              </p>
            </>
          ) : null}
        </section>
      </div>

      {/* -- Sheets -- */}

      {sheet.kind === "rotate" ? (
        <Modal
          title="Rotate group key"
          primaryLabel="Rotate and re-issue invites"
          onPrimary={() => void runRotate()}
          secondaryLabel="Cancel"
          onSecondary={() => setSheet({ kind: "none" })}
          busy={busy || joinPassword.length === 0}
        >
          <p>
            {removePubkeys.size > 0
              ? `${removePubkeys.size} member(s) will lose access to everything shared from now on.`
              : "Nobody is removed; the key is refreshed as a precaution."}
          </p>
          <p className="text-xs text-slate-400">
            Members who kept an old invite can still read messages sent before the
            rotation. Cannot be undone.
          </p>
          <Field
            label="Join password"
            type="password"
            value={joinPassword}
            onChange={setJoinPassword}
            placeholder="The group's join password"
            hint="Used to re-wrap each member's new invite."
          />
        </Modal>
      ) : null}

      {sheet.kind === "invites" ? (
        <Modal
          title={`${sheet.title} (${sheet.invites.length})`}
          primaryLabel="Done"
          onPrimary={() => setSheet({ kind: "none" })}
        >
          {sheet.invites.length === 0 ? (
            <p className="text-xs text-slate-400">
              No members to re-invite yet, so only your own invite changed.
            </p>
          ) : (
            <ul className="max-h-64 space-y-2 overflow-y-auto">
              {sheet.invites.map((invite) => (
                <li key={invite.pubkeyB64} className="space-y-1">
                  <span className="block text-xs text-slate-300">
                    {invite.displayName || shortKey(invite.pubkeyB64)}
                  </span>
                  <div className="flex gap-2">
                    <input
                      readOnly
                      className="field flex-1 font-mono text-[10px]"
                      value={invite.invite}
                      onFocus={(event) => event.currentTarget.select()}
                    />
                    <CopyButton text={invite.invite} label="Copy" />
                  </div>
                </li>
              ))}
            </ul>
          )}
          <p className="text-xs text-amber-300">
              These strings contain the group key. Hand each one to its owner over a
            channel you trust.
          </p>
        </Modal>
      ) : null}

      {sheet.kind === "leave" ? (
        <ConfirmSheet
          title="Leave group and wipe my data?"
          body="Your position entry is removed for the group, and every key is deleted from this device. You will need a fresh invite to rejoin."
          confirmLabel="Leave and wipe"
          onConfirm={() => void runLeave()}
          onCancel={() => setSheet({ kind: "none" })}
          busy={busy}
        />
      ) : null}

      {sheet.kind === "destroy" ? (
        <ConfirmSheet
          title="Destroy the group for everyone?"
          body={diagnostics?.backend === "nostr"
            ? "This publishes a host-signed closure and wipes this device. Updated devices that receive it will automatically wipe their group data. Offline devices, relays, and Blossom servers may retain copies."
                : "The group is closed for everyone, taking every message, position, and shared file with it. Every member loses access permanently."}
          confirmLabel="Destroy group"
          onConfirm={() => void runDestroy()}
          onCancel={() => setSheet({ kind: "none" })}
          busy={busy}
        />
      ) : null}
      {sheet.kind === "delete-file" ? (
        <ConfirmSheet
          title={sheet.status === "available" ? "Delete this file?" : "Retry deletion notice?"}
          body="The uploader will ask the recorded Blossom server to delete this blob and notify the group. All known references to the blob will be marked unavailable. Copies, mirrors, or unconfirmed relays may retain it."
          confirmLabel={sheet.status === "available" ? "Delete file" : "Retry notice"}
          onConfirm={() => void runDeleteFile()}
          onCancel={() => setSheet({ kind: "none" })}
          busy={busy}
        />
      ) : null}
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <dt className="shrink-0 text-slate-500">{label}</dt>
      <dd className="truncate text-right text-slate-200">{value}</dd>
    </div>
  );
}
