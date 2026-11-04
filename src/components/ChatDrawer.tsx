import { useEffect, useMemo, useRef, useState } from "react";
import type { AppError, ChatItem, MemberView } from "../lib/api";
import { describeError } from "../lib/api";
import { ConfirmSheet } from "./Modal";
import {
  bytesToObjectUrl,
  clockTime,
  fileToBytes,
  formatBytes,
  readableOn,
  shortKey,
} from "../lib/format";

interface ChatDrawerProps {
  items: ChatItem[];
  roster: MemberView[];
  selfPubkey: string;
  blockedPubkeys: Set<string>;
  /** Posts an encrypted text message. */
  onSendText: (text: string) => Promise<void>;
  /** Uploads the bytes and posts the pointer envelope. */
  onSendFile: (file: File, caption?: string) => Promise<void>;
  /** Fetches and verifies a shared blob. */
  onDownload: (assetName: string, sha256B64: string, mime: string) => Promise<void>;
  onBlock: (pubkeyB64: string, blocked: boolean) => Promise<void>;
  onReport: (commentId: number, pubkeyB64: string) => void;
  onDeleteMessage: (eventId: string) => Promise<string>;
}

/** Largest share the vault accepts, mirroring the Rust ceiling. */
const MAX_FILE_BYTES = 15 * 1024 * 1024;

/**
 * Chat pane: the transcript, a composer, and per-message moderation.
 *
 * Files are shown as a pointer plus a fetch button rather than auto-loading: every
 * download costs a request against the shared hourly budget, so the user decides
 * when to spend one.
 */
export function ChatDrawer({
  items,
  roster,
  selfPubkey,
  blockedPubkeys,
  onSendText,
  onSendFile,
  onDownload,
  onBlock,
  onReport,
  onDeleteMessage,
}: ChatDrawerProps) {
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<AppError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [deleteEventId, setDeleteEventId] = useState<string | null>(null);
  const listRef = useRef<HTMLDivElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const names = useMemo(() => {
    const map = new Map<string, string>();
    for (const member of roster) {
      map.set(member.pubkeyB64, member.displayName);
    }
    return map;
  }, [roster]);

  // Keep the newest message in view.
  useEffect(() => {
    const list = listRef.current;
    if (!list) return;
    list.scrollTop = list.scrollHeight;
  }, [items.length]);
  const handleSendText = async () => {
    const text = draft.trim();
    if (!text || busy) return;
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      await onSendText(text);
      setDraft("");
    } catch (thrown) {
      setError(thrown as AppError);
    } finally {
      setBusy(false);
    }
  };

  const handlePickFile = async (file: File) => {
    setError(null);
    setNotice(null);

    if (file.size > MAX_FILE_BYTES) {
      setError({
        kind: "payload_too_large",
        message: `${formatBytes(file.size)} exceeds the ${formatBytes(MAX_FILE_BYTES)} limit`,
      });
      return;
    }

    setBusy(true);
    try {
      await onSendFile(file, draft.trim() || undefined);
      setDraft("");
      setNotice(`Shared ${file.name}`);
    } catch (thrown) {
      setError(thrown as AppError);
    } finally {
      setBusy(false);
    }
  };

  const handleDownload = async (
    assetName: string,
    sha256B64: string,
    mime: string,
  ) => {
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      await onDownload(assetName, sha256B64, mime);
      setNotice("Fetched and decrypted");
    } catch (thrown) {
      setError(thrown as AppError);
    } finally {
      setBusy(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteEventId) return;
    setBusy(true);
    setError(null);
    try {
      setNotice(await onDeleteMessage(deleteEventId));
      setDeleteEventId(null);
    } catch (thrown) {
      setError(thrown as AppError);
      setDeleteEventId(null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full flex-col">
      <div ref={listRef} className="min-h-0 flex-1 space-y-2 overflow-y-auto pb-3">
        {items.length === 0 ? (
          <p className="card text-center text-sm text-slate-400">
            No messages yet. Say hello — it is encrypted before it leaves this device.
          </p>
        ) : null}

        {items.map((item) => {
          const senderName = names.get(senderOf(item)) ?? shortKey(senderOf(item));
          const isSelf = senderOf(item) === selfPubkey;
          const hidden = blockedPubkeys.has(senderOf(item)) && !isSelf;
          const open = expanded === item.commentId;

          if (item.kind === "undecryptable") {
            return (
              <div
                key={`u-${item.commentId}`}
                className="card border-amber-900/60 bg-amber-950/30 text-xs text-amber-200"
              >
                A message at #{item.commentId} could not be read: {item.reason}
              </div>
            );
          }

          if (item.kind === "moderation") {
            return (
              <div
                key={`m-${item.commentId}`}
                className="card border-surface-border text-xs text-slate-400"
              >
                <span className="font-semibold text-slate-300">Report</span> from{" "}
                {senderName} on message #{item.targetCommentId}: {item.reason}
              </div>
            );
          }

          if (hidden) {
            // Blocked senders collapse to a single line so the transcript keeps
            // its shape without revealing content.
            return (
              <div
                key={`h-${item.commentId}`}
                className="rounded-xl border border-surface-border bg-surface px-3 py-2 text-xs text-slate-500"
              >
                Message from {senderName} hidden by your block list.
              </div>
            );
          }

          return (
            <div
              key={`c-${item.commentId}`}
              className={`rounded-2xl border p-3 ${
                isSelf
                  ? "border-accent-muted bg-accent/10"
                  : "border-surface-border bg-surface-raised"
              }`}
            >
              <div className="mb-1 flex items-center justify-between gap-2 text-xs">
                <span className="font-semibold text-slate-200">{senderName}</span>
                <span className="text-slate-500">{clockTime(item.unixMs)}</span>
              </div>

              {item.kind === "text" ? (
                <p className="whitespace-pre-wrap break-words text-sm text-slate-100">
                  {item.text}
                </p>
              ) : (
                <div className="space-y-2">
                  {item.caption ? (
                    <p className="whitespace-pre-wrap break-words text-sm text-slate-100">
                      {item.caption}
                    </p>
                  ) : null}
                  <div className="flex items-center gap-2 rounded-xl border border-surface-border bg-surface p-2">
                    <span className="text-lg" aria-hidden>
                      📎
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-xs text-slate-300">
                        {item.mime.split("/").pop()?.toUpperCase() ?? "FILE"}
                      </span>
                      <span className="block text-[10px] text-slate-500">
                        {item.unavailable ? "Uploader reports this file was deleted" : formatBytes(item.sizeBytes)}
                      </span>
                    </span>
                    <button
                      type="button"
                      className="btn-secondary px-3 py-1.5 text-xs"
                      disabled={busy || item.unavailable}
                      onClick={() =>
                        void handleDownload(item.assetName, item.sha256B64, item.mime)
                      }
                    >
                      Fetch
                    </button>
                  </div>
                </div>
              )}

              {isSelf && item.nostrEventId ? (
                <button
                  type="button"
                  className="mt-2 text-[10px] font-medium text-red-400 hover:text-red-300"
                  onClick={() => setDeleteEventId(item.nostrEventId)}
                >
                  Delete my message
                </button>
              ) : null}
              {!isSelf ? (
                <div className="mt-2 flex items-center gap-2 border-t border-surface-border/60 pt-2">
                  <button
                    type="button"
                    className="text-[10px] font-medium text-slate-500 hover:text-slate-300"
                    onClick={() => setExpanded(open ? null : item.commentId)}
                  >
                    {open ? "Hide" : "Actions"}
                  </button>
                  {open ? (
                    <>
                      <button
                        type="button"
                        className="text-[10px] font-medium text-slate-400 hover:text-slate-200"
                        onClick={() =>
                          void onBlock(senderOf(item), !blockedPubkeys.has(senderOf(item)))
                        }
                      >
                        {blockedPubkeys.has(senderOf(item)) ? "Unblock" : "Block"}
                      </button>
                      <button
                        type="button"
                        className="text-[10px] font-medium text-red-400 hover:text-red-300"
                        onClick={() => onReport(item.commentId, senderOf(item))}
                      >
                        Report
                      </button>
                      <span className="ml-auto font-mono text-[10px] text-slate-600">
                        {shortKey(senderOf(item))}
                      </span>
                    </>
                  ) : null}
                </div>
              ) : null}
            </div>
          );
        })}
      </div>

      {error ? (
        <div className="mb-2 rounded-xl border border-red-800 bg-red-950/70 p-2 text-xs text-red-100">
          {describeError(error)}
        </div>
      ) : null}
      {notice ? (
        <div className="mb-2 rounded-xl border border-surface-border bg-surface-raised p-2 text-xs text-slate-300">
          {notice}
        </div>
      ) : null}
      {deleteEventId ? (
        <ConfirmSheet
          title="Request message deletion?"
          body="Relays may ignore this request, and other devices may keep copies. Deleting a file message does not delete its blob."
          confirmLabel="Request deletion"
          onConfirm={() => void handleDelete()}
          onCancel={() => setDeleteEventId(null)}
          busy={busy}
        />
      ) : null}

      <div className="flex items-end gap-2">
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) void handlePickFile(file);
            event.target.value = "";
          }}
        />
        <button
          type="button"
          className="btn-secondary shrink-0 px-3 text-xs"
          disabled={busy}
          onClick={() => fileInputRef.current?.click()}
          title={`Share a file (max ${formatBytes(MAX_FILE_BYTES)})`}
        >
          File
        </button>
        <textarea
          className="field max-h-24 flex-1 resize-none py-2"
          rows={1}
          placeholder="Message"
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter" && !event.shiftKey) {
              event.preventDefault();
              void handleSendText();
            }
          }}
        />
        <button
          type="button"
          className="btn-primary shrink-0 px-3 text-xs"
          disabled={busy || draft.trim().length === 0}
          onClick={() => void handleSendText()}
        >
          Send
        </button>
      </div>
    </div>
  );
}

/** The public key that authored an item. */
function senderOf(item: ChatItem): string {
  switch (item.kind) {
    case "text":
    case "file":
    case "moderation":
      return item.senderPubkeyB64;
    case "undecryptable":
      return "";
  }
}

/**
 * Render decrypted bytes and trigger a save.
 *
 * Kept out of the component so a download does not need to store the blob in
 * React state, which would keep plaintext alive longer than necessary.
 */
export function saveDecryptedFile(
  bytes: number[],
  fileName: string,
  mime: string,
): void {
  const url = bytesToObjectUrl(bytes, mime);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  // Revoke on the next tick so a slow browser has time to start the download.
  window.setTimeout(() => URL.revokeObjectURL(url), 2_000);
}

/** Read a `File` into the `number[]` shape the Rust command expects. */
export const readFileBytes = fileToBytes;

export { readableOn };