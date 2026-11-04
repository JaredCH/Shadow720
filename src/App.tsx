import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import * as api from "./lib/api";
import type {
  AppError,
  ChatItem,
  DiagnosticsResponse,
  MemberView,
  VaultReport,
} from "./lib/api";
import { describeError } from "./lib/api";
import {
  currentPosition,
  describeLocationFailure,
  locationPermissionState,
  locationRemedy,
  locationRemedyLabel,
  openLocationRemedy,
  requestLocationPermission,
} from "./lib/location";
import type { LocationFailure, LocationRemedy } from "./lib/location";
import { ChatDrawer, readFileBytes, saveDecryptedFile } from "./components/ChatDrawer";
import { ConsentGate, InviteDisplay } from "./components/ConsentGate";
import { ConfirmSheet, ErrorBanner, Field, InfoBanner, Modal, TextArea } from "./components/Modal";
import { MapPanel } from "./components/MapPanel";
import { ProviderPicker, providerById } from "./components/ProviderPicker";
import type { ProviderId } from "./components/ProviderPicker";
import { SignInPanel } from "./components/SignInPanel";
import { SettingsPanel } from "./components/SettingsPanel";

type Phase =
  | "starting"
  | "needs-consent"
  | "needs-group"
  | "legacy-recovery"
  | "ready"
  | "failed";

type Tab = "map" | "chat" | "settings";

/**
 * Poll loop intervals come from the Rust side, which owns the rate-limit policy.
 * These are only floors, used if a command returns something implausible.
 */
const MIN_CHAT_DELAY_MS = 2_000;
const MIN_ROSTER_DELAY_MS = 5_000;

/** How often to refresh the local GPS fix while the map tab is visible. */
const FIX_INTERVAL_MS = 20_000;

export default function App() {
  const [phase, setPhase] = useState<Phase>("starting");
  const [fatalError, setFatalError] = useState<AppError | null>(null);

  const [eulaAccepted, setEulaAccepted] = useState(false);
  const [disclosureAccepted, setDisclosureAccepted] = useState(false);

  const [groupLabel, setGroupLabel] = useState<string>("");
  const [fingerprint, setFingerprint] = useState<string>("");
  const [selfPubkey, setSelfPubkey] = useState<string>("");
  const [isHost, setIsHost] = useState(false);

  const [roster, setRoster] = useState<MemberView[]>([]);
  const [chat, setChat] = useState<ChatItem[]>([]);
  const [blocked, setBlocked] = useState<Set<string>>(new Set());
  const [diagnostics, setDiagnostics] = useState<DiagnosticsResponse | null>(null);
  const [vault, setVault] = useState<VaultReport | null>(null);

  const [selfFix, setSelfFix] = useState<{ lat: number; lon: number } | null>(null);
  const [trails, setTrails] = useState<Record<string, api.TrailPoint[]>>({});
  const [groups, setGroups] = useState<api.GroupSummary[]>([]);
  const [showGroups, setShowGroups] = useState(false);
  const [locationNotice, setLocationNotice] = useState<{
    message: string;
    remedy: LocationRemedy | null;
  } | null>(null);
  const [selectedPubkey, setSelectedPubkey] = useState<string | null>(null);

  const [tab, setTab] = useState<Tab>("map");
  const [banner, setBanner] = useState<AppError | null>(null);
  const [invite, setInvite] = useState<{ value: string; fingerprint: string } | null>(
    null,
  );
  const [rotationPrompt, setRotationPrompt] = useState<api.RotationStatus | null>(null);
  const [backgroundEnabled, setBackgroundEnabled] = useState(false);
  const [reportTarget, setReportTarget] = useState<{
    commentId: number;
    pubkey: string;
  } | null>(null);
  const [confirmLegacyDiscard, setConfirmLegacyDiscard] = useState(false);
  const [confirmVaultReset, setConfirmVaultReset] = useState(false);

  // Timers are held in refs so the loops cannot stack up across renders.
  const chatTimer = useRef<number | null>(null);
  const rosterTimer = useRef<number | null>(null);
  const fixTimer = useRef<number | null>(null);
  const activePhase = useRef<Phase>("starting");
  activePhase.current = phase;

  const finishClosedGroup = useCallback(async (message: string) => {
    activePhase.current = "starting";
    setPhase("starting");
    if (chatTimer.current !== null) window.clearTimeout(chatTimer.current);
    if (rosterTimer.current !== null) window.clearTimeout(rosterTimer.current);
    if (fixTimer.current !== null) window.clearTimeout(fixTimer.current);
    setRoster([]);
    setChat([]);
    setDiagnostics(null);
    setVault(null);
    setSelfFix(null);
    setInvite(null);
    setBackgroundEnabled(false);
    try {
      const location = await api.setBackgroundLocation(false);
      if (location.warning) message += ` ${location.warning}`;
    } catch (thrown) {
      message += ` Could not stop background location: ${api.toAppError(thrown).message}`;
    }
    try {
      await api.unlockVault({ vaultDir: await resolveVaultDir() });
      setBanner({ kind: "group_state", message });
      setPhase("needs-group");
    } catch (thrown) {
      setFatalError(api.toAppError(thrown));
      setPhase("failed");
    }
  }, []);

  // -- bootstrap -------------------------------------------------------------

  useEffect(() => {
    let cancelled = false;

    const start = async () => {
      try {
        // The vault directory is provided by the shell at runtime; the Rust side
        // treats it as opaque, so the browser preview simply lacks one.
        const vaultDir = await resolveVaultDir();
        const unlocked = await api.unlockVault({ vaultDir });

        if (cancelled) return;

        if (unlocked.requiresRecovery) {
          setPhase("legacy-recovery");
        } else if (unlocked.groupConfigured) {
          if (await api.checkGroupClosed()) {
            await finishClosedGroup("The host closed this group. Its local vault was wiped; copies on relays and other devices may remain.");
            return;
          }
          await loadGroupState();
          setPhase("ready");
        } else {
          setPhase("needs-consent");
        }
      } catch (thrown) {
        if (cancelled) return;
        const error = api.toAppError(thrown);
        if (error.kind === "not_configured") {
          // No native runtime: show the consent flow so the UI is explorable.
          setPhase("needs-consent");
          setBanner(error);
          return;
        }
        setFatalError(error);
        setPhase("failed");
      }
    };

    void start();
    return () => {
      cancelled = true;
    };
  }, []);

  const loadGroupState = useCallback(async () => {
    const [rosterSnapshot, chatSnapshot, info] = await Promise.all([
      api.rosterSnapshot(),
      api.chatSnapshot(),
      api.diagnostics(),
    ]);
    setRoster(rosterSnapshot.members);
    setTrails(rosterSnapshot.trails);
    setSelfPubkey(rosterSnapshot.selfPubkey);
    setChat(chatSnapshot.items);
    setDiagnostics(info);
    setIsHost(info.isHost);
    setGroupLabel(info.groupLabel);
    setFingerprint(info.fingerprint);

    const blockedKeys = await api.blockedMembers();
    setBlocked(new Set(blockedKeys));

    // Consent is persisted, so a restart must restore it: the location loop is
    // gated on the disclosure, and leaving it false silently disabled sharing.
    const consent = await api.consentStatus();
    setBackgroundEnabled(consent.enabledBackgroundLocation);
    setEulaAccepted(consent.acceptedEula);
    setDisclosureAccepted(consent.acceptedLocationDisclosure);

    setGroups(await api.listGroups());
  }, []);

  /** Switch to another stored group and reload everything for it. */
  const handleSwitchGroup = useCallback(async (groupId: string) => {
    setShowGroups(false);
    try {
      await api.switchGroup(groupId);
      // Trails belong to the previous group's members, so they must not carry over.
      setTrails({});
      setSelfFix(null);
      setSelectedPubkey(null);
      setChat([]);
      setRoster([]);
      await loadGroupState();
      setPhase("ready");
    } catch (thrown) {
      setBanner(api.toAppError(thrown));
    }
  }, [loadGroupState]);

  // -- polling ---------------------------------------------------------------

  const stopPolling = useCallback(() => {
    if (chatTimer.current !== null) window.clearTimeout(chatTimer.current);
    if (rosterTimer.current !== null) window.clearTimeout(rosterTimer.current);
    if (fixTimer.current !== null) window.clearTimeout(fixTimer.current);
    chatTimer.current = null;
    rosterTimer.current = null;
    fixTimer.current = null;
  }, []);

  const pollChat = useCallback(async () => {
    try {
      if (await api.checkGroupClosed()) {
        await finishClosedGroup("The host closed this group. Its local vault was wiped; copies on relays and other devices may remain.");
        return;
      }
      const response = await api.pollChat();
      const snapshot = await api.chatSnapshot();
      setChat(snapshot.items);
      if (!response.rateLimited) setBanner(null);

      const delay = Math.max(response.nextDelayMs || MIN_CHAT_DELAY_MS, MIN_CHAT_DELAY_MS);
      if (activePhase.current !== "ready") return;
      chatTimer.current = window.setTimeout(() => void pollChat(), delay);
    } catch (thrown) {
      if (activePhase.current !== "ready") return;
      const error = api.toAppError(thrown);
      // A rate limit is expected behaviour, not something to alarm the user about.
      if (error.kind !== "rate_limited") setBanner(error);
      const retry = error.kind === "rate_limited" ? 30_000 : 10_000;
      if (activePhase.current !== "ready") return;
      chatTimer.current = window.setTimeout(() => void pollChat(), retry);
    }
  }, [finishClosedGroup]);

  const pollRoster = useCallback(async () => {
    try {
      const response = await api.pollRoster();
      const snapshot = await api.rosterSnapshot();
      setRoster(snapshot.members);
      setTrails(snapshot.trails);
      if (!response.rateLimited) setBanner(null);

      const delay = Math.max(
        response.nextDelayMs || MIN_ROSTER_DELAY_MS,
        MIN_ROSTER_DELAY_MS,
      );
      if (activePhase.current !== "ready") return;
      rosterTimer.current = window.setTimeout(() => void pollRoster(), delay);
    } catch (thrown) {
      if (activePhase.current !== "ready") return;
      const error = api.toAppError(thrown);
      if (error.kind !== "rate_limited") setBanner(error);
      const retry = error.kind === "rate_limited" ? 60_000 : 15_000;
      if (activePhase.current !== "ready") return;
      rosterTimer.current = window.setTimeout(() => void pollRoster(), retry);
    }
  }, []);

  useEffect(() => {
    if (phase !== "ready") {
      stopPolling();
      return;
    }

    // Stagger the two loops deliberately: the Rust client serializes requests, so
    // firing both at launch only queues one behind the other.
    chatTimer.current = window.setTimeout(() => void pollChat(), 500);
    rosterTimer.current = window.setTimeout(() => void pollRoster(), 2_500);

    return stopPolling;
  }, [phase, pollChat, pollRoster, stopPolling]);

  // -- location --------------------------------------------------------------

  /** Show a location failure together with the action that would fix it. */
  const showLocationFailure = useCallback((failure: LocationFailure) => {
    setLocationNotice({
      message: describeLocationFailure(failure),
      remedy: locationRemedy(failure),
    });
  }, []);

  const pushFix = useCallback(async () => {
    const result = await currentPosition();
    if (!result.fix) {
      if (result.failure) showLocationFailure(result.failure);
      else setLocationNotice(null);
      return;
    }

    setSelfFix(result.fix);
    setLocationNotice(null);

    try {
      await api.updateLocation(result.fix.lat, result.fix.lon, {
        speedMps: result.fix.speedMps,
        headingDeg: result.fix.headingDeg,
        accuracyM: result.fix.accuracyM,
      });
      // Reflect the new position immediately rather than waiting for a poll.
      const snapshot = await api.rosterSnapshot();
      setRoster(snapshot.members);
      setTrails(snapshot.trails);
    } catch (thrown) {
      const error = api.toAppError(thrown);
      if (error.kind !== "rate_limited") setBanner(error);
    }
  }, [showLocationFailure]);

  /**
   * Apply the fix for a location failure.
   *
   * The system prompt can be answered in place, so a grant resumes sharing
   * immediately. A settings screen cannot report back, so the notice stays until
   * the next fix attempt succeeds.
   */
  const handleLocationRemedy = useCallback(async (remedy: LocationRemedy) => {
    const handled = await openLocationRemedy(remedy);
    if (!handled) {
      setLocationNotice({
        message:
          remedy === "permission"
            ? "Location permission is still not granted. Enable it for Shadow720 in system settings."
            : "This device has no settings screen to open. Enable location for Shadow720 in system settings.",
        remedy: null,
      });
      return;
    }
    if (remedy === "permission") {
      setLocationNotice(null);
      void pushFix();
    }
  }, [pushFix]);

  useEffect(() => {
    if (phase !== "ready" || !disclosureAccepted) return;

    let cancelled = false;

    const tick = async () => {
      if (cancelled || activePhase.current !== "ready") return;
      await pushFix();
      if (cancelled || activePhase.current !== "ready") return;
      fixTimer.current = window.setTimeout(() => void tick(), FIX_INTERVAL_MS);
    };

    // The OS prompt only appears after the in-app disclosure, which the consent
    // gate has already collected by the time we reach here.
    void (async () => {
      const state = await locationPermissionState();
      if (state !== "granted") {
        const granted = await requestLocationPermission();
        if (!granted) {
          showLocationFailure("permission-denied");
          return;
        }
      }
      void tick();
    })();

    return () => {
      cancelled = true;
      if (fixTimer.current !== null) window.clearTimeout(fixTimer.current);
    };
  }, [phase, disclosureAccepted, pushFix, showLocationFailure]);

  // Returning from a settings screen is the only signal that the user may have
  // changed something, so re-check rather than leaving a stale warning on screen.
  useEffect(() => {
    if (phase !== "ready" || !locationNotice) return;

    const onVisible = () => {
      if (document.visibilityState !== "visible") return;
      void (async () => {
        const state = await locationPermissionState();
        if (state === "granted") {
          setLocationNotice(null);
          void pushFix();
        }
      })();
    };

    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
  }, [phase, locationNotice, pushFix]);

  // -- rotation check --------------------------------------------------------

  useEffect(() => {
    if (phase !== "ready") return;
    let cancelled = false;

    const check = async () => {
      try {
        const status = await api.checkRotation();
        if (!cancelled && status?.needsReissue) setRotationPrompt(status);
      } catch {
        // A failed check is not worth surfacing: it will be retried on the next
        // roster poll anyway.
      }
    };

    const timer = window.setInterval(() => void check(), 120_000);
    void check();
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [phase]);

  // -- actions ---------------------------------------------------------------

  const completeConsent = async (displayName: string) => {
    await api.setPreferences({
      displayName,
      avatarColor: "#5b8cff",
      acceptedEula: true,
      acceptedLocationDisclosure: true,
      enabledBackgroundLocation: false,
    });
    setEulaAccepted(true);
    setDisclosureAccepted(true);
    setPhase("needs-group");
  };

  const handleCreateGroup = async (input: {
    repoOwner: string;
    repoName: string;
    repoScopedPat: string;
    groupLabel: string;
    joinPassword: string;
    displayName: string;
    releaseTag: string;
    repoCreated: boolean;
  }) => {
    const response = await api.createGroup({
      repoOwner: input.repoOwner,
      repoName: input.repoName,
      repoScopedPat: input.repoScopedPat,
      groupLabel: input.groupLabel,
      joinPassword: input.joinPassword,
      displayName: input.displayName,
      rosterIssueNum: 0,
      chatIssueNum: 0,
      releaseTag: input.releaseTag || null,
      repoCreated: input.repoCreated,
    });

    setGroupLabel(input.groupLabel);
    setFingerprint(response.fingerprint);
    setIsHost(true);
    setInvite({ value: response.invite, fingerprint: response.fingerprint });

    if (!response.hasAdminScope) {
      setBanner({
        kind: "github_auth",
        message:
          "The token lacks Administration read/write, so Destroy Group will not work. Everything else is fine.",
      });
    }

    await loadGroupState();
    setPhase("ready");
  };

  const handleCreateNostrGroup = async (input: {
    groupLabel: string;
    joinPassword: string;
    displayName: string;
  }) => {
    const response = await api.createNostrGroup({
      groupLabel: input.groupLabel,
      joinPassword: input.joinPassword,
      displayName: input.displayName,
    });

    setGroupLabel(input.groupLabel);
    setFingerprint(response.fingerprint);
    setIsHost(true);
    setInvite({ value: response.invite, fingerprint: response.fingerprint });

    await loadGroupState();
    setPhase("ready");
  };

  const handleJoinGroup = async (input: {
    invite: string;
    joinPassword: string;
    displayName: string;
  }) => {
    const response = await api.joinGroup(input);
    setGroupLabel(response.groupLabel);
    setFingerprint(response.fingerprint);
    setIsHost(false);
    if (await api.checkGroupClosed()) {
      await finishClosedGroup("The host has closed this group. Its local vault was wiped; copies may remain elsewhere.");
      return;
    }
    await loadGroupState();
    setPhase("ready");
  };

  const handleBlock = async (pubkeyB64: string, shouldBlockNow: boolean) => {
    try {
      await api.blockMember(pubkeyB64, shouldBlockNow);
      const next = new Set(blocked);
      if (shouldBlockNow) next.add(pubkeyB64);
      else next.delete(pubkeyB64);
      setBlocked(next);

      // Re-read both snapshots: the Rust side filters using the live block list,
      // so the change is already reflected on the next read.
      const [rosterSnapshot, chatSnapshot] = await Promise.all([
        api.rosterSnapshot(),
        api.chatSnapshot(),
      ]);
      setRoster(rosterSnapshot.members);
    setTrails(rosterSnapshot.trails);
      setChat(chatSnapshot.items);
    } catch (thrown) {
      setBanner(api.toAppError(thrown));
    }
  };

  const handleSendFile = async (file: File, caption?: string) => {
    const bytes = await readFileBytes(file);
    const response = await api.sendFile(
      bytes,
      file.name,
      file.type || "application/octet-stream",
      caption,
    );
    if (response.prunedCount > 0) {
      setBanner({
        kind: "payload_too_large",
        message: `Vault was full, so ${response.prunedCount} older file${
          response.prunedCount === 1 ? " was" : "s were"
        } removed to make room.`,
      });
    }
    const snapshot = await api.chatSnapshot();
    setChat(snapshot.items);
  };

  const handleDownload = async (
    assetName: string,
    sha256B64: string,
    mime: string,
  ) => {
    const file = await api.downloadFile(assetName, sha256B64, mime);
    if (!file.sha256Verified) {
      throw {
        kind: "crypto",
        message:
          "The file decrypted but its contents do not match the advertised checksum.",
      } satisfies AppError;
    }
    saveDecryptedFile(file.data, assetName, file.mime);
  };

  const handleReport = (commentId: number, pubkey: string) => {
    setReportTarget({ commentId, pubkey });
  };

  const handleDeleteMessage = async (eventId: string) => {
    const result = await api.deleteOwnMessage(eventId);
    const accepted = result.acceptedRelays.join(", ");
    const unconfirmed = result.unconfirmedRelays.length
      ? ` Unconfirmed: ${result.unconfirmedRelays.join(", ")}.`
      : "";
    return `Deletion request accepted by: ${accepted}.${unconfirmed} Other copies may remain; the next sync updates the chat.`;
  };

  const submitReport = async (reason: string) => {
    if (!reportTarget) return;
    try {
      await api.reportContent(reportTarget.commentId, reportTarget.pubkey, reason);
      const snapshot = await api.chatSnapshot();
      setChat(snapshot.items);
    } catch (thrown) {
      setBanner(api.toAppError(thrown));
    } finally {
      setReportTarget(null);
    }
  };

  const handleRefreshVault = async () => {
    try {
      setVault(await api.vaultReport());
    } catch (thrown) {
      setBanner(api.toAppError(thrown));
    }
  };

  const handleDeleteNostrBlob = async (sha256: string) => {
    const result = await api.deleteNostrBlob(sha256);
    const unconfirmed = result.unconfirmedRelays.length
      ? ` Unconfirmed relays: ${result.unconfirmedRelays.join(", ")}.`
      : "";
    return `Deletion confirmed by ${result.server}. ${result.noticeError
      ? `Notice failed: ${result.noticeError}. Retry the notice from storage.`
      : `Notice accepted by ${result.acceptedRelays.join(", ")}.${unconfirmed}`} Other copies may remain.`;
  };

    const handleToggleBackground = async () => {
      const next = !backgroundEnabled;
      try {
        const response = await api.setBackgroundLocation(next);
        setBackgroundEnabled(response.enabled);
        if (response.warning) {
          setBanner({ kind: "not_configured", message: response.warning });
        }
        if (next) {
          // Background sharing only makes sense with a granted permission; ask now
          // rather than letting the service fail silently.
          const granted = await requestLocationPermission();
          if (!granted) showLocationFailure("permission-denied");
        }
      } catch (thrown) {
        setBanner(api.toAppError(thrown));
      }
    };

  const handleLeave = async () => {
    await api.leaveAndWipe();
    setPhase("needs-group");
    setRoster([]);
    setChat([]);
    setDiagnostics(null);
    setVault(null);
    setSelfFix(null);
    setInvite(null);
  };

  const handleDestroy = async () => {
    const result = await api.destroyGroup();
    const message = result.acceptedRelays.length
      ? `Closure accepted by ${result.acceptedRelays.join(", ")}.${result.unconfirmedRelays.length ? ` Unconfirmed: ${result.unconfirmedRelays.join(", ")}.` : ""} Other devices and copies may remain.`
      : `Group destruction requested. Local vault ${result.vaultWiped ? "wiped" : "could not be wiped"}.`;
    await finishClosedGroup(message);
  };

  /** This device's entry in the roster, for the distance calculation. */
  const selfMember = useMemo(
    () => roster.find((member) => member.isSelf) ?? null,
    [roster],
  );
    void selfMember;

  // -- render ----------------------------------------------------------------

  if (phase === "starting") {
    return (
      <Shell>
        <div className="flex h-full items-center justify-center">
          <p className="text-sm text-slate-400">Opening the secure vault…</p>
        </div>
      </Shell>
    );
  }

  if (phase === "failed") {
    return (
      <Shell>
        <div className="flex h-full flex-col items-center justify-center gap-4 p-6 text-center">
          <h1 className="text-lg font-semibold text-slate-100">
            Shadow720 could not start
          </h1>
          <p className="text-sm text-slate-400">
            {fatalError ? describeError(fatalError) : "An unknown error occurred."}
          </p>
          {fatalError?.kind === "vault_unavailable" ? (
            <p className="text-xs text-slate-500">
              If the device key was invalidated, for example by a factory reset, the
              old vault cannot be recovered. Resetting removes the unreadable local
              vault so a fresh invite can be used.
            </p>
          ) : null}
          {fatalError?.kind === "vault_unavailable" ? (
            <button
              type="button"
              className="btn-danger w-full"
              onClick={() => setConfirmVaultReset(true)}
            >
              Reset local vault
            </button>
          ) : null}
          {confirmVaultReset ? (
            <ConfirmSheet
              title="Reset the local vault?"
              body="The unreadable vault on this device will be deleted. Any group you were in must be rejoined with a fresh invite; nothing on the relays or other devices is affected."
              confirmLabel="Reset vault"
              onCancel={() => setConfirmVaultReset(false)}
              onConfirm={() => void (async () => {
                try {
                  await api.resetVault();
                  setConfirmVaultReset(false);
                  setFatalError(null);
                  setPhase("needs-consent");
                } catch (thrown) {
                  setFatalError(api.toAppError(thrown));
                  setConfirmVaultReset(false);
                }
              })()}
            />
          ) : null}
        </div>
      </Shell>
    );
  }

  if (phase === "needs-consent") {
    return (
      <Shell>
        <ConsentGate
          eulaAccepted={eulaAccepted}
          disclosureAccepted={disclosureAccepted}
          onComplete={completeConsent}
        />
      </Shell>
    );
  }

  if (phase === "legacy-recovery") {
    return (
      <Shell>
        <div className="flex h-full flex-col items-center justify-center gap-4 p-6 text-center">
          <h1 className="text-lg font-semibold">Older group cannot be restored</h1>
          <p className="text-sm text-slate-400">
            This vault predates saved group identities. Its original host identity cannot be recovered.
            Keep the vault if you need to preserve it, or discard it to join a group with a fresh invite.
          </p>
          <button className="btn-danger" onClick={() => setConfirmLegacyDiscard(true)}>Discard older vault</button>
          {confirmLegacyDiscard ? (
            <ConfirmSheet
              title="Discard this older local vault?"
              body="Its keys and credentials will be removed. This cannot recover the old host identity."
              confirmLabel="Discard vault"
              onCancel={() => setConfirmLegacyDiscard(false)}
              onConfirm={() => void (async () => {
                try {
                  await api.discardLegacyGroup();
                  await finishClosedGroup("The older local vault was discarded. Join with a fresh invite or create a new group.");
                } catch (thrown) {
                  setFatalError(api.toAppError(thrown));
                  setPhase("failed");
                }
              })()}
            />
          ) : null}
        </div>
      </Shell>
    );
  }

  if (phase === "needs-group") {
    return (
      <Shell>
        <GroupSetup
          banner={banner}
          onDismissBanner={() => setBanner(null)}
          onCreate={handleCreateGroup}
          onCreateNostr={handleCreateNostrGroup}
          onJoin={handleJoinGroup}
        />
      </Shell>
    );
  }

  return (
    <Shell>
      <div className="flex h-full flex-col">
        <header className="flex items-center justify-between gap-3 border-b border-surface-border px-4 py-3">
          <div className="min-w-0">
            <button
              type="button"
              className="flex min-w-0 items-center gap-1 text-left"
              onClick={() => setShowGroups(true)}
              title="Switch group"
            >
              <h1 className="truncate text-sm font-semibold text-slate-100">
                {groupLabel || "Shadow720"}
              </h1>
              {groups.length > 1 ? (
                <span className="shrink-0 text-[10px] text-slate-500">▾</span>
              ) : null}
            </button>
            <p className="truncate text-[10px] text-slate-500">
              {diagnostics?.repoFullName ?? "connected"} · you are{" "}
              <span className="font-mono">{fingerprint || "—"}</span>
            </p>
          </div>
          <StatusDot
            halted={diagnostics?.haltedUntilUnixS ?? null}
            remaining={diagnostics?.remainingRequests ?? null}
          />
        </header>

        {banner ? (
          <div className="px-4 pt-3">
            <ErrorBanner
              message={describeError(banner)}
              onDismiss={() => setBanner(null)}
            />
          </div>
        ) : null}

        {locationNotice ? (
          <div className="px-4 pt-3">
            <InfoBanner
              message={locationNotice.message}
              tone="warn"
              action={
                locationNotice.remedy
                  ? {
                      label: locationRemedyLabel(locationNotice.remedy),
                      onClick: () => void handleLocationRemedy(locationNotice.remedy!),
                    }
                  : undefined
              }
            />
          </div>
        ) : null}

        <main className="min-h-0 flex-1 px-4 pt-3">
          {tab === "map" ? (
            <MapPanel
              members={roster}
              selfFix={selfFix}
              trails={trails}
              selectedPubkey={selectedPubkey}
              onSelect={setSelectedPubkey}
            />
          ) : null}

          {tab === "chat" ? (
            <ChatDrawer
              items={chat}
              roster={roster}
              selfPubkey={selfPubkey}
              blockedPubkeys={blocked}
              onSendFile={handleSendFile}
              onDownload={handleDownload}
              onBlock={handleBlock}
              onReport={handleReport}
              onDeleteMessage={handleDeleteMessage}
            />
          ) : null}

          {tab === "settings" ? (
            <SettingsPanel
              diagnostics={diagnostics}
              roster={roster}
              blockedPubkeys={blocked}
              vault={vault}
              isHost={isHost}
                            backgroundEnabled={backgroundEnabled}
                            onToggleBackground={handleToggleBackground}
                            locationIssue={
                              locationNotice?.remedy
                                ? {
                                    message: locationNotice.message,
                                    actionLabel: locationRemedyLabel(locationNotice.remedy),
                                  }
                                : null
                            }
                            onFixLocation={() => {
                              if (locationNotice?.remedy) {
                                void handleLocationRemedy(locationNotice.remedy);
                              }
                            }}
                            onBlock={handleBlock}
              onRefreshVault={handleRefreshVault}
              onDeleteNostrBlob={handleDeleteNostrBlob}
              onRotate={async (joinPassword, removePubkeys) => {
                const response = await api.rotateGroupKey(
                  joinPassword,
                  removePubkeys,
                );
                await loadGroupState();
                return response.invites;
              }}
              onRekey={async (newPat, joinPassword) => {
                const response = await api.rekeyGroup(newPat, joinPassword);
                await loadGroupState();
                return response.invites;
              }}
              onLeave={handleLeave}
              onDestroy={handleDestroy}
              onClose={() => setTab("map")}
            />
          ) : null}
        </main>

        <nav className="grid grid-cols-3 border-t border-surface-border">
          {(["map", "chat", "settings"] as const).map((option) => (
            <button
              key={option}
              type="button"
              onClick={() => setTab(option)}
              className={`py-3 text-xs font-semibold capitalize transition-colors ${
                tab === option
                  ? "text-accent"
                  : "text-slate-500 hover:text-slate-300"
              }`}
            >
              {option}
              {option === "chat" && chat.length > 0 ? (
                <span className="ml-1 text-[10px] text-slate-600">{chat.length}</span>
              ) : null}
            </button>
          ))}
        </nav>
      </div>

      {showGroups ? (
        <Modal
          title="Your groups"
          secondaryLabel="Close"
          onSecondary={() => setShowGroups(false)}
        >
          <div className="space-y-2">
            {groups.map((group) => (
              <button
                key={group.id}
                type="button"
                disabled={group.isActive}
                onClick={() => void handleSwitchGroup(group.id)}
                className={`flex w-full items-center justify-between gap-3 rounded-xl border p-3 text-left ${
                  group.isActive
                    ? "border-accent bg-surface"
                    : "border-surface-border bg-surface-raised hover:border-accent"
                }`}
              >
                <span className="min-w-0">
                  <span className="block truncate text-sm font-semibold text-slate-100">
                    {group.label}
                  </span>
                  <span className="block truncate text-[10px] text-slate-500">
                    {group.backend}
                  </span>
                </span>
                {group.isActive ? (
                  <span className="pill shrink-0 bg-accent/20 text-accent">current</span>
                ) : null}
              </button>
            ))}
          </div>
          <p className="text-xs text-slate-500">
            Switching is local and works offline. Each group keeps its own keys,
            messages, and positions on this device.
          </p>
        </Modal>
      ) : null}

      {invite ? (
        <InviteDisplay
          invite={invite.value}
          fingerprint={invite.fingerprint}
          label="Group created — invite someone"
          onDone={() => setInvite(null)}
          hint="Send this string plus the join password. That is everything a guest needs."
        />
      ) : null}

      {rotationPrompt ? (
        <Modal
          title="The group key was rotated"
          primaryLabel="Ask the host for a new invite"
          onPrimary={() => setRotationPrompt(null)}
          secondaryLabel="Later"
          onSecondary={() => setRotationPrompt(null)}
        >
          <p>
            The host rotated the group key, so this device can no longer read new
            messages or positions in this group.
          </p>
          <p className="text-xs text-slate-400">
            Ask the host for a fresh invite string and join again. Messages sent before
            the rotation remain readable.
          </p>
        </Modal>
      ) : null}

      {reportTarget ? (
        <ReportSheet
          commentId={reportTarget.commentId}
          onCancel={() => setReportTarget(null)}
          onSubmit={(reason) => void submitReport(reason)}
        />
      ) : null}
    </Shell>
  );
}

/** App chrome: a phone-shaped column on wide screens, full-bleed on a phone. */
function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-full justify-center bg-slate-950">
      <div className="flex h-full w-full max-w-md flex-col overflow-hidden bg-surface">
        {children}
      </div>
    </div>
  );
}

/** Small sync indicator: green ready, amber paused. */
function StatusDot({
  halted,
  remaining,
}: {
  halted: number | null;
  remaining: number | null;
}) {
  const paused = halted !== null && halted * 1000 > Date.now();
  return (
    <span
      className={`flex shrink-0 items-center gap-1.5 rounded-full border px-2 py-1 text-[10px] ${
        paused
          ? "border-amber-800 bg-amber-950/60 text-amber-200"
          : "border-surface-border bg-surface-raised text-slate-400"
      }`}
      title={
        remaining === null
          ? "GitHub request budget unknown"
          : `${remaining} GitHub requests left this hour`
      }
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${
          paused ? "bg-amber-400" : "bg-emerald-400"
        }`}
      />
      {paused ? "paused" : "synced"}
    </span>
  );
}

interface GroupSetupProps {
  banner: AppError | null;
  onDismissBanner: () => void;
  onCreate: (input: {
    repoOwner: string;
    repoName: string;
    repoScopedPat: string;
    groupLabel: string;
    joinPassword: string;
    displayName: string;
    releaseTag: string;
    repoCreated: boolean;
  }) => Promise<void>;
  onCreateNostr: (input: {
    groupLabel: string;
    joinPassword: string;
    displayName: string;
  }) => Promise<void>;
  onJoin: (input: {
    invite: string;
    joinPassword: string;
    displayName: string;
  }) => Promise<void>;
}

/**
 * Create-or-join screen.
 *
 * Both paths are shown side by side rather than behind a wizard, because the
 * choice is binary and a host who tapped the wrong option would have to re-enter a
 * token to get back.
 */
function GroupSetup({
  banner,
  onDismissBanner,
  onCreate,
  onCreateNostr,
  onJoin,
}: GroupSetupProps) {
  const [mode, setMode] = useState<"join" | "create">("join");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<AppError | null>(null);

  // Join fields.
  const [inviteText, setInviteText] = useState("");
  const [joinPassword, setJoinPassword] = useState("");
  const [displayName, setDisplayName] = useState("");

  // Create fields.
  const [provider, setProvider] = useState<ProviderId>("github");
  const [provision, setProvision] = useState(true);
  const [signedIn, setSignedIn] = useState<api.SignInResponse | null>(null);
  const [allowDestroy, setAllowDestroy] = useState(false);
  const [repoOwner, setRepoOwner] = useState("");
  const [repoName, setRepoName] = useState("");
  const [pat, setPat] = useState("");
  const [label, setLabel] = useState("");
  const [createPassword, setCreatePassword] = useState("");
  const [createName, setCreateName] = useState("");
  const [releaseTag, setReleaseTag] = useState("vault-v1");
  /** Set once the repository exists, so the token step can name it. */
  const [provisioned, setProvisioned] = useState<api.ProvisionResponse | null>(null);

  const selectedProvider = providerById(provider);
  const repoReady = !provision || provisioned !== null;

  const submitJoin = async () => {
    setError(null);
    setBusy(true);
    try {
      await onJoin({
        invite: inviteText.trim(),
        joinPassword,
        displayName: displayName.trim(),
      });
    } catch (thrown) {
      setError(api.toAppError(thrown));
    } finally {
      setBusy(false);
    }
  };

  /** Step one: create the repository so a scoped token can be issued for it. */
  const submitProvision = async () => {
    setError(null);
    setBusy(true);
    try {
      // The signed-in token lives in Rust, so nothing secret is passed here.
      const response = await api.provisionRepository({
        repoName: repoName.trim() || null,
        releaseTag: releaseTag.trim() || null,
      });
      setProvisioned(response);
      setRepoOwner(response.repoOwner);
      setRepoName(response.repoName);
    } catch (thrown) {
      setError(api.toAppError(thrown));
    } finally {
      setBusy(false);
    }
  };

  /** Nostr path: no sign-in, no repository, no token. */
  const submitNostr = async () => {
    setError(null);
    setBusy(true);
    try {
      await onCreateNostr({
        groupLabel: label.trim() || "My group",
        joinPassword: createPassword,
        displayName: createName.trim(),
      });
    } catch (thrown) {
      setError(api.toAppError(thrown));
    } finally {
      setBusy(false);
    }
  };

  /** Step two: create the group against the repository that now exists. */
  const submitCreate = async () => {
    setError(null);
    setBusy(true);
    try {
      // Only trust the provisioned repo while the provision path is selected;
      // switching to "use an existing repo" must not silently reuse it.
      const created = provision ? provisioned : null;
      await onCreate({
        repoOwner: created?.repoOwner ?? repoOwner.trim(),
        repoName: created?.repoName ?? repoName.trim(),
        repoScopedPat: pat.trim(),
        groupLabel: label.trim() || "My group",
        joinPassword: createPassword,
        displayName: createName.trim(),
        releaseTag: releaseTag.trim(),
        repoCreated: created !== null,
      });
    } catch (thrown) {
      setError(api.toAppError(thrown));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full flex-col">
      <header className="border-b border-surface-border px-4 py-4">
        <h1 className="text-base font-semibold text-slate-100">Shadow720</h1>
        <p className="mt-1 text-xs text-slate-500">
          Encrypted on this device before anything is stored. No server holds your
          group's data.
        </p>
      </header>

      <div className="flex gap-1 border-b border-surface-border px-4 pt-3">
        {(["join", "create"] as const).map((option) => (
          <button
            key={option}
            type="button"
            onClick={() => setMode(option)}
            className={`rounded-t-xl px-4 py-2 text-xs font-semibold ${
              mode === option
                ? "border border-b-0 border-surface-border bg-surface-raised text-slate-100"
                : "text-slate-500 hover:text-slate-300"
            }`}
          >
            {option === "join" ? "Join a group" : "Create a group"}
          </button>
        ))}
      </div>

      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
        {banner ? (
          <ErrorBanner
            message={describeError(banner)}
            onDismiss={onDismissBanner}
          />
        ) : null}
        {error ? (
          <ErrorBanner message={describeError(error)} onDismiss={() => setError(null)} />
        ) : null}

        {mode === "join" ? (
          <>
            <TextArea
              label="Invite string"
              value={inviteText}
              onChange={setInviteText}
              placeholder="GRP1-…"
              rows={4}
              hint="Paste the whole string, including the GRP1- prefix."
            />
            <Field
              label="Join password"
              type="password"
              value={joinPassword}
              onChange={setJoinPassword}
              placeholder="The group's password"
              hint="Given to you separately from the invite."
            />
            <Field
              label="Your display name"
              value={displayName}
              onChange={setDisplayName}
              placeholder="Jared"
            />
            <button
              type="button"
              className="btn-primary w-full"
              disabled={
                busy ||
                inviteText.trim().length === 0 ||
                joinPassword.length === 0 ||
                displayName.trim().length === 0
              }
              onClick={() => void submitJoin()}
            >
              {busy ? "Joining…" : "Join group"}
            </button>
          </>
        ) : (
          <>
            <ProviderPicker value={provider} onChange={setProvider} />

            {selectedProvider.available ? null : (
              <InfoBanner
                tone="warn"
                message={`${selectedProvider.label} is not available yet. Pick GitHub to create a group now.`}
              />
            )}

            {provider === "nostr" ? (
              <>
                <InfoBanner message="No account and no setup. A keypair is generated on this device, and the invite carries no credential — each member signs their own events." />
                <Field
                  label="Group name"
                  value={label}
                  onChange={setLabel}
                  placeholder="Weekend trip"
                />
                <Field
                  label="Join password"
                  type="password"
                  value={createPassword}
                  onChange={setCreatePassword}
                  placeholder="Something only your members know"
                  hint="Protects the invite string. Share it out of band."
                />
                <Field
                  label="Your display name"
                  value={createName}
                  onChange={setCreateName}
                  placeholder="Jared"
                />
                <button
                  type="button"
                  className="btn-primary w-full"
                  disabled={
                    busy ||
                    createPassword.length === 0 ||
                    createName.trim().length === 0
                  }
                  onClick={() => void submitNostr()}
                >
                  {busy ? "Creating…" : "Create group"}
                </button>
              </>
            ) : (
              <>
            <div className="flex gap-1 rounded-xl border border-surface-border p-1">
              {(
                [
                  { id: true, label: "Create a new repo" },
                  { id: false, label: "Use an existing repo" },
                ] as const
              ).map((option) => (
                <button
                  key={String(option.id)}
                  type="button"
                  onClick={() => {
                    setProvision(option.id);
                    // A repo provisioned under the other mode must not leak in.
                    setProvisioned(null);
                  }}
                  className={`flex-1 rounded-lg px-3 py-2 text-xs font-semibold ${
                    provision === option.id
                      ? "bg-surface-raised text-slate-100"
                      : "text-slate-500 hover:text-slate-300"
                  }`}
                >
                  {option.label}
                </button>
              ))}
            </div>

            {provision ? (
              provisioned ? (
                <InfoBanner
                  message={`Created ${provisioned.repoFullName} with both schema issues and the vault release. Now create a fine-grained token scoped to just that repository.`}
                />
              ) : (
                <>
                  <InfoBanner message="Step 1 of 2. Sign in and the app creates the private repository, both schema issues, and the vault release for you. Nothing to set up by hand." />
                  <SignInPanel
                    allowDestroy={allowDestroy}
                    onAllowDestroyChange={setAllowDestroy}
                    onSignedIn={setSignedIn}
                  />
                  {signedIn ? (
                    <>
                      <Field
                        label="Repository name"
                        value={repoName}
                        onChange={setRepoName}
                        placeholder="Leave blank to generate one"
                        hint="Created private, with an initial commit so the vault release can be tagged."
                      />
                      <Field
                        label="Release tag"
                        value={releaseTag}
                        onChange={setReleaseTag}
                        hint="Created automatically when it does not exist."
                      />
                      <button
                        type="button"
                        className="btn-primary w-full"
                        disabled={busy || !selectedProvider.available}
                        onClick={() => void submitProvision()}
                      >
                        {busy ? "Creating repository…" : "Create repository"}
                      </button>
                    </>
                  ) : null}
                </>
              )
            ) : (
              <>
                <InfoBanner message="Point the app at a repository you already own. Missing issues and the vault release are created automatically." />
                <div className="grid grid-cols-2 gap-3">
                  <Field
                    label="Repo owner"
                    value={repoOwner}
                    onChange={setRepoOwner}
                    placeholder="JaredCH"
                  />
                  <Field
                    label="Repo name"
                    value={repoName}
                    onChange={setRepoName}
                    placeholder="grp-9f8a7b6c"
                  />
                </div>
                <Field
                  label="Release tag"
                  value={releaseTag}
                  onChange={setReleaseTag}
                  hint="Created automatically when it does not exist."
                />
              </>
            )}

            {repoReady ? (
              <>
                {provision ? (
                  <InfoBanner message="Step 2 of 2. Name the group and pick a join password. The signed-in account is used automatically." />
                ) : null}

                <details className="rounded-xl border border-surface-border p-3">
                  <summary className="cursor-pointer text-xs font-semibold text-slate-400">
                    Use a repository-scoped token instead (optional, safer)
                  </summary>
                  <div className="mt-3">
                    <Field
                      label="Repository token"
                      type="password"
                      value={pat}
                      onChange={setPat}
                      placeholder="github_pat_…"
                      hint="Leave blank to use the signed-in account. A token scoped to this one repository limits what an invite can do."
                    />
                  </div>
                </details>

                <Field
                  label="Group name"
                  value={label}
                  onChange={setLabel}
                  placeholder="Weekend trip"
                />

                <Field
                  label="Join password"
                  type="password"
                  value={createPassword}
                  onChange={setCreatePassword}
                  placeholder="Something only your members know"
                  hint="Protects the invite string. Share it out of band."
                />

                <Field
                  label="Your display name"
                  value={createName}
                  onChange={setCreateName}
                  placeholder="Jared"
                />

                <button
                  type="button"
                  className="btn-primary w-full"
                  disabled={
                    busy ||
                    !selectedProvider.available ||
                    createPassword.length === 0 ||
                    createName.trim().length === 0 ||
                    (!provision &&
                      (repoOwner.trim().length === 0 || repoName.trim().length === 0))
                  }
                  onClick={() => void submitCreate()}
                >
                  {busy ? "Creating…" : "Create group"}
                </button>
              </>
            ) : null}
              </>
            )}
          </>
        )}
      </div>
    </div>
  );
}

/** Reason-picking sheet for reporting a message. */
function ReportSheet({
  commentId,
  onCancel,
  onSubmit,
}: {
  commentId: number;
  onCancel: () => void;
  onSubmit: (reason: string) => void;
}) {
  const [reason, setReason] = useState("");
  const reasons = ["Spam", "Harassment", "Illegal content", "Copyright"];

  return (
    <Modal
      title={`Report message #${commentId}`}
      primaryLabel="Send report"
      onPrimary={() => onSubmit(reason.trim())}
      secondaryLabel="Cancel"
      onSecondary={onCancel}
    >
      <p className="text-xs text-slate-400">
        The host sees this report and can delete the message. Nobody is told who
        reported it.
      </p>
      <div className="flex flex-wrap gap-2">
        {reasons.map((option) => (
          <button
            key={option}
            type="button"
            className={`rounded-full border px-3 py-1 text-xs ${
              reason === option
                ? "border-accent bg-accent/15 text-accent"
                : "border-surface-border text-slate-400"
            }`}
            onClick={() => setReason(option)}
          >
            {option}
          </button>
        ))}
      </div>
      <Field label="Details" value={reason} onChange={setReason} placeholder="Reason" />
    </Modal>
  );
}

/**
 * Resolve the directory the vault lives in.
 *
 * Tauri exposes its per-app data path; without the runtime there is nothing to
 * resolve against, so the caller falls into the preview path instead.
 */
async function resolveVaultDir(): Promise<string> {
  const internals = (globalThis as { __TAURI_INTERNALS__?: unknown })
    .__TAURI_INTERNALS__;
  if (!internals) {
    throw {
      kind: "not_configured",
      message: "no native runtime",
    } satisfies AppError;
  }
  const path = await import("@tauri-apps/api/path");
  return path.appDataDir();
}