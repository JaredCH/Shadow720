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
  hasBackgroundLocation,
  locationPermissionState,
  locationRemedy,
  locationRemedyLabel,
  openLocationRemedy,
  readBattery,
  requestLocationPermission,
  requestNotificationPermission,
} from "./lib/location";
import type { LocationFailure, LocationRemedy } from "./lib/location";
import { ChatDrawer, readFileBytes, saveDecryptedFile } from "./components/ChatDrawer";
import { ConsentGate, InviteDisplay } from "./components/ConsentGate";
import { ConfirmSheet, ErrorBanner, Field, InfoBanner, Modal, TextArea } from "./components/Modal";
import { MapPanel } from "./components/MapPanel";
import { PeopleSheet } from "./components/PeopleSheet";
import { ProviderPicker } from "./components/ProviderPicker";
import type { ProviderId } from "./components/ProviderPicker";
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
const MIN_CHAT_DELAY_MS = 1_000;

/**
 * Build version, shown on the failure screen.
 *
 * Without it there is no way to tell which APK is installed, which made a
 * report of an already-fixed bug indistinguishable from a new one.
 */
const APP_VERSION = "0.1.9";
const MIN_ROSTER_DELAY_MS = 3_000;

/** How often to refresh the local GPS fix while the map tab is visible. */
const FIX_INTERVAL_MS = 10_000;

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
  const [showAddGroup, setShowAddGroup] = useState(false);
  const [showPeople, setShowPeople] = useState(false);
  const [askInvitePassword, setAskInvitePassword] = useState(false);
  const [invitePassword, setInvitePassword] = useState("");
  const [locationNotice, setLocationNotice] = useState<{
    message: string;
    remedy: LocationRemedy | null;
  } | null>(null);
  /** Fixes cached while offline, so the UI can say sharing is deferred. */
  const [pendingLocations, setPendingLocations] = useState(0);
  /**
   * Mirror of `pendingLocations` for the poll loop.
   *
   * The loop is created once per phase, so reading the state directly would
   * capture the value from the render that created it and never see an update.
   */
  const pendingRef = useRef(0);
  useEffect(() => {
    pendingRef.current = pendingLocations;
  }, [pendingLocations]);
  const [selectedPubkey, setSelectedPubkey] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("map");
  const [banner, setBanner] = useState<AppError | null>(null);
  const [invite, setInvite] = useState<{
    value: string;
    fingerprint: string;
    containsToken: boolean;
  } | null>(null);
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

  /**
   * Open the vault and route to the right phase.
   *
   * Extracted from the mount effect so the reset flow can reuse it: wiping the
   * vault leaves no open handle, so the only way forward is to unlock again.
   */
  const bootstrap = useCallback(async () => {
    try {
      // The vault directory is provided by the shell at runtime; the Rust side
      // treats it as opaque, so the browser preview simply lacks one.
      const vaultDir = await resolveVaultDir();
      const unlocked = await api.unlockVault({ vaultDir });

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
  }, [finishClosedGroup, loadGroupState]);

  // -- bootstrap -------------------------------------------------------------

  useEffect(() => {
    void bootstrap();
  }, [bootstrap]);

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

  /**
   * Publish whatever was cached while offline.
   *
   * Called when the browser reports the connection is back, after a roster poll
   * succeeds, and once at startup. All three are needed: the `online` event does
   * not fire on Android when a relay merely becomes reachable again, a poll is the
   * only proof that a relay actually answers, and a restart may have left a queue
   * on disk from a previous session.
   */
  const flushPending = useCallback(async () => {
    try {
      const flushed = await api.flushPendingLocations();
      if (flushed > 0) {
        const snapshot = await api.rosterSnapshot();
        setRoster(snapshot.members);
        setTrails(snapshot.trails);
      }
      setPendingLocations(0);
    } catch {
      // Still offline, or the relay refused. The queue is intact and the next
      // reconnect will try again, so this is not worth a banner.
    }
  }, []);

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

      // A successful poll is the only proof that a relay actually answers, which
      // is what the `online` event cannot tell us on Android. Anything cached
      // while offline is published now.
      if (pendingRef.current > 0) void flushPending();

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
  }, [flushPending]);

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

    // Battery is read alongside the fix rather than on its own timer: the two are
    // published together, and a separate loop would only add wakeups.
    const battery = await readBattery();

    try {
      const response = await api.updateLocation(result.fix.lat, result.fix.lon, {
        speedMps: result.fix.speedMps,
        headingDeg: result.fix.headingDeg,
        accuracyM: result.fix.accuracyM,
        batteryPct: battery?.pct,
        isCharging: battery?.charging,
      });
      // A queued fix is not an error: the core kept it and will replay it. The
      // count is what the banner reports, so the user knows sharing is deferred
      // rather than broken.
      setPendingLocations(response.pending);
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
      if (state === "system-disabled") {
        showLocationFailure("system-disabled");
        return;
      }
      if (state !== "granted") {
        const granted = await requestLocationPermission();
        if (!granted) {
          const after = await locationPermissionState();
          if (after === "granted") {
            void tick();
            return;
          }
          showLocationFailure(
            after === "system-disabled" ? "system-disabled" : "permission-denied",
          );
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
        } else if (state === "system-disabled") {
          showLocationFailure("system-disabled");
        }
      })();
    };

    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
  }, [phase, locationNotice, pushFix, showLocationFailure]);

  // -- offline cache ---------------------------------------------------------

  /**
   * Publish cached fixes when the connection returns.
   *
   * The `online` event is the fastest signal on desktop and in the browser, but it
   * is not sufficient on its own: Android does not fire it when a relay merely
   * becomes reachable again, and a restart can leave a queue on disk from a
   * previous session. The roster poll and the startup call cover those cases.
   */
  useEffect(() => {
    if (phase !== "ready") return;

    const onOnline = () => void flushPending();
    window.addEventListener("online", onOnline);
    // A queue may have survived the last session, so try once on entry.
    void flushPending();

    return () => window.removeEventListener("online", onOnline);
  }, [phase, flushPending]);

  // -- native background fixes -----------------------------------------------

  /**
   * Consume fixes from the Android foreground service.
   *
   * The service keeps producing positions with the screen off, but until this
   * listener existed nothing read them, so background sharing looked enabled while
   * the pin never moved. Each fix is published through the same command the
   * foreground loop uses, so the movement gate and cadence policy still apply.
   */
  useEffect(() => {
    if (phase !== "ready" || !disclosureAccepted) return;
    let cancelled = false;
    let unsubscribe: (() => void) | null = null;

    void (async () => {
      const stop = await api.onNativeFix((fix) => {
        if (cancelled || activePhase.current !== "ready") return;
        if (!Number.isFinite(fix.lat) || !Number.isFinite(fix.lon)) return;
        setSelfFix({ lat: fix.lat, lon: fix.lon });
        void api
          .updateLocation(fix.lat, fix.lon, {
            speedMps: fix.speedMps >= 0 ? fix.speedMps : undefined,
            headingDeg: fix.headingDeg >= 0 ? fix.headingDeg : undefined,
            accuracyM: fix.accuracyM > 0 ? fix.accuracyM : undefined,
            batteryPct: fix.batteryPct >= 0 ? fix.batteryPct : undefined,
            isCharging: fix.isCharging,
          })
          .then(async (response) => {
            if (cancelled) return;
            // The service publishes with the screen off, so this is the only place
            // the deferred count can be updated while the app is backgrounded.
            setPendingLocations(response.pending);
            const snapshot = await api.rosterSnapshot();
            if (cancelled) return;
            setRoster(snapshot.members);
            setTrails(snapshot.trails);
          })
          .catch(() => {
            // A failed publish is retried by the next fix; the foreground loop
            // also keeps running, so this is not worth a banner.
          });
      });
      if (cancelled) stop();
      else unsubscribe = stop;
    })();

    return () => {
      cancelled = true;
      unsubscribe?.();
    };
  }, [phase, disclosureAccepted]);

  // -- location history ------------------------------------------------------

  /**
   * Load a member's track history for the map's history panel.
   *
   * Local only, so this is cheap and works offline. The core clamps the range to
   * the retention window.
   */
  const loadHistory = useCallback(async (pubkeyB64: string, hours: number) => {
    const response = await api.locationHistory({ pubkeyB64, hours });
    return response.tracks[pubkeyB64] ?? [];
  }, []);

  // Persist the track log periodically and whenever the app is backgrounded.
  //
  // Writing on every fix would be a file write every ten seconds; writing only on
  // exit would lose the session when Android kills the process. A minute is the
  // compromise, and the visibility hook covers the common "user swiped away" case.
  useEffect(() => {
    if (phase !== "ready") return;

    const save = () => {
      void api.saveLocationHistory().catch(() => {
        // Losing history is not worth interrupting the user over; the next save
        // will try again.
      });
    };

    const timer = window.setInterval(save, 60_000);
    const onHidden = () => {
      if (document.visibilityState === "hidden") save();
    };
    document.addEventListener("visibilitychange", onHidden);

    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onHidden);
      save();
    };
  }, [phase]);

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
    setInvite({
      value: response.invite,
      fingerprint: response.fingerprint,
      containsToken: false,
    });
    setShowAddGroup(false);

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
    setShowAddGroup(false);
    setPhase("ready");
  };

  const handleSendText = async (text: string) => {
    await api.sendText(text);
    const snapshot = await api.chatSnapshot();
    setChat(snapshot.items);
  };

  const openInvite = async () => {
    try {
      const stored = await api.currentInvite();
      if (stored) {
        setInvite({
          value: stored,
          fingerprint,
          containsToken: !diagnostics?.accountless,
        });
        return;
      }
      setInvitePassword("");
      setAskInvitePassword(true);
    } catch (thrown) {
      setBanner(api.toAppError(thrown));
    }
  };

  const submitShareInvite = async () => {
    try {
      const response = await api.shareInvite(invitePassword);
      setAskInvitePassword(false);
      setInvitePassword("");
      setInvite({
        value: response.invite,
        fingerprint: response.fingerprint,
        containsToken: !diagnostics?.accountless,
      });
    } catch (thrown) {
      setBanner(api.toAppError(thrown));
    }
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

    if (next) {
      // Order matters, and Play checks it: the in-app disclosure is already
      // acknowledged by the time this runs, then the foreground grant, then the
      // notification permission the foreground service needs to be visible, and
      // only then the background grant — which on Android 11+ is a settings trip,
      // not a dialog.
      const foreground = await requestLocationPermission();
      if (!foreground) {
        const state = await locationPermissionState();
        showLocationFailure(
          state === "system-disabled" ? "system-disabled" : "permission-denied",
        );
        return;
      }

      const notifications = await requestNotificationPermission();
      if (!notifications) {
        setBanner({
          kind: "not_configured",
          message:
            "Notifications are off, so Android would hide the notice that your position is being shared. Turn notifications on for Shadow720, then try again.",
        });
        return;
      }

      const background = await hasBackgroundLocation();
      if (!background) {
        setBanner({
          kind: "not_configured",
          message:
            "Android needs \"Allow all the time\" for location before sharing can continue with the app closed. Open Settings, choose Permissions → Location, and pick Allow all the time.",
        });
        // The settings page is where the grant lives; there is no dialog for it.
        await openLocationRemedy("app-settings");
        return;
      }
    }

    try {
      const response = await api.setBackgroundLocation(next);
      setBackgroundEnabled(response.enabled);
      if (response.warning) {
        setBanner({ kind: "not_configured", message: response.warning });
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
          <p className="text-[10px] font-mono text-slate-600">
            version {APP_VERSION}
          </p>
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
                  // The vault is not open here: unlocking is what failed. Pass the
                  // directory explicitly, then re-run the bootstrap so the app
                  // lands on a fresh vault instead of the same error screen.
                  await api.resetVault(await resolveVaultDir());
                  setConfirmVaultReset(false);
                  setFatalError(null);
                  setPhase("starting");
                  await bootstrap();
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
          onCreateNostr={handleCreateNostrGroup}
          onJoin={handleJoinGroup}
        />
      </Shell>
    );
  }

  return (
    <Shell>
      <div className="flex h-full">
        <Sidebar tab={tab} onSelect={setTab} chatCount={chat.length} />
        <div className="flex h-full min-w-0 flex-1 flex-col">
        <header className="border-b border-surface-border px-4 pb-3 pt-[max(0.75rem,env(safe-area-inset-top))]">
          <div className="flex items-center justify-between gap-3">
            <div className="min-w-0">
              <h1 className="truncate text-sm font-semibold text-slate-100">
                {groupLabel || "Shadow720"}
              </h1>
              <p className="truncate text-[10px] text-slate-500">
                {diagnostics?.groupRef ?? "connected"} · you are{" "}
                <span className="font-mono">{fingerprint || "—"}</span>
              </p>
            </div>
            <StatusDot
              halted={diagnostics?.haltedUntilUnixS ?? null}
              remaining={diagnostics?.remainingRequests ?? null}
            />
          </div>
          <div className="mt-2 flex gap-2">
            <button
              type="button"
              className="btn-secondary px-2 py-1 text-[10px]"
              onClick={() => setShowGroups(true)}
            >
              Groups
            </button>
            <button
              type="button"
              className="btn-secondary px-2 py-1 text-[10px]"
              onClick={() => void openInvite()}
            >
              Invite
            </button>
            <button
              type="button"
              className="btn-secondary px-2 py-1 text-[10px]"
              onClick={() => setShowPeople(true)}
            >
              People
            </button>
          </div>
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

        {pendingLocations > 0 ? (
          <div className="px-4 pt-3">
            <InfoBanner
              message={`No relay is reachable, so ${pendingLocations} position${
                pendingLocations === 1 ? "" : "s"
              } ${pendingLocations === 1 ? "is" : "are"} cached on this device. ${
                pendingLocations === 1 ? "It" : "They"
              } will be sent automatically when the connection returns.`}
              tone="warn"
              action={{ label: "Retry now", onClick: () => void flushPending() }}
            />
          </div>
        ) : null}
        <main className="min-h-0 flex-1 px-4 pt-3 lg:px-6">
          {tab === "map" ? (
            <MapPanel
              members={roster}
              selfFix={selfFix}
              trails={trails}
              selectedPubkey={selectedPubkey}
              onSelect={setSelectedPubkey}
              onLoadHistory={loadHistory}
            />
          ) : null}

          {tab === "chat" ? (
            <ChatDrawer
              items={chat}
              roster={roster}
              selfPubkey={selfPubkey}
              blockedPubkeys={blocked}
              onSendText={handleSendText}
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
              onLeave={handleLeave}
              onDestroy={handleDestroy}
              onClose={() => setTab("map")}
            />
          ) : null}
        </main>

        <nav className="grid grid-cols-3 border-t border-surface-border pb-[env(safe-area-inset-bottom)] lg:hidden">
          {TABS.map((option) => (
            <button
              key={option.id}
              type="button"
              onClick={() => setTab(option.id)}
              className={`py-3 text-xs font-semibold capitalize transition-colors ${
                tab === option.id
                  ? "text-accent"
                  : "text-slate-500 hover:text-slate-300"
              }`}
            >
              {option.label}
              {option.id === "chat" && chat.length > 0 ? (
                <span className="ml-1 text-[10px] text-slate-600">{chat.length}</span>
              ) : null}
            </button>
          ))}
        </nav>
        </div>
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
          <button
            type="button"
            className="btn-secondary w-full"
            onClick={() => {
              setShowGroups(false);
              setShowAddGroup(true);
            }}
          >
            Join or create another group
          </button>
          <p className="text-xs text-slate-500">
            Switching is local and works offline. Each group keeps its own keys,
            messages, and positions on this device.
          </p>
        </Modal>
      ) : null}

      {showAddGroup ? (
        <div className="fixed inset-0 z-40 bg-surface">
          <GroupSetup
            banner={banner}
            onDismissBanner={() => setBanner(null)}
            onCancel={() => setShowAddGroup(false)}
            onCreateNostr={handleCreateNostrGroup}
            onJoin={handleJoinGroup}
          />
        </div>
      ) : null}

      {showPeople ? (
        <PeopleSheet
          roster={roster}
          isHost={isHost}
          accountless={diagnostics?.accountless ?? false}
          onClose={() => setShowPeople(false)}
          onSetRole={async (pubkey, role) => {
            await api.setMemberRole(pubkey, role);
            await loadGroupState();
          }}
          onKick={async (pubkey, password) => {
            const response = await api.rotateGroupKey(
              password,
              [pubkey],
              "removed by owner",
            );
            await loadGroupState();
            return response;
          }}
        />
      ) : null}

      {askInvitePassword ? (
        <Modal
          title="Group code"
          primaryLabel="Show code"
          onPrimary={() => void submitShareInvite()}
          secondaryLabel="Cancel"
          onSecondary={() => setAskInvitePassword(false)}
          busy={invitePassword.length === 0}
        >
          <p>
            This device does not have a saved group code. Enter the join password
            to pack one. The recipient needs that password too.
          </p>
          <Field
            label="Join password"
            type="password"
            value={invitePassword}
            onChange={setInvitePassword}
            autoComplete="current-password"
          />
        </Modal>
      ) : null}

      {invite ? (
        <InviteDisplay
          invite={invite.value}
          fingerprint={invite.fingerprint}
          label="Group code"
          containsToken={invite.containsToken}
          onDone={() => setInvite(null)}
          hint="Send this code plus the join password. That is everything a guest needs."
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

/**
 * App chrome: a phone-shaped column on narrow screens, a full-width desktop
 * surface on wide screens. The ready view adds its own sidebar on `lg+`.
 */
function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-full justify-center bg-slate-950">
      <div className="flex h-full w-full max-w-md flex-col overflow-hidden bg-surface lg:max-w-none">
        {children}
      </div>
    </div>
  );
}

/** The three top-level destinations, shared by the desktop sidebar and the mobile tab bar. */
const TABS: { id: Tab; label: string }[] = [
  { id: "map", label: "Map" },
  { id: "chat", label: "Chat" },
  { id: "settings", label: "Settings" },
];

/** Desktop left-hand navigation rail. */
function Sidebar({
  tab,
  onSelect,
  chatCount,
}: {
  tab: Tab;
  onSelect: (tab: Tab) => void;
  chatCount: number;
}) {
  return (
    <aside className="hidden w-56 shrink-0 flex-col border-r border-surface-border bg-surface-raised/40 lg:flex">
      <div className="border-b border-surface-border px-4 py-4">
        <h1 className="text-sm font-semibold text-slate-100">Shadow720</h1>
        <p className="mt-0.5 text-[10px] text-slate-500">E2EE · no server</p>
      </div>
      <nav className="flex flex-col gap-1 p-2">
        {TABS.map((option) => (
          <button
            key={option.id}
            type="button"
            onClick={() => onSelect(option.id)}
            className={`flex items-center justify-between rounded-xl px-3 py-2.5 text-sm font-semibold transition-colors ${
              tab === option.id
                ? "bg-accent/15 text-accent"
                : "text-slate-400 hover:bg-surface-raised hover:text-slate-200"
            }`}
          >
            <span>{option.label}</span>
            {option.id === "chat" && chatCount > 0 ? (
              <span className="rounded-full bg-accent/20 px-2 py-0.5 text-[10px] text-accent">
                {chatCount}
              </span>
            ) : null}
          </button>
        ))}
      </nav>
      <div className="mt-auto px-4 py-3 text-[10px] text-slate-600">
        v{APP_VERSION}
      </div>
    </aside>
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
          ? "Relay connection status"
          : `${remaining} relay requests left this hour`
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
  onCancel?: () => void;
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
  onCancel,
  onCreateNostr,
  onJoin,
}: GroupSetupProps) {
  const [mode, setMode] = useState<"join" | "create">("create");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<AppError | null>(null);

  // Join fields.
  const [inviteText, setInviteText] = useState("");
  const [joinPassword, setJoinPassword] = useState("");
  const [displayName, setDisplayName] = useState("");

  // Create fields.
  const [provider, setProvider] = useState<ProviderId>("nostr");
  const [label, setLabel] = useState("");
  const [createPassword, setCreatePassword] = useState("");
  const [createName, setCreateName] = useState("");

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

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-start justify-between gap-3 border-b border-surface-border px-4 py-4">
        <div>
          <h1 className="text-base font-semibold text-slate-100">Shadow720</h1>
          <p className="mt-1 text-xs text-slate-500">
            Encrypted on this device before anything is stored. No server holds your
            group's data.
          </p>
        </div>
        {onCancel ? (
          <button type="button" className="btn-secondary shrink-0 px-3 py-1 text-xs" onClick={onCancel}>
            Back
          </button>
        ) : null}
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
