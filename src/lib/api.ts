/**
 * Typed bridge to the Rust command surface.
 *
 * Every command returns `{ kind, message }` on failure rather than rejecting with
 * a string, so the UI switches on `kind` instead of pattern-matching prose.
 */

export type AppErrorKind =
  | "crypto"
  | "invite_format"
  | "invite_password"
  | "github_api"
  | "github_auth"
  | "rate_limited"
  | "network"
  | "response_parse"
  | "payload_too_large"
  | "vault_unavailable"
  | "invalid_argument"
  | "group_state"
  | "io"
  | "not_configured";

/** A command failure, normalised across every possible transport shape. */
export interface AppError {
  kind: AppErrorKind;
  message: string;
}

function isAppError(value: unknown): value is AppError {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return typeof candidate.kind === "string" && typeof candidate.message === "string";
}

/** Convert anything thrown by the bridge into an `AppError`. */
export function toAppError(thrown: unknown): AppError {
  if (isAppError(thrown)) return thrown;
  if (typeof thrown === "string") return { kind: "io", message: thrown };
  if (thrown instanceof Error) return { kind: "io", message: thrown.message };
  return { kind: "io", message: "an unexpected error occurred" };
}

// -- Result types mirrored from Rust ----------------------------------------

export interface UnlockRequest {
  vaultDir: string;
}

export interface UnlockResponse {
  existed: boolean;
  groupConfigured: boolean;
  repoFullName: string | null;
  currentEpoch: number | null;
  requiresRecovery: boolean;
}

export interface ConsentStatus {
  acceptedEula: boolean;
  acceptedLocationDisclosure: boolean;
  enabledBackgroundLocation: boolean;
  onboardingComplete: boolean;
}

export interface BackgroundLocationResponse {
  enabled: boolean;
  /** True when the platform actually applied the change. */
  applied: boolean;
  /** Present when the change could not be fully applied, e.g. on desktop. */
  warning: string | null;
}

export interface PreferencesRequest {
  displayName: string;
  avatarColor: string;
  acceptedEula: boolean;
  acceptedLocationDisclosure: boolean;
  enabledBackgroundLocation: boolean;
}

export interface BeginSignInRequest {
  /** Include the destructive `delete_repo` scope so "Destroy Group" works. */
  allowDestroy: boolean;
}

export interface BeginSignInResponse {
  /** Short code the user types at `verificationUri`. */
  userCode: string;
  /** Page the user should open. */
  verificationUri: string;
  /** Seconds until the code expires. */
  expiresIn: number;
  /** Minimum seconds between polls. */
  interval: number;
}

export interface SignInResponse {
  login: string;
  scope: string;
  /** True when `delete_repo` was granted, so Destroy Group will work. */
  canDestroy: boolean;
}

export interface CreateNostrGroupRequest {
  groupLabel: string;
  joinPassword: string;
  displayName: string;
  /** Relay URLs. Defaults to the built-in list when empty. */
  relays?: string[];
  /** Blossom servers for blobs. Defaults to the built-in list when empty. */
  blossomServers?: string[];
}

export interface CreateNostrGroupResponse {
  invite: string;
  fingerprint: string;
  groupId: string;
  relays: string[];
  /** This device's Nostr public key, which is its identity in the group. */
  nostrPubkey: string;
}

export interface ProvisionRequest {
  /**
   * Account-scoped token, for callers that paste one instead of signing in.
   * Ignored when a sign-in has already completed.
   */
  accountToken?: string | null;
  /** Repository name. Generated when empty. */
  repoName?: string | null;
  /** Release tag for the vault. Defaults to `vault-v1`. */
  releaseTag?: string | null;
}

export interface ProvisionResponse {
  repoOwner: string;
  repoName: string;
  repoFullName: string;
  rosterIssueNum: number;
  chatIssueNum: number;
  releaseId: number;
  accountLogin: string;
}

export interface CreateGroupRequest {
  repoOwner: string;
  repoName: string;
  repoScopedPat: string;
  groupLabel: string;
  joinPassword: string;
  displayName: string;
  /** `0` creates a roster issue and uses its number. */
  rosterIssueNum: number;
  /** `0` creates a chat issue and uses its number. */
  chatIssueNum: number;
  releaseId?: number;
  releaseTag?: string | null;
  /** True when `provisionRepository` created this repository. */
  repoCreated?: boolean;
}

export interface CreateGroupResponse {
  invite: string;
  fingerprint: string;
  repoFullName: string;
  tokenLogin: string;
  hasAdminScope: boolean;
  releaseId: number;
}

export interface JoinGroupRequest {
  invite: string;
  joinPassword: string;
  displayName: string;
}

export interface JoinGroupResponse {
  repoFullName: string;
  groupLabel: string;
  rosterIssueNum: number;
  chatIssueNum: number;
  releaseId: number;
  keyEpoch: number;
  fingerprint: string;
  alreadyMember: boolean;
}

export interface LocationUpdateResponse {
  shouldPublish: boolean;
  skipReason: string | null;
}

export interface PollResponse {
  nextDelayMs: number;
  notModified: boolean;
  rateLimited: boolean;
  haltRemainingSecs: number | null;
}

/** How a member appears to be moving, derived from their reported speed. */
export type Activity = "still" | "walking" | "running" | "cycling" | "driving";

export interface MemberView {
  commentId: number;
  pubkeyB64: string;
  displayName: string;
  avatarColor: string;
  lat: number;
  lon: number;
  accuracyM: number;
  speedMps: number;
  headingDeg: number;
  activity: Activity;
  batteryPct: number;
  isCharging: boolean;
  unixMs: number;
  isSelf: boolean;
  isStale: boolean;
  isBlocked: boolean;
}

/** One recorded position on a member's trail. */
export interface TrailPoint {
  lat: number;
  lon: number;
  unixMs: number;
}

export interface RosterSnapshot {
  members: MemberView[];
  selfPubkey: string;
  currentEpoch: number;
  /** Recent positions per member public key, oldest first. */
  trails: Record<string, TrailPoint[]>;
}

export type ChatItem =
  | {
      kind: "text";
      commentId: number;
      nostrEventId: string | null;
      senderPubkeyB64: string;
      text: string;
      unixMs: number;
      isSelf: boolean;
      isBlocked: boolean;
    }
  | {
      kind: "file";
      commentId: number;
      nostrEventId: string | null;
      senderPubkeyB64: string;
      assetName: string;
      sizeBytes: number;
      mime: string;
      sha256B64: string;
      caption: string | null;
      unixMs: number;
      isSelf: boolean;
      isBlocked: boolean;
      unavailable: boolean;
    }
  | {
      kind: "moderation";
      commentId: number;
      senderPubkeyB64: string;
      targetCommentId: number;
      reason: string;
      unixMs: number;
    }
  | {
      kind: "undecryptable";
      commentId: number;
      reason: string;
    };

export interface ChatSnapshot {
  items: ChatItem[];
  selfPubkey: string;
}

export interface SendFileResponse {
  assetName: string;
  prunedCount: number;
  vaultBytes: number;
}

export interface DownloadedFile {
  fileName: string;
  mime: string;
  data: number[];
  sha256Verified: boolean;
}

export interface RotationStatus {
  newEpoch: number;
  retiredEpoch: number;
  alreadyHeld: boolean;
  needsReissue: boolean;
}

export interface MemberInvite {
  pubkeyB64: string;
  displayName: string;
  invite: string;
}

export interface RotateResponse {
  newEpoch: number;
  retiredEpoch: number;
  invites: MemberInvite[];
  removedPubkeys: string[];
}

export interface RekeyResponse {
  tokenValid: boolean;
  tokenLogin: string;
  invites: MemberInvite[];
  keyEpoch: number;
}

export interface WipeResponse {
  rosterCommentDeleted: boolean;
  vaultWiped: boolean;
}

export interface DestroyResponse {
  repoFullName: string;
  vaultWiped: boolean;
  acceptedRelays: string[];
  unconfirmedRelays: string[];
}

export interface DiagnosticsResponse {
  /** Which storage backend holds this group. */
  backend: string;
  /** True when the backend needs no account. */
  accountless: boolean;
  repoFullName: string;
  groupLabel: string;
  isHost: boolean;
  currentEpoch: number;
  knownEpochs: number[];
  rosterLen: number;
  chatLen: number;
  blockedCount: number;
  chatIntervalS: number;
  rosterIntervalS: number;
  haltedUntilUnixS: number | null;
  remainingRequests: number | null;
  totalRequests: number | null;
  fingerprint: string;
}

export interface VaultAssetView {
  id: number;
  name: string;
  size: number;
  createdAtMs: number;
  deletionStatus: "available" | "notice_pending" | "announced" | null;
}

export interface VaultReport {
  assets: VaultAssetView[];
  totalBytes: number;
  maxBytes: number;
  rateLimitRemaining: number | null;
}

// -- Invocation --------------------------------------------------------------

type InvokeFn = <T>(command: string, args?: Record<string, unknown>) => Promise<T>;

let cachedInvoke: InvokeFn | null = null;

/**
 * The Tauri bridge is resolved lazily and cached.
 *
 * Importing `@tauri-apps/api/core` at module scope breaks a plain `vite build`
 * when the UI is opened in a browser for iteration, so the import happens on
 * first use and a helpful error is raised if the runtime is absent.
 */
async function resolveInvoke(): Promise<InvokeFn> {
  if (cachedInvoke) return cachedInvoke;

  const internals = (globalThis as { __TAURI_INTERNALS__?: unknown })
    .__TAURI_INTERNALS__;
  if (!internals) {
    throw {
      kind: "not_configured",
      message:
        "the native runtime is unavailable; open this app inside the Shadow720 build rather than a browser tab",
    } satisfies AppError;
  }

  const core = await import("@tauri-apps/api/core");
  cachedInvoke = core.invoke as InvokeFn;
  return cachedInvoke;
}

/** Invoke a command, converting any failure into a typed `AppError`. */
async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    const invoke = await resolveInvoke();
    return await invoke<T>(command, args);
  } catch (thrown) {
    throw toAppError(thrown);
  }
}

// -- Vault ------------------------------------------------------------------

export const unlockVault = (request: UnlockRequest) =>
  call<UnlockResponse>("unlock_vault", { request });

export const discardLegacyGroup = () => call<void>("discard_legacy_group");

/**
 * Delete the local vault so an unreadable one can be replaced.
 *
 * The only escape from a vault whose device key was invalidated. Nothing remote
 * is touched.
 */
export const resetVault = () => call<void>("reset_vault");

/** A group this device belongs to, with no secrets. */
export interface GroupSummary {
  id: string;
  label: string;
  backend: string;
  isActive: boolean;
}

/** Every group this device belongs to, for the switcher. */
export const listGroups = () => call<GroupSummary[]>("list_groups");

/**
 * Switch to another stored group.
 *
 * Local only: the vault already holds everything needed, so this works offline.
 */
export const switchGroup = (groupId: string) =>
  call<void>("switch_group", { groupId });

/** Forget one stored group. Returns true when it was the active one. */
export const forgetGroup = (groupId: string) =>
  call<boolean>("forget_group", { groupId });
export const lockVault = () => call<void>("lock_vault");

// -- Onboarding -------------------------------------------------------------

export const consentStatus = () => call<ConsentStatus>("consent_status");

export const setPreferences = (request: PreferencesRequest) =>
  call<ConsentStatus>("set_preferences", { request });

/**
 * Start or stop background location sharing.
 *
 * On Android this drives the location foreground service, so the persistent
 * notification appears and disappears with it.
 */
export const setBackgroundLocation = (enabled: boolean) =>
  call<BackgroundLocationResponse>("set_background_location", { enabled });

/** What the platform reports about location access. */
export interface LocationAccessResponse {
  /** True when the device-wide location switch is on. */
  systemLocationEnabled: boolean;
  /** True when this platform can open a settings screen for the user. */
  canOpenSettings: boolean;
}

/**
 * Report whether the device location switch is on.
 *
 * The runtime permission is checked separately, in the webview; this covers the
 * case where the permission is granted but the system switch is off.
 */
export const locationAccess = () =>
  call<LocationAccessResponse>("location_access");

/**
 * Open the system screen where location access can be granted.
 *
 * `appPage` selects this app's permission page rather than the device switch.
 * Android cannot grant the permission itself, so this is the only path once the
 * user has permanently denied it.
 */
export const openLocationSettings = (appPage: boolean) =>
  call<void>("open_location_settings", { appPage });

// -- Group lifecycle --------------------------------------------------------

/**
 * Start an account sign-in and get the code to show the user.
 *
 * Fine-grained PATs cannot be created through the API, so the device flow is the
 * only way to keep setup inside the app: one button, a short code, and the user
 * approves on whatever device they already have.
 */
export const beginSignIn = (allowDestroy: boolean) =>
  call<BeginSignInResponse>("begin_sign_in", { request: { allowDestroy } });

/**
 * Poll once for a completed sign-in.
 *
 * Resolves to `null` while the user has not approved yet, so the caller can keep
 * a spinner running without treating "not yet" as an error. The polling secret
 * stays in Rust; this takes no arguments.
 */
export const pollSignIn = () => call<SignInResponse | null>("poll_sign_in");

/**
 * Create the repository, both schema issues, and the vault release.
 *
 * Uses the token from a completed sign-in, which never crosses into the webview.
 */
export const provisionRepository = (request: ProvisionRequest) =>
  call<ProvisionResponse>("provision_repository", { request });

/**
 * Create a group on Nostr: no account, no token, no repository.
 *
 * The identity is a keypair generated on this device, so there is nothing to
 * sign in to. The invite carries the group key and relay list, and deliberately
 * carries no credential.
 */
export const createNostrGroup = (request: CreateNostrGroupRequest) =>
  call<CreateNostrGroupResponse>("create_nostr_group", { request });

export const createGroup = (request: CreateGroupRequest) =>
  call<CreateGroupResponse>("create_group", { request });

export const joinGroup = (request: JoinGroupRequest) =>
  call<JoinGroupResponse>("join_group", { request });

// -- Location ---------------------------------------------------------------

export const updateLocation = (
  lat: number,
  lon: number,
  motion: { speedMps?: number; headingDeg?: number; accuracyM?: number } = {},
) =>
  call<LocationUpdateResponse>("update_location", {
    update: {
      lat,
      lon,
      speedMps: motion.speedMps ?? 0,
      headingDeg: motion.headingDeg ?? 0,
      accuracyM: motion.accuracyM ?? 0,
    },
  });

// -- Polling ----------------------------------------------------------------

export const pollRoster = () => call<PollResponse>("poll_roster");
export const pollChat = () => call<PollResponse>("poll_chat");
export const deleteOwnMessage = (eventId: string) =>
  call<{ acceptedRelays: string[]; unconfirmedRelays: string[] }>("delete_own_message", { eventId });
export const refreshRateLimit = () => call<PollResponse>("refresh_rate_limit");

export const rosterSnapshot = () => call<RosterSnapshot>("roster_snapshot");
export const chatSnapshot = () => call<ChatSnapshot>("chat_snapshot");
export const diagnostics = () => call<DiagnosticsResponse>("diagnostics");

// -- Chat -------------------------------------------------------------------

export const sendText = (text: string) =>
  call<PollResponse>("send_text", { request: { text } });

export const sendFile = (
  data: number[],
  fileName: string,
  mime: string,
  caption?: string,
) =>
  call<SendFileResponse>("send_file", {
    request: { data, fileName, mime, caption: caption ?? null },
  });

export const downloadFile = (
  assetName: string,
  expectedSha256B64?: string,
  mime?: string,
) =>
  call<DownloadedFile>("download_file", {
    assetName,
    expectedSha256B64: expectedSha256B64 ?? null,
    mime: mime ?? null,
  });

// -- Moderation -------------------------------------------------------------

export const blockMember = (pubkeyB64: string, blocked: boolean) =>
  call<void>("block_member", { request: { pubkeyB64, blocked } });

export const blockedMembers = () => call<string[]>("blocked_members");

export const reportContent = (
  targetCommentId: number,
  targetPubkeyB64: string,
  reason: string,
) =>
  call<PollResponse>("report_content", {
    request: { targetCommentId, targetPubkeyB64, reason },
  });

// -- Rotation and recovery --------------------------------------------------

export const checkRotation = () => call<RotationStatus | null>("check_rotation");

export const rotateGroupKey = (
  joinPassword: string,
  removePubkeys: string[],
  reason?: string,
) =>
  call<RotateResponse>("rotate_group_key", {
    request: { joinPassword, removePubkeys, reason: reason ?? null },
  });

export const rekeyGroup = (
  newPat: string,
  joinPassword: string,
  releaseTag?: string,
) =>
  call<RekeyResponse>("rekey_group", {
    request: { newPat, joinPassword, releaseTag: releaseTag ?? null },
  });

// -- Leaving -----------------------------------------------------------------

export const leaveAndWipe = () => call<WipeResponse>("leave_and_wipe");
export const destroyGroup = () => call<DestroyResponse>("destroy_group");
export const checkGroupClosed = () => call<boolean>("check_group_closed");

// -- Vault inspection -------------------------------------------------------

export const vaultReport = () => call<VaultReport>("vault_report");

export const deleteAsset = (assetId: number) =>
  call<void>("delete_asset", { assetId });

export const deleteNostrBlob = (sha256: string) =>
  call<{
    server: string;
    acceptedRelays: string[];
    unconfirmedRelays: string[];
    noticeError: string | null;
  }>("delete_nostr_blob", { sha256 });

/** Human-readable summary for an error, used for banners and toasts. */
export function describeError(error: AppError): string {
  switch (error.kind) {
    case "invite_password":
      return "That join password does not match this invite. Check it and try again.";
    case "invite_format":
      return `The invite string is not usable: ${error.message}`;
    case "github_auth":
      return "GitHub rejected the token. It may have expired, or lack the required scopes.";
    case "rate_limited":
      return "GitHub rate limit reached. Sync resumes automatically; no action needed.";
    case "vault_unavailable":
      // The underlying message distinguishes a genuinely invalidated device key
      // from a keystore or filesystem failure. Replacing it with one generic
      // sentence made every vault problem look like a factory reset.
      return `The secure vault cannot be opened on this device: ${error.message}`;
    case "payload_too_large":
      return "That file is too large to share. The limit is 15 MB.";
    case "github_api":
      return `GitHub refused the request: ${error.message}`;
    case "network":
      return "Could not reach GitHub. Check the connection and try again.";
    default:
      return error.message;
  }
}

/** True when the error deserves an immediate modal rather than an inline note. */
export function isBlocking(error: AppError): boolean {
  return (
    error.kind === "vault_unavailable" ||
    error.kind === "github_auth" ||
    error.kind === "invite_format"
  );
}