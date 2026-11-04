/**
 * Repository-host selector for the create-group flow.
 *
 * Providers are grouped by whether they need an account, because that is the
 * decision the user actually cares about: an account provider means signing in
 * or pasting a token, an accountless one means the app can provision everything
 * itself.
 *
 * Only GitHub is wired end to end today. The others are listed with an explicit
 * "not yet" state rather than hidden, so the selector does not silently promise
 * something the backend cannot do.
 */

export type ProviderId =
  | "github"
  | "gitlab"
  | "codeberg"
  | "nostr"
  | "radicle"
  | "gitgost";

export interface ProviderOption {
  id: ProviderId;
  label: string;
  /** One line describing what the provider is, shown under the label. */
  blurb: string;
  /** True when the user must sign in or supply a token. */
  requiresAccount: boolean;
  /** False when the backend cannot drive this provider yet. */
  available: boolean;
  /** Shown when `available` is false. */
  unavailableReason?: string;
}

export const PROVIDER_GROUPS: { title: string; items: ProviderOption[] }[] = [
  {
    title: "No account required",
    items: [
      {
        id: "nostr",
        label: "Nostr",
        blurb:
          "Identity is a keypair generated on this device. No signup, no token, and the invite carries no credential.",
        requiresAccount: false,
        available: true,
      },
    ],
  },
  {
    title: "Account backends",
    items: [
      {
        id: "github",
        label: "GitHub",
        blurb:
          "Private repo, issues, and release assets. Sign in and the app builds everything.",
        requiresAccount: true,
        available: false,
        unavailableReason:
          "The GitHub flow is being reworked. Use Nostr to create a group now.",
      },
      {
        id: "gitlab",
        label: "GitLab",
        blurb: "Issues and releases, free tier. Device-flow sign-in supported.",
        requiresAccount: true,
        available: false,
        unavailableReason: "Backend not implemented yet.",
      },
      {
        id: "codeberg",
        label: "Codeberg",
        blurb: "Gitea-based, free and non-profit.",
        requiresAccount: true,
        available: false,
        unavailableReason: "Backend not implemented yet.",
      },
      {
        id: "radicle",
        label: "Radicle",
        blurb: "Identity is a keypair, no signup. Git only — no issues or releases.",
        requiresAccount: false,
        available: false,
        unavailableReason:
          "Radicle has no issues or release-asset API, so the roster, chat, and vault have nowhere to live yet.",
      },
      {
        id: "gitgost",
        label: "gitGost",
        blurb: "Anonymous gateway to git hosts. No account, no tokens.",
        requiresAccount: false,
        available: false,
        unavailableReason:
          "Third-party gateway with no issues or release API, and no uptime guarantee to build a group on.",
      },
    ],
  },
];

/** Look up an option by id, falling back to Nostr. */
export function providerById(id: ProviderId): ProviderOption {
  for (const group of PROVIDER_GROUPS) {
    for (const item of group.items) {
      if (item.id === id) return item;
    }
  }
  const fallback = PROVIDER_GROUPS[0]?.items[0];
  if (!fallback) {
    throw new Error("provider catalogue is empty");
  }
  return fallback;
}

/** Grouped, single-select provider list. */
export function ProviderPicker({
  value,
  onChange,
}: {
  value: ProviderId;
  onChange: (id: ProviderId) => void;
}) {
  return (
    <div className="space-y-4">
      {PROVIDER_GROUPS.map((group) => (
        <div key={group.title}>
          <p className="label">{group.title}</p>
          <div className="space-y-2">
            {group.items.map((item) => {
              const selected = item.id === value;
              return (
                <button
                  key={item.id}
                  type="button"
                  disabled={!item.available}
                  onClick={() => onChange(item.id)}
                  className={`w-full rounded-xl border p-3 text-left transition ${
                    selected
                      ? "border-accent bg-surface-raised"
                      : "border-surface-border bg-surface"
                  } ${item.available ? "hover:border-slate-500" : "opacity-50"}`}
                >
                  <span className="flex items-center justify-between gap-2">
                    <span className="text-sm font-semibold text-slate-100">
                      {item.label}
                    </span>
                    {item.available ? null : (
                      <span className="rounded-md border border-surface-border px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-slate-500">
                        soon
                      </span>
                    )}
                  </span>
                  <span className="mt-1 block text-xs text-slate-500">
                    {item.blurb}
                  </span>
                  {item.unavailableReason ? (
                    <span className="mt-1 block text-xs text-amber-500/80">
                      {item.unavailableReason}
                    </span>
                  ) : null}
                </button>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}
