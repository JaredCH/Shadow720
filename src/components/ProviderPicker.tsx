/**
 * Storage selector for the create-group flow.
 *
 * Nostr is the only backend: identity is a keypair generated on this device, so
 * there is no account to create and no token to paste. The picker stays as a
 * single-option list so the create flow keeps its shape and a future backend can
 * be added without restructuring the form.
 */

export type ProviderId = "nostr";

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
