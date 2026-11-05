// Password history of an entry, React-free so dates and the restore payload are
// testable. The server keeps the last HISTORY_LIMIT values, newest first; each
// item's `changed_at` is when that value stopped being the password.

export const HISTORY_LIMIT = 10;

const parse = (iso) => {
  const date = iso ? new Date(iso) : null;
  return date && !Number.isNaN(date.getTime()) ? date : null;
};

export const hasHistory = (entry) =>
  entry?.kind !== "note" && (entry?.password_history?.length ?? 0) > 0;

// The current password, then every earlier one, with the span each was in use.
// The oldest value's start is unknown: the server did not record it.
export const historyTimeline = (entry) => {
  const history = entry?.password_history ?? [];
  const current = entry?.password_value ?? "";
  return [
    { key: "current", value: current, current: true, since: parse(history[0]?.changed_at) },
    ...history.map((item, index) => ({
      key: `old-${index}`,
      index,
      value: item.value,
      current: false,
      until: parse(item.changed_at),
      since: parse(history[index + 1]?.changed_at),
      sameAsCurrent: item.value === current,
    })),
  ];
};

// "Jan 1, 2025, 10:52 AM" in the user's locale; "long" spells the month out.
export const formatWhen = (date, { locale, timeZone, dateStyle = "medium" } = {}) =>
  date
    ? new Intl.DateTimeFormat(locale, { dateStyle, timeStyle: "short", timeZone }).format(date)
    : "";

const SPANS = [
  ["year", 365 * 24 * 3600e3],
  ["month", 30 * 24 * 3600e3],
  ["week", 7 * 24 * 3600e3],
  ["day", 24 * 3600e3],
  ["hour", 3600e3],
  ["minute", 60e3],
];

// "3 months ago", "yesterday", "just now".
export const relativeTime = (date, now = new Date(), locale) => {
  if (!date) return "";
  const elapsed = now.getTime() - date.getTime();
  if (Math.abs(elapsed) < 60e3) return "just now";
  const format = new Intl.RelativeTimeFormat(locale, { numeric: "auto" });
  for (const [unit, ms] of SPANS) {
    if (Math.abs(elapsed) >= ms) return format.format(-Math.trunc(elapsed / ms), unit);
  }
  return "just now";
};

// "used for 4 months", "used for less than a day"; nothing when the start is unknown.
export const usedFor = (since, until) => {
  if (!since || !until) return "";
  const elapsed = until.getTime() - since.getTime();
  if (elapsed < 24 * 3600e3) return "used for less than a day";
  for (const [unit, ms] of SPANS) {
    const count = Math.floor(elapsed / ms);
    if (count >= 1) return `used for ${count} ${unit}${count === 1 ? "" : "s"}`;
  }
  return "";
};

// The PATCH /passwords/update body that makes `value` the entry's password again,
// keeping every other field as it is (the server then moves the current value
// into the history).
export const restorePayload = (entry, value) => ({
  password: { password_name: entry.password_name },
  new_password: {
    password_name: entry.password_name,
    kind: entry.kind ?? "login",
    username: entry.username ?? null,
    password_value: value,
    url: entry.url ?? null,
    totp_secret: entry.totp_secret ?? null,
    description: entry.description ?? null,
    tags: entry.tags ?? [],
    custom_fields: (entry.custom_fields ?? []).map(({ label, value: fieldValue, hidden }) => ({
      label,
      value: fieldValue,
      hidden,
    })),
    folder: entry.folder ?? null,
    favorite: !!entry.favorite,
  },
});

// A short line under the entry's name: the username, else the website's host.
export const entrySubtitle = (entry) => {
  if (entry?.username) return entry.username;
  if (!entry?.url) return "";
  try {
    const url = new URL(
      /^[a-z][a-z0-9+.-]*:\/\//i.test(entry.url) ? entry.url : `https://${entry.url}`
    );
    return url.host || entry.url;
  } catch {
    return entry.url;
  }
};
