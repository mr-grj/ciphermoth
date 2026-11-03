// The API sends naive UTC timestamps ("2026-11-03T19:08:48.274272").
export const parseUtc = (value) => {
  if (!value) return null;
  const date = new Date(/[zZ]|[+-]\d\d:\d\d$/.test(value) ? value : `${value}Z`);
  return Number.isNaN(date.getTime()) ? null : date;
};

export const formatDay = (value) =>
  parseUtc(value)?.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  }) ?? "";

const UNITS = [
  ["year", 365 * 86_400_000],
  ["month", 30 * 86_400_000],
  ["week", 7 * 86_400_000],
  ["day", 86_400_000],
  ["hour", 3_600_000],
  ["minute", 60_000],
];

export const formatAgo = (value, now = Date.now()) => {
  const date = parseUtc(value);
  if (!date) return "";
  const elapsed = now - date.getTime();
  const format = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  for (const [unit, ms] of UNITS) {
    if (Math.abs(elapsed) >= ms) return format.format(-Math.round(elapsed / ms), unit);
  }
  return "just now";
};
