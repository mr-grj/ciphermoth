// npm audit --audit-level=moderate, minus the advisories accepted below. npm has
// no ignore list of its own. Anything else, or a report it cannot read, fails.
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

// An acceptance covers only the versions it was checked against, so a dependency
// moving to another major line brings the advisory back.
export const ACCEPTED = [
  {
    advisory: "GHSA-g3hv-75wg-m249",
    package: "minimatch",
    versions: /^3\./,
    reason:
      "The advisory lists every version below 11.0.1 and no release of the 3.x line " +
      "that serve-handler and ESLint require fixes it, but the amplification is in " +
      "the optimizationLevel preprocessing of later lines, which 3.x does not have. " +
      "It also needs an attacker's glob pattern; our patterns come from serve.json " +
      "and the ESLint config.",
  },
];

const FAILING_SEVERITIES = new Set(["moderate", "high", "critical"]);

const advisoryId = (via) => via.url?.split("/").pop();

const isAccepted = (via, vulnerability, lockfile) => {
  const accepted = ACCEPTED.find(
    (entry) => entry.advisory === advisoryId(via) && entry.package === via.name
  );
  if (!accepted || !vulnerability.nodes?.length) return false;
  return vulnerability.nodes.every((node) =>
    accepted.versions.test(lockfile.packages?.[node]?.version ?? "")
  );
};

// Packages that are only affected through a dependency list that dependency's
// name in `via`; the advisories themselves are the objects.
export const auditFindings = (report, lockfile) => {
  if (typeof report.vulnerabilities !== "object" || report.vulnerabilities === null) {
    throw new Error(report.message ?? report.error?.summary ?? "npm audit gave no report");
  }
  const findings = { blocking: [], accepted: [] };
  for (const vulnerability of Object.values(report.vulnerabilities)) {
    for (const via of vulnerability.via) {
      if (typeof via === "string" || !FAILING_SEVERITIES.has(via.severity)) continue;
      const list = isAccepted(via, vulnerability, lockfile) ? "accepted" : "blocking";
      findings[list].push(`${via.name} (${via.severity}): ${via.title} - ${via.url}`);
    }
  }
  return findings;
};

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const folder = process.argv[2] ?? ".";
  const audit = spawnSync("npm", ["audit", "--json"], {
    cwd: folder,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  let findings;
  try {
    findings = auditFindings(
      JSON.parse(audit.stdout),
      JSON.parse(readFileSync(join(folder, "package-lock.json"), "utf8"))
    );
  } catch (error) {
    console.error(`Could not audit ${folder}: ${error.message}`);
    process.exit(1);
  }
  for (const finding of findings.accepted) console.log(`Accepted: ${finding}`);
  for (const finding of findings.blocking) console.error(`Vulnerable: ${finding}`);
  if (findings.blocking.length > 0) process.exit(1);
  console.log(`${folder}: no vulnerabilities beyond the accepted advisories`);
}
