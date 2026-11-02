import assert from "node:assert/strict";
import { test } from "node:test";

import { auditFindings } from "./npm_audit.mjs";

const advisory = (name, id, severity = "moderate") => ({
  name,
  severity,
  title: "A finding",
  url: `https://github.com/advisories/${id}`,
});

const report = (name, via) => ({
  vulnerabilities: { [name]: { name, via, nodes: [`node_modules/${name}`] } },
});

const lockfile = (name, version) => ({
  packages: { [`node_modules/${name}`]: { version } },
});

const MINIMATCH = advisory("minimatch", "GHSA-g3hv-75wg-m249");

test("the accepted advisory passes on the version it was checked against", () => {
  const findings = auditFindings(
    report("minimatch", [MINIMATCH]),
    lockfile("minimatch", "3.1.5")
  );
  assert.equal(findings.blocking.length, 0);
  assert.equal(findings.accepted.length, 1);
});

test("the accepted advisory blocks on another major version", () => {
  const findings = auditFindings(
    report("minimatch", [MINIMATCH]),
    lockfile("minimatch", "10.2.6")
  );
  assert.equal(findings.blocking.length, 1);
});

test("the accepted advisory blocks when the installed version is unknown", () => {
  const findings = auditFindings(report("minimatch", [MINIMATCH]), { packages: {} });
  assert.equal(findings.blocking.length, 1);
});

test("the accepted advisory blocks if one of several copies is outside the range", () => {
  const vulnerabilities = {
    minimatch: {
      via: [MINIMATCH],
      nodes: ["node_modules/minimatch", "node_modules/a/node_modules/minimatch"],
    },
  };
  const packages = {
    "node_modules/minimatch": { version: "3.1.5" },
    "node_modules/a/node_modules/minimatch": { version: "10.2.6" },
  };
  const findings = auditFindings({ vulnerabilities }, { packages });
  assert.equal(findings.blocking.length, 1);
});

test("another advisory of the same package blocks", () => {
  const findings = auditFindings(
    report("minimatch", [MINIMATCH, advisory("minimatch", "GHSA-aaaa-bbbb-cccc", "high")]),
    lockfile("minimatch", "3.1.5")
  );
  assert.equal(findings.accepted.length, 1);
  assert.equal(findings.blocking.length, 1);
});

test("the same advisory id on another package blocks", () => {
  const findings = auditFindings(
    report("other", [advisory("other", "GHSA-g3hv-75wg-m249")]),
    lockfile("other", "3.1.5")
  );
  assert.equal(findings.blocking.length, 1);
});

test("packages affected only through a dependency add nothing", () => {
  const findings = auditFindings(report("eslint", ["minimatch"]), lockfile("eslint", "9.39.5"));
  assert.deepEqual(findings, { blocking: [], accepted: [] });
});

test("low severity stays below the audit level", () => {
  const findings = auditFindings(
    report("other", [advisory("other", "GHSA-aaaa-bbbb-cccc", "low")]),
    lockfile("other", "1.0.0")
  );
  assert.deepEqual(findings, { blocking: [], accepted: [] });
});

test("an npm error instead of a report fails", () => {
  assert.throws(
    () => auditFindings({ message: "audit endpoint returned an error" }, { packages: {} }),
    /audit endpoint returned an error/
  );
});
