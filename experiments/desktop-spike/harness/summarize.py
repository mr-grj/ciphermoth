import argparse
import json
from pathlib import Path


def load(path: Path) -> dict:
    return json.loads(path.read_text()) if path.exists() else {}


def mb(value: float | None) -> str:
    return "-" if value is None else f"{value / 2**20:.1f}"


def ms(value: float | None) -> str:
    return "-" if value is None else f"{value:.0f}"


def total_rss(idle: dict | None) -> tuple[str, str, str, str]:
    if not idle:
        return "-", "-", "-", "-"
    app = (idle.get("app") or {}).get("rss_mb")
    core = (idle.get("core") or {}).get("rss_mb")
    views = sum((v or {}).get("rss_mb") or 0 for v in idle.get("webviews", []))
    return (
        "-" if app is None else f"{app:.0f}",
        "-" if core is None else f"{core:.0f}",
        f"{views:.0f}",
        f"{(app or 0) + (core or 0) + views:.0f}",
    )


def row(target: str, directory: Path) -> dict:
    summary = load(directory / "summary.json")
    lifecycle = load(directory / "lifecycle.json")
    stages = summary.get("stages", {})
    scenarios = lifecycle.get("scenarios", {})
    ipc = scenarios.get("ipc_selftest", {})
    metrics = ipc.get("metrics") or {}
    repeated = scenarios.get("repeated_launches", {})
    kill = scenarios.get("force_kill_shell", {})
    bundles = stages.get("build_app", {}).get("bundles", {})
    core_build = stages.get("build_core", {})
    return {
        "target": target,
        "vectors": stages.get("vectors", {}),
        "protocol_tests": stages.get("core_protocol_tests", {}).get("ok"),
        "lifecycle_pass": sum(1 for s in scenarios.values() if s.get("ok")),
        "lifecycle_total": len(scenarios),
        "failed_scenarios": [k for k, s in scenarios.items() if not s.get("ok")],
        "ipc_checks": f"{sum(c['ok'] for c in ipc.get('checks', []))}/"
        f"{len(ipc.get('checks', []))}",
        "core_dir": mb(stages.get("build_core", {}).get("core_dir_bytes")),
        "shell": mb(stages.get("build_app", {}).get("shell_binary_bytes")),
        "bundles": {k: mb(v) for k, v in bundles.items()},
        "core_build_s": core_build.get("seconds"),
        "core_install_s": (core_build.get("timings") or {}).get("install_s"),
        "app_build_s": stages.get("build_app", {}).get("seconds"),
        "first_core_ready": ms(repeated.get("first_launch_core_ready_ms")),
        "warm_core_ready": ms(repeated.get("warm_core_ready_ms_median")),
        "first_ui_ready": ms(repeated.get("first_launch_ui_ready_ms")),
        "warm_ui_ready": ms(repeated.get("warm_ui_ready_ms_median")),
        "latency": metrics.get("small_latency_ms") or {},
        "attachment": metrics.get("attachment_5mib") or {},
        "listing": metrics.get("listing_1000_ms") or {},
        "restart_ms": metrics.get("restart_after_crash_ms"),
        "kdf": metrics.get("kdf") or {},
        "core_peak_sampled": ipc.get("core_rss_peak_mb_sampled"),
        "idle": total_rss(kill.get("idle_memory")),
        "kill_gone_s": kill.get("core_gone_after_s"),
        "webview_connections": len(
            (kill.get("sockets") or {}).get("webview_connections", [])
        ),
        "user_agent": ipc.get("user_agent"),
    }


def table(headers: list[str], rows: list[list[object]]) -> None:
    print("| " + " | ".join(headers) + " |")
    print("|" + "---|" * len(headers))
    for cells in rows:
        print("| " + " | ".join(str(c) for c in cells) + " |")
    print()


def vectors_cell(v: dict) -> str:
    if not v:
        return "-"
    digest = "identical" if v.get("identical_digest") else "DIFFERENT"
    return f"{v.get('passed')} pass, digest {digest}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dirs", nargs="+", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    rows = [row(d.name, d) for d in args.dirs]
    if args.json:
        args.json.write_text(json.dumps(rows, indent=2))
    table(
        ["Target", "Vectors", "Protocol tests", "IPC checks", "Lifecycle", "Failed"],
        [
            [
                r["target"],
                vectors_cell(r["vectors"]),
                "pass" if r["protocol_tests"] else "FAIL",
                r["ipc_checks"],
                f"{r['lifecycle_pass']}/{r['lifecycle_total']}",
                ", ".join(r["failed_scenarios"]) or "-",
            ]
            for r in rows
        ],
    )
    table(
        [
            "Target",
            "Core MB",
            "Shell MB",
            "Bundles MB",
            "Core build s (deps s)",
            "App s",
        ],
        [
            [
                r["target"],
                r["core_dir"],
                r["shell"],
                ", ".join(
                    f"{k.rsplit('.', 1)[-1]} {v}" for k, v in r["bundles"].items()
                ),
                f"{r['core_build_s']} ({r['core_install_s']})",
                r["app_build_s"],
            ]
            for r in rows
        ],
    )
    table(
        [
            "Target",
            "First launch core/UI ms",
            "Warm core/UI ms",
            "IPC mean/p95 ms",
            "5 MiB up/down ms",
            "1000 rows ms",
            "Restart ms",
            "Argon2id ms",
            "Core peak MB",
        ],
        [
            [
                r["target"],
                f"{r['first_core_ready']} / {r['first_ui_ready']}",
                f"{r['warm_core_ready']} / {r['warm_ui_ready']}",
                f"{r['latency'].get('mean', '-')} / {r['latency'].get('p95', '-')}",
                f"{r['attachment'].get('upload_ms', '-')} / "
                f"{r['attachment'].get('download_ms', '-')}",
                r["listing"].get("max", "-"),
                r["restart_ms"] or "-",
                r["kdf"].get("argon2id_ms", "-"),
                mb(r["kdf"].get("peak_rss_after")),
            ]
            for r in rows
        ],
    )
    table(
        [
            "Target",
            "Idle RSS MB shell/core/webview/total",
            "Core gone s",
            "Webview TCP",
            "UA",
        ],
        [
            [
                r["target"],
                " / ".join(r["idle"]),
                r["kill_gone_s"],
                r["webview_connections"],
                r["user_agent"],
            ]
            for r in rows
        ],
    )


if __name__ == "__main__":
    main()
