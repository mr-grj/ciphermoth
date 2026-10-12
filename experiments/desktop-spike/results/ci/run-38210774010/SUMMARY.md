| Target | Vectors | Protocol tests | IPC checks | Lifecycle | Failed |
|---|---|---|---|---|---|
| macos-arm64 | 133 pass, digest identical | pass | 20/20 | 11/11 | - |
| macos-x64 | 133 pass, digest identical | pass | 20/20 | 11/11 | - |
| windows-x64 | 133 pass, digest identical | pass | 20/20 | 10/10 | - |
| windows-arm64 | 133 pass, digest identical | pass | 20/20 | 10/10 | - |
| linux-x64 | 133 pass, digest identical | pass | 20/20 | 10/10 | - |
| linux-arm64 | 133 pass, digest identical | pass | 20/20 | 10/10 | - |

| Target | Core MB | Shell MB | Bundles MB | Core build s (deps s) | App s |
|---|---|---|---|---|---|
| macos-arm64 | 54.0 | 4.6 | app 58.7, dmg 29.3 | 30.7 (1.4) | 187.8 |
| macos-x64 | 53.1 | 5.0 | app 58.2, dmg 29.7 | 57.0 (1.9) | 356.6 |
| windows-x64 | 52.7 | 4.8 | exe 24.1 | 36.8 (1.2) | 367.6 |
| windows-arm64 | 53.7 | 4.5 | exe 23.3 | 42.6 (4.1) | 373.1 |
| linux-x64 | 104.3 | 5.4 | deb 43.1 | 24.8 (0.5) | 196.4 |
| linux-arm64 | 96.2 | 5.0 | deb 41.0 | 21.8 (0.5) | 162.9 |

| Target | First launch core/UI ms | Warm core/UI ms | IPC mean/p95 ms | 5 MiB up/down ms | 1000 rows ms | Restart ms | Argon2id ms | Core peak MB |
|---|---|---|---|---|---|---|---|---|
| macos-arm64 | 1963 / 3659 | 1205 / 2345 | 1.16 / 2 | 67 / 40 | 33 | 1241 | 702.4 | 155.2 |
| macos-x64 | 3735 / 3249 | 1779 / 857 | 2.11 / 3 | 154 / 124 | 66 | 1419 | 102.4 | 145.1 |
| windows-x64 | 6810 / 6167 | 1616 / 703 | 2.58 / 3.1 | 742.4 / 99.9 | 40.9 | 1294 | 91.2 | 151.1 |
| windows-arm64 | 2670 / 1800 | 1495 / 581 | 2.49 / 2.8 | 472.6 / 139.7 | 33.4 | 1325.3 | 74.4 | 154.4 |
| linux-x64 | 1215 / 1385 | 1042 / 444 | 0.82 / 1 | 148 / 101 | 38 | 1087 | 106.9 | 155.4 |
| linux-arm64 | 1282 / 1743 | 761 / 311 | 0.97 / 1 | 97 / 48 | 25 | 887 | 63.4 | 154.2 |

| Target | Idle RSS MB shell/core/webview/total | Core gone s | Webview TCP | UA |
|---|---|---|---|---|
| macos-arm64 | 72 / 90 / 82 / 244 | 0.339 | 0 | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) |
| macos-x64 | 47 / 81 / 72 / 200 | 0.353 | 0 | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) |
| windows-x64 | 30 / 87 / 300 / 416 | 0.027 | 4 | Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36 Edg/153.0.0.0 |
| windows-arm64 | 30 / 88 / 323 / 440 | 0.027 | 0 | Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36 Edg/154.0.0.0 |
| linux-x64 | 138 / 91 / 230 / 459 | 0.0 | 0 | Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/60.5 Safari/605.1.15 |
| linux-arm64 | 130 / 90 / 228 / 448 | 0.0 | 0 | Mozilla/5.0 (X11; Ubuntu; Linux aarch64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/60.5 Safari/605.1.15 |

