import { useCallback, useEffect, useState } from "react";
import {
  Box,
  Button,
  Chip,
  Divider,
  LinearProgress,
  Paper,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import MothIcon from "../../../../frontend/src/components/MothIcon.jsx";
import {
  BORDER_DARK,
  GLOW,
  INK,
  OK,
  PAPER_DARK,
  TEXT_ON_DARK,
  TEXT_ON_DARK_MUTED,
  WARN,
  WEAK,
} from "../../../../frontend/src/lib/brand.js";
import { coreJson, coreRestart, coreStatus, onCoreStatus } from "./core";
import { maybeRunSelftest, runSuite } from "./selftest";

const STATE_COLORS = { ready: OK, starting: WARN, restarting: WARN, failed: WEAK, stopped: WEAK };

const field = {
  "& .MuiOutlinedInput-root": {
    color: TEXT_ON_DARK,
    fontFamily: "'Space Mono', monospace",
    "& fieldset": { borderColor: BORDER_DARK },
    "&:hover fieldset": { borderColor: TEXT_ON_DARK_MUTED },
    "&.Mui-focused fieldset": { borderColor: GLOW },
  },
  "& .MuiInputLabel-root": { color: TEXT_ON_DARK_MUTED },
  "& .MuiInputLabel-root.Mui-focused": { color: GLOW },
};

function StatusLine({ status }) {
  const state = status?.state ?? "starting";
  return (
    <Stack direction="row" spacing={1.5} sx={{ alignItems: "center", flexWrap: "wrap" }}>
      <Chip
        size="small"
        label={`core ${state}`}
        sx={{
          bgcolor: "transparent",
          color: STATE_COLORS[state] ?? TEXT_ON_DARK_MUTED,
          border: `1px solid ${STATE_COLORS[state] ?? BORDER_DARK}`,
          fontFamily: "'Space Mono', monospace",
        }}
      />
      {status?.info && (
        <Typography
          variant="caption"
          sx={{ color: TEXT_ON_DARK_MUTED, fontFamily: "'Space Mono', monospace" }}
        >
          pid {status.info.pid} · protocol {status.info.protocol} · python {status.info.python} ·
          sqlite {status.info.sqlite} · ready in {status.ready_ms} ms
        </Typography>
      )}
      {status?.reason && (
        <Typography variant="caption" sx={{ color: WEAK }}>
          {status.reason}
        </Typography>
      )}
    </Stack>
  );
}

function CheckRow({ item }) {
  const color = item.state === "ok" ? OK : item.state === "failed" ? WEAK : TEXT_ON_DARK_MUTED;
  return (
    <Stack direction="row" spacing={1.5} sx={{ py: 0.5, alignItems: "baseline" }}>
      <Box
        sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: color, flexShrink: 0, mt: 0.5 }}
      />
      <Typography variant="body2" sx={{ color: TEXT_ON_DARK, flexGrow: 1 }}>
        {item.name}
      </Typography>
      <Typography
        variant="caption"
        sx={{
          color: item.error ? WEAK : TEXT_ON_DARK_MUTED,
          fontFamily: "'Space Mono', monospace",
        }}
      >
        {item.error ?? (item.ms !== undefined ? `${item.ms} ms` : "")}
      </Typography>
    </Stack>
  );
}

export default function App() {
  const [status, setStatus] = useState(null);
  const [vault, setVault] = useState(null);
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [checks, setChecks] = useState([]);
  const [running, setRunning] = useState(false);

  const refreshVault = useCallback(async () => {
    try {
      setVault((await coreJson("GET", "/spike/vault/status")).data);
    } catch {
      setVault(null);
    }
  }, []);

  useEffect(() => {
    let unlisten;
    coreStatus().then(setStatus);
    onCoreStatus((next) => {
      setStatus(next);
      if (next.state === "ready") refreshVault();
    }).then((fn) => {
      unlisten = fn;
    });
    return () => unlisten?.();
  }, [refreshVault]);

  useEffect(() => {
    if (status?.state === "ready") refreshVault();
  }, [status?.state, refreshVault]);

  const progress = useCallback((item) => {
    setChecks((current) => {
      const rest = current.filter((c) => c.name !== item.name);
      return [...rest, item];
    });
  }, []);

  useEffect(() => {
    maybeRunSelftest(progress).then((scenario) => {
      if (scenario === "ipc") setRunning(false);
    });
  }, [progress]);

  const submit = async (event) => {
    event.preventDefault();
    const route = vault?.exists ? "/spike/vault/unlock" : "/spike/vault/create";
    const reply = await coreJson("POST", route, { master_password: password });
    setPassword("");
    setMessage(
      reply.status === 200
        ? "Unlocked. The key stays inside the core."
        : (reply.data?.detail?.[0]?.msg ?? reply.data?.detail ?? "Refused.")
    );
    refreshVault();
  };

  const runChecks = async () => {
    setRunning(true);
    setChecks([]);
    try {
      await runSuite(progress);
    } finally {
      setRunning(false);
      refreshVault();
    }
  };

  return (
    <Box
      sx={{ minHeight: "100vh", bgcolor: INK, color: TEXT_ON_DARK, p: 4, boxSizing: "border-box" }}
    >
      <Stack direction="row" spacing={1.5} sx={{ alignItems: "center", mb: 0.5 }}>
        <MothIcon width={34} height={34} style={{ color: GLOW }} />
        <Typography variant="h5" sx={{ fontWeight: 600, letterSpacing: "-0.02em" }}>
          Cipher<span style={{ color: GLOW }}>Moth</span>
        </Typography>
        <Chip
          size="small"
          label="DESKTOP SPIKE"
          sx={{ bgcolor: "transparent", color: WARN, border: `1px solid ${WARN}`, fontWeight: 700 }}
        />
      </Stack>
      <Typography variant="body2" sx={{ color: TEXT_ON_DARK_MUTED, mb: 3 }}>
        Tauri shell, Python core over private pipes. Synthetic data only.
      </Typography>

      <Paper
        sx={{ bgcolor: PAPER_DARK, border: `1px solid ${BORDER_DARK}`, p: 2.5, mb: 2.5 }}
        elevation={0}
      >
        <StatusLine status={status} />
        {status?.state === "failed" && (
          <Button
            sx={{ mt: 1.5 }}
            variant="outlined"
            color="secondary"
            onClick={() => coreRestart()}
          >
            Retry
          </Button>
        )}
      </Paper>

      <Paper
        sx={{ bgcolor: PAPER_DARK, border: `1px solid ${BORDER_DARK}`, p: 2.5, mb: 2.5 }}
        elevation={0}
      >
        <Typography variant="subtitle2" sx={{ mb: 1.5 }}>
          {vault?.exists
            ? vault.unlocked
              ? "Synthetic vault unlocked"
              : "Unlock the synthetic vault"
            : "Create a synthetic vault"}
        </Typography>
        <Stack component="form" direction="row" spacing={1.5} onSubmit={submit}>
          <TextField
            size="small"
            type="password"
            label="Master password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            sx={{ ...field, flexGrow: 1 }}
          />
          <Button
            type="submit"
            variant="contained"
            color="secondary"
            disabled={!password || status?.state !== "ready"}
          >
            {vault?.exists ? "Unlock" : "Create"}
          </Button>
        </Stack>
        {message && (
          <Typography variant="caption" sx={{ display: "block", mt: 1, color: TEXT_ON_DARK_MUTED }}>
            {message}
          </Typography>
        )}
      </Paper>

      <Paper sx={{ bgcolor: PAPER_DARK, border: `1px solid ${BORDER_DARK}`, p: 2.5 }} elevation={0}>
        <Stack direction="row" sx={{ alignItems: "center", mb: 1 }}>
          <Typography variant="subtitle2" sx={{ flexGrow: 1 }}>
            IPC checks
          </Typography>
          <Button
            variant="outlined"
            color="secondary"
            size="small"
            onClick={runChecks}
            disabled={running || status?.state !== "ready"}
          >
            Run checks
          </Button>
        </Stack>
        {running && <LinearProgress color="secondary" sx={{ mb: 1 }} />}
        <Divider sx={{ borderColor: BORDER_DARK, mb: 1 }} />
        {checks.length === 0 ? (
          <Typography variant="caption" sx={{ color: TEXT_ON_DARK_MUTED }}>
            Runs JSON, binary, 5 MiB attachment, concurrency, timeout, cancellation, error and crash
            checks.
          </Typography>
        ) : (
          checks.map((item) => <CheckRow key={item.name} item={item} />)
        )}
      </Paper>
    </Box>
  );
}
