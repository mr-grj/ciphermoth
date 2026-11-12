import { useEffect, useState } from "react";
import { Box, CircularProgress, Tooltip, Typography, useTheme } from "@mui/material";

import { generateTotp, totpRemaining } from "../../lib/totp";
import { GLOW, TOTP } from "../../lib/brand";

const PERIOD = 30;

const TotpCell = ({ secret, onCopy }) => {
  const theme = useTheme();
  const [code, setCode] = useState("");
  const [remaining, setRemaining] = useState(PERIOD);
  const [invalid, setInvalid] = useState(false);

  useEffect(() => {
    let active = true;
    const tick = async () => {
      try {
        const next = await generateTotp(secret);
        if (!active) return;
        setCode(next);
        setInvalid(false);
      } catch {
        if (active) setInvalid(true);
      }
      if (active) setRemaining(totpRemaining(PERIOD));
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, [secret]);

  if (invalid) {
    return (
      <Typography variant="caption" sx={{ color: "error.main" }}>
        invalid
      </Typography>
    );
  }
  if (!code) return null;

  return (
    <Tooltip title="Copy 2FA code">
      <Box
        component="button"
        type="button"
        aria-label={`Copy 2FA code ${code.slice(0, 3)} ${code.slice(3)}`}
        onClick={() => onCopy?.(code)}
        sx={{
          display: "flex",
          alignItems: "center",
          gap: 0.75,
          cursor: "pointer",
          border: 0,
          p: 0,
          bgcolor: "transparent",
          color: "inherit",
        }}
      >
        <Typography
          component="span"
          variant="body2"
          sx={{
            fontFamily: "'Space Mono', monospace",
            fontWeight: 700,
            color: theme.palette.mode === "dark" ? GLOW : TOTP,
          }}
        >
          {code.slice(0, 3)} {code.slice(3)}
        </Typography>
        <CircularProgress
          aria-label="2FA code time remaining"
          variant="determinate"
          value={(remaining / PERIOD) * 100}
          size={16}
          thickness={5}
          sx={{ color: remaining <= 5 ? "warning.main" : "text.disabled" }}
        />
      </Box>
    </Tooltip>
  );
};

export default TotpCell;
