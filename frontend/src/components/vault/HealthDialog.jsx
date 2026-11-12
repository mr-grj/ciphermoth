import { useMemo } from "react";
import {
  Box,
  Button,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  ListItemButton,
  ListItemText,
  Stack,
  Typography,
} from "@mui/material";
import CheckCircleOutlinedIcon from "@mui/icons-material/CheckCircleOutlined";
import ChevronRightIcon from "@mui/icons-material/ChevronRight";
import ContentCopyOutlinedIcon from "@mui/icons-material/ContentCopyOutlined";
import GppMaybeOutlinedIcon from "@mui/icons-material/GppMaybeOutlined";
import ScheduleOutlinedIcon from "@mui/icons-material/ScheduleOutlined";

import { analyzeVault } from "../../lib/vaultHealth";

const scoreColor = (score) => {
  if (score >= 80) return "success";
  if (score >= 50) return "warning";
  return "error";
};

const scoreLabel = (score) => {
  if (score >= 80) return "Healthy";
  if (score >= 50) return "Needs attention";
  return "At risk";
};

const ScoreGauge = ({ score }) => {
  const color = scoreColor(score);
  return (
    <Stack spacing={1} sx={{ alignItems: "center" }}>
      <Box sx={{ position: "relative", display: "inline-flex" }}>
        <CircularProgress
          aria-hidden="true"
          variant="determinate"
          value={100}
          size={120}
          thickness={4}
          sx={{ color: "divider" }}
        />
        <CircularProgress
          role="meter"
          aria-label="Vault Health"
          variant="determinate"
          value={score}
          size={120}
          thickness={4}
          color={color}
          sx={{ position: "absolute", left: 0, strokeLinecap: "round" }}
        />
        <Box
          sx={{
            position: "absolute",
            inset: 0,
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <Typography component="span" variant="h4" sx={{ fontWeight: 700, lineHeight: 1 }}>
            {score}
          </Typography>
          <Typography variant="caption" sx={{ color: "text.secondary" }}>
            / 100
          </Typography>
        </Box>
      </Box>
      <Typography
        component="p"
        variant="subtitle2"
        sx={{ fontWeight: 700, color: `${color}.main` }}
      >
        {scoreLabel(score)}
      </Typography>
    </Stack>
  );
};

const StatTile = ({ icon: Icon, label, count, color }) => (
  <Box
    sx={{
      flex: 1,
      textAlign: "center",
      p: 1.25,
      borderRadius: 2,
      border: "1px solid",
      borderColor: "divider",
    }}
  >
    <Icon fontSize="small" sx={{ color: count ? `${color}.main` : "text.disabled" }} />
    <Typography
      component="p"
      variant="h6"
      sx={{ fontWeight: 700, lineHeight: 1.2, color: count ? "text.primary" : "text.disabled" }}
    >
      {count}
    </Typography>
    <Typography variant="caption" sx={{ color: "text.secondary" }}>
      {label}
    </Typography>
  </Box>
);

const IssueGroup = ({ icon: Icon, title, hint, color, entries, onSelect }) => {
  if (entries.length === 0) return null;
  return (
    <Box>
      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
        <Icon fontSize="small" sx={{ color: `${color}.main` }} />
        <Typography component="h3" variant="subtitle2" sx={{ fontWeight: 700 }}>
          {title}
        </Typography>
        <Typography variant="caption" sx={{ color: "text.secondary" }}>
          ({entries.length})
        </Typography>
      </Stack>
      <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.75 }}>
        {hint}
      </Typography>
      <Stack spacing={0.5}>
        {entries.map((entry) => (
          <ListItemButton
            key={entry.password_name}
            onClick={() => onSelect(entry)}
            sx={{ borderRadius: 1.5, border: "1px solid", borderColor: "divider", py: 0.75 }}
          >
            <ListItemText
              primary={
                <Typography variant="body2" sx={{ fontWeight: 600 }}>
                  {entry.password_name}
                </Typography>
              }
              secondary={entry.username || undefined}
            />
            <ChevronRightIcon fontSize="small" sx={{ color: "text.disabled" }} />
          </ListItemButton>
        ))}
      </Stack>
    </Box>
  );
};

const HealthDialog = ({ open, onClose, passwords, onSelect }) => {
  const report = useMemo(() => analyzeVault(passwords), [passwords]);
  const allClear =
    report.weak.length === 0 && report.reused.length === 0 && report.stale.length === 0;

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Vault Health</DialogTitle>
      <DialogContent dividers>
        <Stack spacing={2.5} sx={{ py: 1 }}>
          <ScoreGauge score={report.score} />

          <Stack direction="row" spacing={1}>
            <StatTile
              icon={GppMaybeOutlinedIcon}
              label="Weak"
              count={report.weak.length}
              color="error"
            />
            <StatTile
              icon={ContentCopyOutlinedIcon}
              label="Reused"
              count={report.reused.length}
              color="warning"
            />
            <StatTile
              icon={ScheduleOutlinedIcon}
              label="Old"
              count={report.stale.length}
              color="info"
            />
          </Stack>

          <Typography variant="caption" align="center" sx={{ color: "text.secondary" }}>
            This check runs entirely on your device. Nothing is sent anywhere.
          </Typography>

          {allClear ? (
            <Stack spacing={1} sx={{ alignItems: "center", py: 1 }}>
              <CheckCircleOutlinedIcon sx={{ color: "success.main", fontSize: 34 }} />
              <Typography variant="body2">Everything looks healthy. Nice work.</Typography>
            </Stack>
          ) : (
            <Stack spacing={2}>
              <IssueGroup
                icon={GppMaybeOutlinedIcon}
                title="Weak"
                hint="Short or simple passwords worth strengthening."
                color="error"
                entries={report.weak}
                onSelect={onSelect}
              />
              <IssueGroup
                icon={ContentCopyOutlinedIcon}
                title="Reused"
                hint="The same password is used on more than one entry."
                color="warning"
                entries={report.reused}
                onSelect={onSelect}
              />
              <IssueGroup
                icon={ScheduleOutlinedIcon}
                title="Old"
                hint="Not changed in over a year."
                color="info"
                entries={report.stale}
                onSelect={onSelect}
              />
            </Stack>
          )}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button variant="contained" onClick={onClose}>
          Done
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default HealthDialog;
