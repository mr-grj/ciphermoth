import { useState } from "react";
import {
  Avatar,
  Box,
  Dialog,
  DialogContent,
  DialogTitle,
  IconButton,
  Stack,
  Tooltip,
  Typography,
} from "@mui/material";
import { alpha } from "@mui/material/styles";
import CloseIcon from "@mui/icons-material/Close";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import RestoreIcon from "@mui/icons-material/Restore";
import VisibilityIcon from "@mui/icons-material/Visibility";
import VisibilityOffIcon from "@mui/icons-material/VisibilityOff";

import ConfirmDialog from "../ConfirmDialog";
import {
  HISTORY_LIMIT,
  entrySubtitle,
  formatWhen,
  historyTimeline,
  relativeTime,
  usedFor,
} from "../../lib/passwordHistory";

const MASK = "••••••••";
const oneLine = { overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" };

// The caption under a value: when it was in use, with the exact time on hover.
const describe = (row) => {
  if (row.current) {
    return {
      label: "Current",
      parts: row.since ? [`since ${formatWhen(row.since)}`] : [],
      full: row.since ? `In use since ${formatWhen(row.since, { dateStyle: "long" })}` : "",
    };
  }
  return {
    label: row.until ? formatWhen(row.until) : "Earlier",
    parts: [
      row.until && `replaced ${relativeTime(row.until)}`,
      usedFor(row.since, row.until),
      row.sameAsCurrent && "same as current",
    ].filter(Boolean),
    full: row.until ? `In use until ${formatWhen(row.until, { dateStyle: "long" })}` : "",
  };
};

const HistoryRow = ({ row, shown, onToggle, onCopy, onRestore }) => {
  const { label, parts, full } = describe(row);
  return (
    <Box
      component="li"
      sx={(theme) => ({
        display: "flex",
        alignItems: "center",
        gap: 1,
        pl: 1.75,
        pr: 1,
        py: 1,
        borderRadius: 2,
        border: 1,
        borderColor: row.current ? alpha(theme.palette.secondary.main, 0.45) : "divider",
        bgcolor: row.current
          ? alpha(theme.palette.secondary.main, theme.palette.mode === "dark" ? 0.08 : 0.1)
          : "transparent",
      })}
    >
      <Box sx={{ flex: 1, minWidth: 0 }}>
        <Typography
          variant="body2"
          onClick={onToggle}
          title={shown ? undefined : "Click to reveal"}
          sx={{
            fontFamily: "'Space Mono', monospace",
            color: shown ? "text.primary" : "text.secondary",
            letterSpacing: shown ? 0 : 2,
            cursor: "pointer",
            overflowWrap: "anywhere",
            userSelect: shown ? "text" : "none",
          }}
        >
          {shown ? row.value : MASK}
        </Typography>
        <Typography
          variant="caption"
          title={full || undefined}
          sx={{ display: "block", color: "text.secondary", mt: 0.25 }}
        >
          <Box
            component="span"
            sx={{ fontWeight: 600, color: row.current ? "secondary.main" : "text.primary" }}
          >
            {label}
          </Box>
          {parts.map((part) => ` · ${part}`).join("")}
        </Typography>
      </Box>
      <Stack direction="row" sx={{ flexShrink: 0 }}>
        <Tooltip title={shown ? "Hide" : "Reveal"}>
          <IconButton size="small" onClick={onToggle} aria-label={shown ? "Hide" : "Reveal"}>
            {shown ? <VisibilityOffIcon fontSize="small" /> : <VisibilityIcon fontSize="small" />}
          </IconButton>
        </Tooltip>
        <Tooltip title="Copy">
          <IconButton size="small" onClick={onCopy} aria-label="Copy">
            <ContentCopyIcon fontSize="small" />
          </IconButton>
        </Tooltip>
        {onRestore && (
          <Tooltip title={row.current || row.sameAsCurrent ? "" : "Use this password again"}>
            <span>
              <IconButton
                size="small"
                onClick={onRestore}
                aria-label="Use this password again"
                disabled={row.current || row.sameAsCurrent}
                sx={{ visibility: row.current ? "hidden" : "visible" }}
              >
                <RestoreIcon fontSize="small" />
              </IconButton>
            </span>
          </Tooltip>
        )}
      </Stack>
    </Box>
  );
};

// The rows of an entry's password history. The vault's history dialog shows the
// current password too and can restore an old one; the edit form only lists the
// earlier values, since the current one is in the form above them.
export const PasswordHistoryList = ({
  entry,
  onCopy,
  onRestore,
  includeCurrent = true,
  revealAll = false,
}) => {
  const [revealed, setRevealed] = useState(() => new Set());
  const rows = historyTimeline(entry).filter((row) => includeCurrent || !row.current);
  const toggle = (key) =>
    setRevealed((previous) => {
      const next = new Set(previous);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  return (
    <Stack component="ul" spacing={1} sx={{ listStyle: "none", m: 0, p: 0 }}>
      {rows.map((row) => (
        <HistoryRow
          key={row.key}
          row={row}
          // "Reveal all" flips every row; a row's own toggle then flips it back.
          shown={revealAll !== revealed.has(row.key)}
          onToggle={() => toggle(row.key)}
          onCopy={() => onCopy(row.value, row.current ? "Password" : "Old password")}
          onRestore={onRestore && (() => onRestore(row))}
        />
      ))}
    </Stack>
  );
};

// Every password an entry has had, newest first, to copy one back or use it again.
const PasswordHistoryDialog = ({ entry, onClose, onCopy, onRestore }) => {
  const [revealAll, setRevealAll] = useState(false);
  const [restoring, setRestoring] = useState(null);
  const open = !!entry;
  const count = entry?.password_history?.length ?? 0;
  const subtitle = entrySubtitle(entry);

  const close = () => {
    setRestoring(null);
    onClose();
  };

  return (
    <>
      <Dialog
        open={open}
        onClose={close}
        maxWidth="sm"
        fullWidth
        slotProps={{ transition: { onExited: () => setRevealAll(false) } }}
      >
        <DialogTitle sx={{ display: "flex", alignItems: "center", gap: 1, pr: 1.5 }}>
          <Box sx={{ flex: 1 }}>Password history</Box>
          <Tooltip title={revealAll ? "Hide all" : "Reveal all"}>
            <IconButton
              onClick={() => setRevealAll((all) => !all)}
              aria-label={revealAll ? "Hide all" : "Reveal all"}
            >
              {revealAll ? <VisibilityOffIcon /> : <VisibilityIcon />}
            </IconButton>
          </Tooltip>
          <Tooltip title="Close">
            <IconButton onClick={close} aria-label="Close">
              <CloseIcon />
            </IconButton>
          </Tooltip>
        </DialogTitle>
        <DialogContent>
          {entry && (
            <>
              <Stack
                direction="row"
                spacing={1.5}
                sx={{ alignItems: "center", mb: 2, minWidth: 0 }}
              >
                <Avatar
                  variant="rounded"
                  sx={(theme) => ({
                    width: 40,
                    height: 40,
                    fontWeight: 700,
                    color: "secondary.main",
                    bgcolor: alpha(theme.palette.secondary.main, 0.16),
                  })}
                >
                  {[...entry.password_name.trim()][0]?.toUpperCase() ?? "?"}
                </Avatar>
                <Box sx={{ minWidth: 0 }}>
                  <Typography sx={{ fontWeight: 600, ...oneLine }} title={entry.password_name}>
                    {entry.password_name}
                  </Typography>
                  {subtitle && (
                    <Typography variant="body2" sx={{ color: "text.secondary", ...oneLine }}>
                      {subtitle}
                    </Typography>
                  )}
                </Box>
              </Stack>
              {count === 0 ? (
                <Typography variant="body2" sx={{ color: "text.secondary", py: 2 }}>
                  No earlier passwords yet. When you change this password, the old one is kept here.
                </Typography>
              ) : (
                <PasswordHistoryList
                  // A restore reorders the rows, so their reveal state starts over.
                  key={`${entry.password_name}:${entry.password_history[0]?.changed_at}`}
                  entry={entry}
                  revealAll={revealAll}
                  onCopy={onCopy}
                  onRestore={onRestore && ((row) => setRestoring(row))}
                />
              )}
              <Typography
                variant="caption"
                sx={{ display: "block", color: "text.disabled", mt: 2 }}
              >
                The last {HISTORY_LIMIT} passwords are kept, encrypted with the rest of the entry.
              </Typography>
            </>
          )}
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={open && !!restoring}
        title="Use this password again?"
        confirmText="Use again"
        onClose={() => setRestoring(null)}
        onConfirm={async () => {
          const row = restoring;
          if (await onRestore(row.value)) setRestoring(null);
        }}
      >
        It becomes the current password of <strong>{entry?.password_name}</strong>. The current one
        moves to the history
        {count >= HISTORY_LIMIT
          ? `, and the oldest saved password is dropped (only the last ${HISTORY_LIMIT} are kept).`
          : "."}{" "}
        Useful when a website still expects the old one, for example after a password change that
        did not go through.
      </ConfirmDialog>
    </>
  );
};

export default PasswordHistoryDialog;
