import { useMemo, useRef, useState } from "react";
import {
  Box,
  Button,
  Collapse,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  InputAdornment,
  Link,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  TextField,
  Typography,
} from "@mui/material";
import CreateNewFolderOutlinedIcon from "@mui/icons-material/CreateNewFolderOutlined";
import FolderOffOutlinedIcon from "@mui/icons-material/FolderOffOutlined";
import FolderOutlinedIcon from "@mui/icons-material/FolderOutlined";
import SearchIcon from "@mui/icons-material/Search";

import NameList from "./NameList";
import {
  MAX_FOLDER_LENGTH,
  bestRow,
  folderLength,
  folderProblem,
  pickerRows,
  shortFolder,
} from "../../lib/folders";
import { entriesWord } from "../../lib/selection";

// Shows a character count once a name gets close to the limit.
const COUNTER_FROM = MAX_FOLDER_LENGTH - 40;

const oneLine = { overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" };

// Move one entry or a selection into a folder: pick an existing folder, type to
// filter or create one, or take the entries out of their folder. Enter moves to
// the highlighted row, arrows change it, a double-click moves at once.
const MoveToFolderDialog = ({ open, entries, folders, counts, hidden = 0, onClose, onMove }) => {
  const [query, setQuery] = useState("");
  const [picked, setPicked] = useState(null);
  const [showNames, setShowNames] = useState(false);
  const [busy, setBusy] = useState(false);
  const rowRefs = useRef(new Map());

  const reset = () => {
    setQuery("");
    setPicked(null);
    setShowNames(false);
  };

  const list = entries ?? [];
  const single = list.length === 1;
  const currentFolders = new Set(list.map((entry) => entry.folder || null));
  // The one folder every entry is already in, which moving to would change nothing.
  const current = currentFolders.size === 1 ? [...currentFolders][0] : undefined;

  const rows = useMemo(() => pickerRows(query, folders), [query, folders]);
  const isCurrent = (row) => !row.isNew && row.folder === current;
  const choices = rows.filter((row) => !isCurrent(row));
  const target = choices.find((row) => row.key === picked) ?? null;
  const problem = query.trim() ? folderProblem(query) : null;
  const length = folderLength(query.trim());

  const changeQuery = (next) => {
    setQuery(next);
    const nextRows = pickerRows(next, folders).filter((row) => !isCurrent(row));
    setPicked(bestRow(next, folders, nextRows)?.key ?? null);
  };

  const highlight = (key) => {
    setPicked(key);
    rowRefs.current.get(key)?.scrollIntoView?.({ block: "nearest" });
  };

  const move = async (row = target) => {
    if (!row || busy) return;
    setBusy(true);
    try {
      await onMove(row.folder);
    } finally {
      setBusy(false);
    }
  };

  const handleKeyDown = (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      move();
    } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      if (!choices.length) return;
      event.preventDefault();
      const at = choices.findIndex((row) => row.key === picked);
      const step = event.key === "ArrowDown" ? 1 : -1;
      const next = at === -1 ? (step > 0 ? 0 : choices.length - 1) : at + step;
      highlight(choices[(next + choices.length) % choices.length].key);
    }
  };

  const alreadyThere = (folder) => list.filter((entry) => (entry.folder || null) === folder).length;

  const secondary = (row) => {
    if (row.isNew) return "New folder";
    if (isCurrent(row)) return single ? "Current folder" : "All already here";
    const here = alreadyThere(row.folder);
    if (row.folder === null) {
      if (here) return `${here} already without a folder`;
      return single ? "Take out of its folder" : "Take out of their folder";
    }
    const total = entriesWord(counts.get(row.folder) ?? 0);
    return here && !single ? `${total} · ${here} of these already here` : total;
  };

  const icon = (row) => {
    if (row.isNew) return <CreateNewFolderOutlinedIcon fontSize="small" />;
    if (row.folder === null) return <FolderOffOutlinedIcon fontSize="small" />;
    return <FolderOutlinedIcon fontSize="small" />;
  };

  let confirmText = "Move";
  if (target?.isNew) confirmText = "Create and move";
  else if (target?.folder === null) confirmText = "Remove from folder";

  let empty = null;
  if (!rows.length) {
    empty = problem
      ? "Shorten the name to create a new folder."
      : `No folder matches “${shortFolder(query.trim())}”.`;
  } else if (!folders.length && !query.trim()) {
    empty = "No folders yet. Type a name to create the first one.";
  }

  const names = list.map((entry) => entry.password_name);
  const asides = list.map((entry) => (entry.folder ? shortFolder(entry.folder, 24) : ""));

  return (
    <Dialog
      open={open}
      onClose={busy ? undefined : onClose}
      maxWidth="xs"
      fullWidth
      slotProps={{ transition: { onExited: reset } }}
    >
      <DialogTitle>Move to folder</DialogTitle>
      <DialogContent>
        <Typography variant="body2" sx={{ color: "text.secondary", overflowWrap: "anywhere" }}>
          {single ? (
            <>
              Move <strong>{names[0]}</strong> to a folder.
            </>
          ) : (
            <>
              Move <strong>{entriesWord(list.length)}</strong> to a folder.
              {hidden > 0 &&
                ` ${hidden} of them ${hidden === 1 ? "is" : "are"} hidden by the current filter.`}{" "}
              <Link
                component="button"
                type="button"
                variant="body2"
                onClick={() => setShowNames((shown) => !shown)}
                sx={{ verticalAlign: "baseline" }}
              >
                {showNames ? "Hide entries" : "Show entries"}
              </Link>
            </>
          )}
        </Typography>
        {!single && (
          <Collapse in={showNames} unmountOnExit>
            <NameList names={names} aside={(index) => asides[index]} />
          </Collapse>
        )}

        <TextField
          autoFocus
          fullWidth
          size="small"
          placeholder={folders.length ? "Find or create a folder" : "Name a new folder"}
          value={query}
          onChange={(event) => changeQuery(event.target.value)}
          onKeyDown={handleKeyDown}
          error={length > MAX_FOLDER_LENGTH}
          helperText={
            length > COUNTER_FROM ? (
              <Box component="span" sx={{ display: "flex", justifyContent: "space-between" }}>
                <span>{length > MAX_FOLDER_LENGTH ? problem : ""}</span>
                <span>
                  {length}/{MAX_FOLDER_LENGTH}
                </span>
              </Box>
            ) : undefined
          }
          sx={{ mt: 2 }}
          slotProps={{
            input: {
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon fontSize="small" sx={{ color: "text.disabled" }} />
                </InputAdornment>
              ),
            },
            htmlInput: { "aria-label": "Folder name", spellCheck: false },
          }}
        />

        <List
          dense
          aria-label="Folders"
          sx={{
            mt: 1.5,
            py: 0.5,
            maxHeight: 248,
            overflowY: "auto",
            border: 1,
            borderColor: "divider",
            borderRadius: 1.5,
          }}
        >
          {rows.map((row) => (
            <ListItemButton
              key={row.key}
              ref={(node) => {
                if (node) rowRefs.current.set(row.key, node);
                else rowRefs.current.delete(row.key);
              }}
              selected={row.key === picked}
              disabled={isCurrent(row) || busy}
              onClick={() => setPicked(row.key)}
              onDoubleClick={() => move(row)}
              title={row.folder ?? undefined}
              sx={{ borderRadius: 1, mx: 0.5 }}
            >
              <ListItemIcon sx={{ minWidth: 34, color: row.isNew ? "secondary.dark" : undefined }}>
                {icon(row)}
              </ListItemIcon>
              <ListItemText
                primary={row.folder ?? "No folder"}
                secondary={secondary(row)}
                slotProps={{
                  primary: { sx: { ...oneLine, fontWeight: row.isNew ? 600 : 500 } },
                  secondary: { sx: oneLine },
                }}
                sx={{ minWidth: 0, my: 0.25 }}
              />
            </ListItemButton>
          ))}
          {empty && (
            <Typography
              component="li"
              variant="body2"
              sx={{ px: 2, py: 1, color: "text.secondary" }}
            >
              {empty}
            </Typography>
          )}
        </List>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={busy}>
          Cancel
        </Button>
        <Button variant="contained" onClick={() => move()} disabled={!target} loading={busy}>
          {confirmText}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default MoveToFolderDialog;
