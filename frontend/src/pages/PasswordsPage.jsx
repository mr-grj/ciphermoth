import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  IconButton,
  InputAdornment,
  MenuItem,
  Stack,
  TextField,
  Tooltip,
  Typography,
  useMediaQuery,
} from "@mui/material";
import { DataGrid, useGridApiRef } from "@mui/x-data-grid";
import AddIcon from "@mui/icons-material/Add";
import CloseIcon from "@mui/icons-material/Close";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutlined";
import DownloadIcon from "@mui/icons-material/Download";
import HealthAndSafetyIcon from "@mui/icons-material/HealthAndSafety";
import SearchIcon from "@mui/icons-material/Search";
import UploadFileIcon from "@mui/icons-material/UploadFile";
import { useStoreActions, useStoreState } from "easy-peasy";
import { useSnackbar } from "notistack";

import BackupDialog from "../components/vault/BackupDialog";
import ConfirmDialog from "../components/ConfirmDialog";
import EmptyVault from "../components/vault/EmptyVault";
import NameList from "../components/vault/NameList";
import SelectionBar from "../components/vault/SelectionBar";
import HealthDialog from "../components/vault/HealthDialog";
import ImportDialog from "../components/vault/ImportDialog";
import PasswordFormDialog from "../components/vault/PasswordFormDialog";
import EntryContextMenu from "../components/vault/EntryContextMenu";
import TrashDialog from "../components/vault/TrashDialog";
import { createColumns, openUrl } from "../components/vault/columns";
import { gridBaseSx } from "../components/vault/gridStyles";
import useClipboard from "../hooks/useClipboard";
import useMenuAction from "../hooks/useMenuAction";
import { generateTotp } from "../lib/totp";
import { duplicateName, fromControl, isDeleteKey } from "../lib/shortcuts";
import { PAGE_SIZES, loadPageSize, savePageSize } from "../lib/gridPreferences";
import { entriesWord, gridSelectionModel, mergeSelection, pruneSelection } from "../lib/selection";

// Column header + pagination footer + about four rows. A shorter window scrolls the page.
const MIN_GRID_HEIGHT = 280;

const HeaderAction = ({ label, icon, compact, ...props }) => (
  <Tooltip title={compact ? label : ""}>
    <span>
      <Button
        variant="outlined"
        aria-label={label}
        startIcon={compact ? undefined : icon}
        sx={compact ? { minWidth: 40, px: 1 } : undefined}
        {...props}
      >
        {compact ? icon : label}
      </Button>
    </span>
  </Tooltip>
);

const buildSubtitle = (loading, passwords) => {
  if (loading) return "Loading…";
  const n = passwords.length;
  if (n === 0) return "Nothing here yet. Your secrets are waiting for the dark.";
  const word = n === 1 ? "secret" : "secrets";
  return `${n} ${word} in the dark.`;
};

const PasswordsPage = () => {
  const { enqueueSnackbar, closeSnackbar } = useSnackbar();
  const copy = useClipboard();

  const {
    get,
    create,
    update,
    trashMany,
    restoreMany,
    backup,
    importPasswords,
    importCsv,
    toggleFavorite,
    getTrash,
    purgeMany,
    getDamaged,
    removeDamaged,
  } = useStoreActions((actions) => actions.ciphermothModels.passwords);
  const { error, loading, passwords, trash, damaged, damageCheckError } = useStoreState(
    (state) => state.ciphermothModels.passwords
  );

  const [visibleRows, setVisibleRows] = useState(new Set());
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editTarget, setEditTarget] = useState(null);
  // An entry to copy into a new one (Duplicate); only read while editTarget is null.
  const [template, setTemplate] = useState(null);
  const [contextMenu, setContextMenu] = useState(null);
  // Names waiting for the Move to Trash confirmation: one row, or the selection.
  const [trashTargets, setTrashTargets] = useState(null);
  const [selected, setSelected] = useState(() => new Set());
  const [backupOpen, setBackupOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [healthOpen, setHealthOpen] = useState(false);
  const [trashOpen, setTrashOpen] = useState(false);
  const [removeDamagedOpen, setRemoveDamagedOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [folderFilter, setFolderFilter] = useState("");
  const [paginationModel, setPaginationModel] = useState(() => ({
    page: 0,
    pageSize: loadPageSize(),
  }));
  const [columnOverrides, setColumnOverrides] = useState({});
  const gridApi = useGridApiRef();
  const compactHeader = useMediaQuery((theme) => theme.breakpoints.down("md"));
  const wideEnoughForFolders = useMediaQuery((theme) => theme.breakpoints.up("md"));
  const wideEnoughForTags = useMediaQuery((theme) => theme.breakpoints.up("lg"));

  useEffect(() => {
    get();
    getTrash();
    getDamaged();
  }, [get, getTrash, getDamaged]);

  const damagedCount = damaged.entries.length + damaged.attachments.length;

  useEffect(() => {
    if (error) enqueueSnackbar(error, { variant: "error" });
  }, [error, enqueueSnackbar]);

  const toggleVisibility = useCallback((name) => {
    setVisibleRows((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }, []);

  const openAdd = () => {
    setEditTarget(null);
    setTemplate(null);
    setDialogOpen(true);
  };

  const openEdit = useCallback((row) => {
    setEditTarget(row);
    setDialogOpen(true);
  }, []);

  const openNewNote = () => {
    setEditTarget(null);
    setTemplate({ password_name: "", password_value: "", kind: "note" });
    setDialogOpen(true);
  };

  // The desktop menu bar. Actions that need entries say so instead of doing nothing.
  const needsEntries = (open) => () => {
    if (passwords.length) open();
    else enqueueSnackbar("Your vault is empty. Add an entry first.", { variant: "info" });
  };
  useMenuAction("new-login", openAdd);
  useMenuAction("new-note", openNewNote);
  useMenuAction("import", () => setImportOpen(true));
  useMenuAction(
    "backup",
    needsEntries(() => setBackupOpen(true))
  );
  useMenuAction(
    "health",
    needsEntries(() => setHealthOpen(true))
  );
  useMenuAction("trash", () => setTrashOpen(true));
  useMenuAction("find", () => {
    searchInput.current?.focus();
    searchInput.current?.select();
  });

  const openDuplicate = (row) => {
    const name = duplicateName(
      row.password_name,
      passwords.map((p) => p.password_name)
    );
    setEditTarget(null);
    setTemplate({ ...row, password_name: name, favorite: false, attachment_count: 0 });
    setDialogOpen(true);
  };

  const handleToggleFavorite = useCallback(
    async (row) => {
      try {
        await toggleFavorite({ passwordName: row.password_name, favorite: !row.favorite });
      } catch (err) {
        enqueueSnackbar(err.message, { variant: "error" });
      }
    },
    [toggleFavorite, enqueueSnackbar]
  );

  const handleSubmit = async (entry) => {
    if (editTarget) {
      await update({
        password: {
          password_name: editTarget.password_name,
          username: editTarget.username ?? null,
          password_value: editTarget.password_value,
          description: editTarget.description ?? null,
        },
        new_password: entry,
      });
      enqueueSnackbar(entry.kind === "note" ? "Secure note updated." : "Password updated.", {
        variant: "success",
      });
    } else {
      await create(entry);
      enqueueSnackbar(entry.kind === "note" ? "Secure note created." : "Password created.", {
        variant: "success",
      });
    }
    setDialogOpen(false);
  };

  // Entries that disappear (trashed, renamed, deleted elsewhere) leave the selection.
  useEffect(() => {
    setSelected((prev) =>
      pruneSelection(
        prev,
        passwords.map((p) => p.password_name)
      )
    );
  }, [passwords]);

  const askToTrash = useCallback((name) => setTrashTargets([name]), []);

  const undoTrash = async (rows) => {
    try {
      await restoreMany(rows);
      enqueueSnackbar(`${entriesWord(rows.length)} restored.`, { variant: "success" });
    } catch (err) {
      enqueueSnackbar(err.message, { variant: "error" });
    }
  };

  const handleTrash = async () => {
    const names = trashTargets;
    const byName = new Map(passwords.map((p) => [p.password_name, p]));
    const rows = names.map((name) => byName.get(name)).filter(Boolean);
    try {
      await trashMany(names);
      setSelected((prev) => new Set([...prev].filter((name) => !names.includes(name))));
      const message =
        names.length === 1
          ? `Moved ${names[0]} to trash.`
          : `${entriesWord(names.length)} moved to trash.`;
      enqueueSnackbar(message, {
        variant: "success",
        preventDuplicate: false,
        action: (key) => (
          <Button
            color="inherit"
            size="small"
            sx={{ fontWeight: 700 }}
            onClick={() => {
              closeSnackbar(key);
              undoTrash(rows);
            }}
          >
            Undo
          </Button>
        ),
      });
    } catch (err) {
      enqueueSnackbar(err.message, { variant: "error" });
    } finally {
      setTrashTargets(null);
    }
  };

  // Trash actions report success, so the dialog knows whether to clear its selection.
  const handleRestore = async (rows) => {
    try {
      await restoreMany(rows);
      enqueueSnackbar(
        rows.length === 1
          ? `Restored ${rows[0].password_name} from trash.`
          : `${entriesWord(rows.length)} restored from trash.`,
        { variant: "success" }
      );
      return true;
    } catch (err) {
      enqueueSnackbar(err.message, { variant: "error" });
      return false;
    }
  };

  const handleRemoveDamaged = async () => {
    setRemoveDamagedOpen(false);
    try {
      await removeDamaged(damaged);
      enqueueSnackbar("Damaged rows removed.", { variant: "success" });
    } catch (err) {
      enqueueSnackbar(err.message, { variant: "error" });
    }
  };

  const handlePurge = async (rows) => {
    try {
      await purgeMany(rows);
      enqueueSnackbar(
        rows.length === 1
          ? `Permanently deleted ${rows[0].password_name}.`
          : `${entriesWord(rows.length)} permanently deleted.`,
        { variant: "success" }
      );
      return true;
    } catch (err) {
      enqueueSnackbar(err.message, { variant: "error" });
      return false;
    }
  };

  const handleBackup = async (masterPassword) => {
    await backup(masterPassword);
    enqueueSnackbar("Download requested. Check that the backup file was saved and keep it safe.", {
      variant: "info",
    });
  };

  const columns = useMemo(
    () =>
      createColumns({
        visibleRows,
        onToggleVisibility: toggleVisibility,
        onToggleFavorite: handleToggleFavorite,
        onCopy: copy,
        onEdit: openEdit,
        onDelete: askToTrash,
      }),
    [visibleRows, toggleVisibility, handleToggleFavorite, copy, openEdit, askToTrash]
  );

  const folderOptions = useMemo(
    () =>
      [...new Set(passwords.map((p) => p.folder).filter(Boolean))].sort((a, b) =>
        a.localeCompare(b)
      ),
    [passwords]
  );
  const activeFolder = folderOptions.includes(folderFilter) ? folderFilter : "";

  const filteredPasswords = useMemo(() => {
    const query = search.trim().toLowerCase();
    const byFolder = activeFolder ? passwords.filter((p) => p.folder === activeFolder) : passwords;
    const matches = !query
      ? byFolder
      : byFolder.filter(
          (p) =>
            p.password_name.toLowerCase().includes(query) ||
            p.username?.toLowerCase().includes(query) ||
            p.description?.toLowerCase().includes(query) ||
            p.url?.toLowerCase().includes(query) ||
            p.folder?.toLowerCase().includes(query) ||
            p.tags?.some((tag) => tag.toLowerCase().includes(query)) ||
            p.custom_fields?.some(
              (f) =>
                f.label.toLowerCase().includes(query) ||
                (!f.hidden && f.value.toLowerCase().includes(query))
            )
        );

    return [...matches].sort(
      (a, b) =>
        Number(b.favorite) - Number(a.favorite) || a.password_name.localeCompare(b.password_name)
    );
  }, [passwords, search, activeFolder]);

  const visibleIds = useMemo(
    () => filteredPasswords.map((p) => p.password_name),
    [filteredPasswords]
  );
  const rowSelectionModel = useMemo(
    () => gridSelectionModel(selected, visibleIds),
    [selected, visibleIds]
  );
  const hiddenSelected = selected.size - rowSelectionModel.ids.size;
  const trashHidden = (trashTargets ?? []).filter((name) => !visibleIds.includes(name)).length;
  const handleSelectionChange = useCallback(
    (model) => {
      console.log("SEL", model.type, JSON.stringify([...model.ids]));
      setSelected((prev) => mergeSelection(prev, visibleIds, model));
    },
    [visibleIds]
  );
  const clearSelection = useCallback(() => setSelected(new Set()), []);
  const trashSelected = () => {
    const visibleFirst = [
      ...visibleIds.filter((name) => selected.has(name)),
      ...[...selected].filter((name) => !rowSelectionModel.ids.has(name)),
    ];
    setTrashTargets(visibleFirst);
  };

  // Delete moves the selection (or else the focused row) to the trash; Escape
  // clears the selection. Keys typed into anything editable are left alone.
  // Delete or Backspace moves the selection (or else the focused row) to the trash,
  // Enter edits the focused row, Escape clears the selection. Keys typed into
  // anything editable are left alone.
  const handleCellKeyDown = (params, event) => {
    if (contextMenu || event.target.closest("input:not([type=checkbox]), textarea")) return;
    if (event.key === "Escape" && selected.size > 0) {
      clearSelection();
    } else if (isDeleteKey(event)) {
      event.preventDefault();
      if (selected.size > 0) trashSelected();
      else askToTrash(params.row.password_name);
    } else if (event.key === "Enter" && !fromControl(event)) {
      event.preventDefault();
      openEdit(params.row);
    }
  };

  // Double-clicking a row edits it, unless the clicks were on a control in it.
  const handleRowDoubleClick = (params, event) => {
    if (!fromControl(event)) openEdit(params.row);
  };

  const handleRowContextMenu = (event) => {
    if (event.shiftKey) return; // Shift+right-click keeps the browser's own menu.
    const row = filteredPasswords.find((p) => p.password_name === event.currentTarget.dataset.id);
    if (!row) return;
    event.preventDefault();
    // A menu opened from the keyboard (Shift+F10, the menu key) has no pointer
    // position inside the row, so it opens under the row instead.
    const box = event.currentTarget.getBoundingClientRect();
    const { clientX: x, clientY: y } = event;
    const pointer = x >= box.left && x <= box.right && y >= box.top && y <= box.bottom;
    setContextMenu({
      row,
      selection: selected.has(row.password_name) ? selected.size : 0,
      top: pointer ? y : box.bottom,
      left: pointer ? x : box.left + 56,
    });
  };

  const copyTotp = async (secret) => {
    try {
      copy(await generateTotp(secret), "2FA code");
    } catch {
      enqueueSnackbar("This entry's 2FA secret is invalid.", { variant: "error" });
    }
  };

  const contextActions = {
    copy,
    copyTotp,
    openUrl,
    edit: openEdit,
    duplicate: openDuplicate,
    toggleFavorite: handleToggleFavorite,
    trash: askToTrash,
    trashSelection: trashSelected,
    clearSelection,
  };

  const subtitle = useMemo(() => buildSubtitle(loading, passwords), [loading, passwords]);
  const isEmpty = !loading && passwords.length === 0;

  // Columns nothing in the vault uses, or that do not fit, stay out of the way until
  // the user asks for them from the column menu.
  const columnVisibilityModel = useMemo(
    () => ({
      folder: wideEnoughForFolders && folderOptions.length > 0,
      tags: wideEnoughForTags && passwords.some((p) => p.tags?.length),
      totp_secret: passwords.some((p) => p.totp_secret),
      ...columnOverrides,
    }),
    [wideEnoughForFolders, wideEnoughForTags, folderOptions, passwords, columnOverrides]
  );

  const handlePaginationChange = useCallback((model) => {
    setPaginationModel((previous) => {
      if (model.pageSize !== previous.pageSize) savePageSize(model.pageSize);
      return model;
    });
  }, []);

  // Results of a new search or folder start from the first page, not wherever the old
  // list was left.
  const updateSearch = (next) => {
    setSearch(next);
    setPaginationModel((previous) => ({ ...previous, page: 0 }));
  };
  const searchInput = useRef(null);
  const clearSearch = () => {
    updateSearch("");
    searchInput.current?.focus();
  };
  const updateFolder = (next) => {
    setFolderFilter(next);
    setPaginationModel((previous) => ({ ...previous, page: 0 }));
  };

  // Every page starts at its first row, not at the scroll offset of the previous page.
  const shownPage = useRef(paginationModel.page);
  useEffect(() => {
    if (shownPage.current === paginationModel.page) return;
    shownPage.current = paginationModel.page;
    gridApi.current?.scroll?.({ top: 0 });
  }, [paginationModel.page, gridApi]);

  return (
    <Box sx={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
      <Stack
        direction="row"
        useFlexGap
        spacing={1.5}
        sx={{
          flexShrink: 0,
          flexWrap: "wrap",
          justifyContent: "space-between",
          alignItems: "flex-start",
          mb: { xs: 2, sm: 2.5 },
        }}
      >
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 700, lineHeight: 1.2 }}>
            The Vault
          </Typography>
          <Typography variant="body2" sx={{ color: "text.secondary", mt: 0.5 }}>
            {subtitle}
          </Typography>
        </Box>
        <Stack direction="row" spacing={1}>
          <HeaderAction
            label="Health"
            icon={<HealthAndSafetyIcon />}
            compact={compactHeader}
            onClick={() => setHealthOpen(true)}
            disabled={passwords.length === 0}
          />
          <HeaderAction
            label="Backup"
            icon={<DownloadIcon />}
            compact={compactHeader}
            onClick={() => setBackupOpen(true)}
            disabled={passwords.length === 0}
          />
          <HeaderAction
            label="Import"
            icon={<UploadFileIcon />}
            compact={compactHeader}
            onClick={() => setImportOpen(true)}
          />
          <HeaderAction
            label={trash.length ? `Trash (${trash.length})` : "Trash"}
            icon={<DeleteOutlineIcon />}
            compact={compactHeader}
            onClick={() => setTrashOpen(true)}
          />
          <Button variant="contained" startIcon={<AddIcon />} onClick={openAdd}>
            Add
          </Button>
        </Stack>
      </Stack>

      {!isEmpty && (
        <Stack
          direction="row"
          useFlexGap
          spacing={1.5}
          sx={{
            flexShrink: 0,
            flexWrap: "wrap",
            mb: 2,
            alignItems: "center",
            position: "relative",
          }}
        >
          <TextField
            size="small"
            placeholder="Search name, username, website or tag…"
            value={search}
            onChange={(e) => updateSearch(e.target.value)}
            // Escape clears a search the way the clear button does.
            onKeyDown={(e) => {
              if (e.key === "Escape" && search) {
                e.stopPropagation();
                updateSearch("");
              }
            }}
            inputRef={searchInput}
            sx={{ width: { xs: "100%", sm: 380 } }}
            slotProps={{
              input: {
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon fontSize="small" sx={{ color: "text.disabled" }} />
                  </InputAdornment>
                ),
                endAdornment: search && (
                  <InputAdornment position="end">
                    <Tooltip title="Clear search">
                      <IconButton
                        size="small"
                        edge="end"
                        aria-label="Clear search"
                        onClick={clearSearch}
                        sx={{ color: "text.secondary" }}
                      >
                        <CloseIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </InputAdornment>
                ),
              },
            }}
          />
          {folderOptions.length > 0 && (
            <TextField
              select
              size="small"
              label="Folder"
              value={activeFolder}
              onChange={(e) => updateFolder(e.target.value)}
              sx={{ width: { xs: "100%", sm: 200 } }}
            >
              <MenuItem value="">All folders</MenuItem>
              {folderOptions.map((f) => (
                <MenuItem key={f} value={f}>
                  {f}
                </MenuItem>
              ))}
            </TextField>
          )}
          {selected.size > 0 && (
            <SelectionBar
              count={selected.size}
              hidden={hiddenSelected}
              onClear={clearSelection}
              // Wide screens have room beside the filters; narrower ones cover the
              // first filter line, so ticking a row never moves the grid under the pointer.
              sx={{
                ml: { md: "auto" },
                position: { xs: "absolute", md: "static" },
                // A pixel past the field, so its focus ring never shows around the bar.
                top: -1,
                left: -1,
                right: -1,
                minHeight: 42,
                zIndex: 2,
              }}
            >
              <Button
                size="small"
                color="error"
                variant="contained"
                disableElevation
                startIcon={<DeleteOutlineIcon />}
                onClick={trashSelected}
              >
                Move to Trash
              </Button>
            </SelectionBar>
          )}
        </Stack>
      )}

      {damageCheckError && (
        <Alert
          severity="warning"
          sx={{ mb: 2, flexShrink: 0 }}
          action={
            <Button color="inherit" size="small" onClick={() => getDamaged()}>
              Retry
            </Button>
          }
        >
          {damageCheckError}
        </Alert>
      )}

      {damagedCount > 0 && (
        <Alert
          severity="warning"
          sx={{ mb: 2, flexShrink: 0 }}
          action={
            <Button color="inherit" size="small" onClick={() => setRemoveDamagedOpen(true)}>
              Remove
            </Button>
          }
        >
          {damagedCount} {damagedCount === 1 ? "item" : "items"} in the vault file cannot be read
          (damaged or altered), so {damagedCount === 1 ? "it is" : "they are"} not shown. Backups
          and master password changes wait until you restore a snapshot or remove{" "}
          {damagedCount === 1 ? "it" : "them"}.
        </Alert>
      )}

      {loading && (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}>
          <CircularProgress />
        </Box>
      )}

      {isEmpty && <EmptyVault onAdd={openAdd} />}

      {!loading && !isEmpty && (
        <Box sx={{ flex: "1 1 0", minHeight: MIN_GRID_HEIGHT, position: "relative" }}>
          <DataGrid
            apiRef={gridApi}
            rows={filteredPasswords}
            columns={columns}
            getRowId={(row) => row.password_name}
            checkboxSelection
            disableRowSelectionOnClick
            rowSelectionModel={rowSelectionModel}
            onRowSelectionModelChange={handleSelectionChange}
            hideFooterSelectedRowCount
            onCellKeyDown={handleCellKeyDown}
            onRowDoubleClick={handleRowDoubleClick}
            getRowClassName={(params) =>
              params.id === contextMenu?.row.password_name ? "contextMenuRow" : ""
            }
            density="compact"
            rowHeight={44}
            columnHeaderHeight={42}
            pageSizeOptions={PAGE_SIZES}
            paginationModel={paginationModel}
            onPaginationModelChange={handlePaginationChange}
            columnVisibilityModel={columnVisibilityModel}
            onColumnVisibilityModelChange={setColumnOverrides}
            slotProps={{
              row: {
                onContextMenu: handleRowContextMenu,
                // The grid re-focuses a cell on the mouseup after a mousedown in it,
                // which would pull focus out of the menu a right-click just opened.
                onMouseDownCapture: (event) => event.button === 2 && event.stopPropagation(),
                // A double-click edits; it should not also select the text under it.
                onMouseDown: (event) => event.detail > 1 && event.preventDefault(),
              },
            }}
            slots={{
              noRowsOverlay: () => (
                <Box
                  sx={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    flexDirection: "column",
                    gap: 1,
                    height: "100%",
                  }}
                >
                  <Typography variant="body2" sx={{ color: "text.secondary" }}>
                    {search.trim() ? (
                      <>No passwords match &ldquo;{search.trim()}&rdquo;.</>
                    ) : (
                      "No passwords in this folder."
                    )}
                  </Typography>
                  {search && (
                    <Button size="small" onClick={clearSearch}>
                      Clear search
                    </Button>
                  )}
                </Box>
              ),
            }}
            sx={{
              ...gridBaseSx,
              position: "absolute",
              inset: 0,
              bgcolor: "background.paper",
              borderRadius: 2.5,
              "& .MuiDataGrid-columnHeaders": { borderColor: "divider" },
              "& .MuiDataGrid-columnHeader": { bgcolor: "background.paper" },
              "& .MuiDataGrid-columnHeaderTitle": {
                fontWeight: 600,
                color: "text.secondary",
              },
              "& .MuiDataGrid-row:hover": { bgcolor: "action.hover" },
              "& .MuiDataGrid-row.contextMenuRow": {
                bgcolor: "action.focus",
                boxShadow: (theme) => `inset 3px 0 0 ${theme.palette.secondary.main}`,
              },
              // Keeps the page arrows clear of the floating theme toggle.
              "& .MuiDataGrid-footerContainer": { pr: { xs: 7, sm: 8 } },
              "& .MuiTablePagination-selectLabel, & .MuiTablePagination-input": {
                display: { xs: "none", sm: "inline-flex" },
              },
              "& .rowHoverActions": {
                opacity: 0,
                pointerEvents: "none",
                transition: "opacity 120ms ease",
              },
              "& .MuiDataGrid-row:hover .rowHoverActions, & .MuiDataGrid-row:has(:focus-visible) .rowHoverActions":
                {
                  opacity: 1,
                  pointerEvents: "auto",
                },
              // Touch screens have no hover, so the row actions stay visible there.
              "@media (hover: none)": {
                "& .rowHoverActions": { opacity: 1, pointerEvents: "auto" },
              },
            }}
          />
        </Box>
      )}

      <PasswordFormDialog
        open={dialogOpen}
        editTarget={editTarget}
        template={template}
        folderOptions={folderOptions}
        onClose={() => setDialogOpen(false)}
        onSubmit={handleSubmit}
        onCopy={copy}
      />
      <BackupDialog
        open={backupOpen}
        onClose={() => setBackupOpen(false)}
        onBackup={handleBackup}
      />
      <ImportDialog
        open={importOpen}
        onClose={() => setImportOpen(false)}
        onImport={importPasswords}
        onImportCsv={importCsv}
      />
      <HealthDialog
        open={healthOpen}
        passwords={passwords}
        onClose={() => setHealthOpen(false)}
        onSelect={(row) => {
          setHealthOpen(false);
          openEdit(row);
        }}
      />
      <ConfirmDialog
        open={!!trashTargets}
        title="Move to Trash"
        confirmText="Move to Trash"
        confirmColor="error"
        focusConfirm
        onClose={() => setTrashTargets(null)}
        onConfirm={handleTrash}
        details={trashTargets?.length > 1 && <NameList names={trashTargets} />}
      >
        {trashTargets?.length > 1 ? (
          <>
            Move <strong>{entriesWord(trashTargets.length)}</strong> to Trash? You can restore them
            later from the Trash.
            {trashHidden > 0 &&
              ` ${trashHidden} of them ${trashHidden === 1 ? "is" : "are"} hidden by the current filter.`}
          </>
        ) : (
          <>
            Move <strong>{trashTargets?.[0]}</strong> to Trash? You can restore it later from the
            Trash.
          </>
        )}
      </ConfirmDialog>
      <ConfirmDialog
        open={removeDamagedOpen}
        title="Remove damaged items"
        confirmText="Remove"
        confirmColor="error"
        onClose={() => setRemoveDamagedOpen(false)}
        onConfirm={handleRemoveDamaged}
      >
        Permanently remove {damagedCount} unreadable {damagedCount === 1 ? "item" : "items"}? A
        removed entry takes its attachments with it. If you have a snapshot from before the damage,
        restoring it keeps them instead.
      </ConfirmDialog>
      <EntryContextMenu
        menu={contextMenu}
        onClose={() => setContextMenu(null)}
        actions={contextActions}
      />
      <TrashDialog
        open={trashOpen}
        trash={trash}
        onClose={() => setTrashOpen(false)}
        onRestore={handleRestore}
        onPurge={handlePurge}
      />
    </Box>
  );
};

export default PasswordsPage;
