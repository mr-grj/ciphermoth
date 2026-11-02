import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Alert,
  Box,
  Button,
  CircularProgress,
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
import HealthDialog from "../components/vault/HealthDialog";
import ImportDialog from "../components/vault/ImportDialog";
import PasswordFormDialog from "../components/vault/PasswordFormDialog";
import TrashDialog from "../components/vault/TrashDialog";
import { createColumns } from "../components/vault/columns";
import { gridBaseSx } from "../components/vault/gridStyles";
import useClipboard from "../hooks/useClipboard";
import { PAGE_SIZES, loadPageSize, savePageSize } from "../lib/gridPreferences";

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
  const { enqueueSnackbar } = useSnackbar();
  const copy = useClipboard();

  const {
    get,
    create,
    update,
    remove,
    backup,
    importPasswords,
    importCsv,
    toggleFavorite,
    getTrash,
    restore,
    purge,
    getDamaged,
    removeDamaged,
  } = useStoreActions((actions) => actions.ciphermothModels.passwords);
  const { error, loading, passwords, trash, damaged, damageCheckError } = useStoreState(
    (state) => state.ciphermothModels.passwords
  );

  const [visibleRows, setVisibleRows] = useState(new Set());
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editTarget, setEditTarget] = useState(null);
  const [deleteTarget, setDeleteTarget] = useState(null);
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
    setDialogOpen(true);
  };

  const openEdit = useCallback((row) => {
    setEditTarget(row);
    setDialogOpen(true);
  }, []);

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

  const handleDelete = async () => {
    try {
      await remove(deleteTarget);
      enqueueSnackbar("Moved to trash.", { variant: "success" });
    } catch (err) {
      enqueueSnackbar(err.message, { variant: "error" });
    } finally {
      setDeleteTarget(null);
    }
  };

  const handleRestore = async (name) => {
    try {
      await restore(name);
      enqueueSnackbar("Restored from trash.", { variant: "success" });
    } catch (err) {
      enqueueSnackbar(err.message, { variant: "error" });
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

  const handlePurge = async (name) => {
    try {
      await purge(name);
      enqueueSnackbar("Permanently deleted.", { variant: "success" });
    } catch (err) {
      enqueueSnackbar(err.message, { variant: "error" });
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
        onDelete: setDeleteTarget,
      }),
    [visibleRows, toggleVisibility, handleToggleFavorite, copy, openEdit]
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
          sx={{ flexShrink: 0, flexWrap: "wrap", mb: 2, alignItems: "center" }}
        >
          <TextField
            size="small"
            placeholder="Search name, username, website or tag…"
            value={search}
            onChange={(e) => updateSearch(e.target.value)}
            sx={{ width: { xs: "100%", sm: 380 } }}
            slotProps={{
              input: {
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon fontSize="small" sx={{ color: "text.disabled" }} />
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
            disableRowSelectionOnClick
            density="compact"
            rowHeight={44}
            columnHeaderHeight={42}
            pageSizeOptions={PAGE_SIZES}
            paginationModel={paginationModel}
            onPaginationModelChange={handlePaginationChange}
            columnVisibilityModel={columnVisibilityModel}
            onColumnVisibilityModelChange={setColumnOverrides}
            slots={{
              noRowsOverlay: () => (
                <Box
                  sx={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    height: "100%",
                  }}
                >
                  <Typography variant="body2" sx={{ color: "text.secondary" }}>
                    No passwords match &ldquo;{search.trim()}&rdquo;.
                  </Typography>
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
        open={!!deleteTarget}
        title="Move to Trash"
        confirmText="Move to Trash"
        confirmColor="error"
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDelete}
      >
        Move <strong>{deleteTarget}</strong> to Trash? You can restore it later from the Trash.
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
