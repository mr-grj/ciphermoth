import { useMemo, useState } from "react";
import {
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  Tooltip,
  Typography,
} from "@mui/material";
import { DataGrid } from "@mui/x-data-grid";
import DeleteForeverIcon from "@mui/icons-material/DeleteForever";
import RestoreFromTrashIcon from "@mui/icons-material/RestoreFromTrash";

import ConfirmDialog from "../ConfirmDialog";
import NameList from "./NameList";
import SelectionBar from "./SelectionBar";
import { gridBaseSx } from "./gridStyles";
import {
  entriesWord,
  gridSelectionModel,
  mergeSelection,
  pruneSelection,
} from "../../lib/selection";

const formatDeleted = (iso) => {
  if (!iso) return "-";
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString();
};

const buildColumns = ({ onRestore, onPurge }) => [
  { field: "password_name", headerName: "Name", flex: 1, minWidth: 140 },
  {
    field: "username",
    headerName: "Username / email",
    flex: 1,
    minWidth: 150,
    renderCell: (params) => (
      <Typography variant="body2" sx={{ color: params.value ? "text.primary" : "text.disabled" }}>
        {params.value || "-"}
      </Typography>
    ),
  },
  {
    field: "deleted",
    headerName: "Deleted",
    flex: 1,
    minWidth: 170,
    renderCell: (params) => (
      <Typography variant="body2" sx={{ color: "text.secondary" }}>
        {formatDeleted(params.value)}
      </Typography>
    ),
  },
  {
    field: "actions",
    headerName: "Actions",
    width: 110,
    sortable: false,
    align: "center",
    headerAlign: "center",
    renderCell: (params) => (
      <Box sx={{ display: "flex", alignItems: "center", height: "100%" }}>
        <Tooltip title="Restore">
          <IconButton size="small" color="primary" onClick={() => onRestore([params.row])}>
            <RestoreFromTrashIcon fontSize="small" />
          </IconButton>
        </Tooltip>
        <Tooltip title="Delete forever">
          <IconButton size="small" color="error" onClick={() => onPurge([params.row])}>
            <DeleteForeverIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
    ),
  },
];

// Restore and Delete forever act on one row (its buttons) or on the selection. Both go
// through the all-or-nothing bulk routes. Restoring needs no confirmation (nothing is
// lost); deleting forever always asks and lists what goes.
const TrashDialog = ({ open, trash, onClose, onRestore, onPurge }) => {
  const [purgeTargets, setPurgeTargets] = useState(null);
  const [restoring, setRestoring] = useState(false);
  const [chosen, setChosen] = useState(() => new Set());

  const ids = useMemo(() => trash.map((row) => row.id), [trash]);
  const selected = pruneSelection(chosen, ids);
  const selectedRows = trash.filter((row) => selected.has(row.id));
  const rowSelectionModel = useMemo(() => gridSelectionModel(selected, ids), [selected, ids]);

  const restore = async (rows) => {
    setRestoring(true);
    try {
      if (await onRestore(rows)) setChosen(new Set());
    } finally {
      setRestoring(false);
    }
  };

  const columns = buildColumns({ onRestore: restore, onPurge: setPurgeTargets });

  const handlePurge = async () => {
    if (await onPurge(purgeTargets)) {
      setChosen(
        (prev) => new Set([...prev].filter((id) => !purgeTargets.some((r) => r.id === id)))
      );
    }
    setPurgeTargets(null);
  };

  const close = () => {
    setChosen(new Set());
    onClose();
  };

  const handleCellKeyDown = (params, event) => {
    if (event.key === "Escape" && selected.size > 0) {
      event.stopPropagation();
      setChosen(new Set());
      return;
    }
    const remove = event.key === "Delete" || (event.key === "Backspace" && event.metaKey);
    if (!remove || event.altKey || event.ctrlKey || event.shiftKey) return;
    event.preventDefault();
    setPurgeTargets(selectedRows.length ? selectedRows : [params.row]);
  };

  const many = purgeTargets?.length > 1;

  return (
    <Dialog open={open} onClose={close} maxWidth="md" fullWidth>
      <DialogTitle>Trash</DialogTitle>
      <DialogContent>
        {trash.length === 0 ? (
          <Typography variant="body2" sx={{ color: "text.secondary", py: 4, textAlign: "center" }}>
            Trash is empty. Deleted secrets rest here until you restore or purge them.
          </Typography>
        ) : (
          <>
            <Box sx={{ minHeight: 40, mb: 1.5, display: "flex", alignItems: "center" }}>
              {selected.size > 0 ? (
                <SelectionBar
                  count={selected.size}
                  onClear={() => setChosen(new Set())}
                  sx={{ width: "100%" }}
                >
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<RestoreFromTrashIcon />}
                    loading={restoring}
                    onClick={() => restore(selectedRows)}
                  >
                    Restore
                  </Button>
                  <Button
                    size="small"
                    color="error"
                    variant="contained"
                    disableElevation
                    startIcon={<DeleteForeverIcon />}
                    onClick={() => setPurgeTargets(selectedRows)}
                  >
                    Delete forever
                  </Button>
                </SelectionBar>
              ) : (
                <Typography variant="body2" sx={{ color: "text.secondary" }}>
                  Select entries to restore or delete several at once.
                </Typography>
              )}
            </Box>
            <DataGrid
              rows={trash}
              columns={columns}
              getRowId={(row) => row.id}
              checkboxSelection
              disableRowSelectionOnClick
              rowSelectionModel={rowSelectionModel}
              onRowSelectionModelChange={(model) =>
                setChosen((prev) => mergeSelection(pruneSelection(prev, ids), ids, model))
              }
              hideFooterSelectedRowCount
              onCellKeyDown={handleCellKeyDown}
              density="compact"
              rowHeight={44}
              columnHeaderHeight={42}
              autoHeight
              pageSizeOptions={[10, 25]}
              initialState={{ pagination: { paginationModel: { pageSize: 10 } } }}
              sx={gridBaseSx}
            />
          </>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={close}>Close</Button>
      </DialogActions>

      <ConfirmDialog
        open={!!purgeTargets}
        title="Delete Forever"
        confirmText="Delete Forever"
        confirmColor="error"
        onClose={() => setPurgeTargets(null)}
        onConfirm={handlePurge}
        details={
          many && (
            <NameList
              names={purgeTargets.map((row) => row.password_name)}
              aside={(index) => formatDeleted(purgeTargets[index].deleted)}
            />
          )
        }
      >
        {many ? (
          <>
            Permanently delete <strong>{entriesWord(purgeTargets.length)}</strong> and their
            attachments? This cannot be undone.
          </>
        ) : (
          <>
            Permanently delete <strong>{purgeTargets?.[0]?.password_name}</strong> (deleted{" "}
            {formatDeleted(purgeTargets?.[0]?.deleted)})? This cannot be undone.
          </>
        )}
      </ConfirmDialog>
    </Dialog>
  );
};

export default TrashDialog;
