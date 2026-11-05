// Shared DataGrid styling for the vault grids (main list + trash): divider
// border, vertically-centred cells, no focus outline on cells, and a sort arrow
// sized and coloured like the header text instead of a filled button.
export const gridBaseSx = {
  borderColor: "divider",
  "& .MuiDataGrid-cell": { display: "flex", alignItems: "center" },
  "& .MuiDataGrid-cell:focus": { outline: "none" },
  "& .MuiDataGrid-cell:focus-within": { outline: "none" },
  // The grid paints the button in its own header colour, which differs from ours.
  "& .MuiDataGrid-columnHeader .MuiDataGrid-sortButton": {
    width: 22,
    height: 22,
    p: 0.375,
    ml: 0.25,
    bgcolor: "transparent",
    color: "text.secondary",
    "&:hover": { bgcolor: "action.hover", color: "text.primary" },
  },
  "& .MuiDataGrid-sortIcon": { fontSize: 15, color: "inherit" },
};
