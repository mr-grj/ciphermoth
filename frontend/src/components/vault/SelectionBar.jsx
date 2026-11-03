import { Box, IconButton, Stack, Tooltip, Typography } from "@mui/material";
import { alpha } from "@mui/material/styles";
import CloseIcon from "@mui/icons-material/Close";

const tint = (theme) =>
  alpha(theme.palette.secondary.main, theme.palette.mode === "dark" ? 0.1 : 0.14);

// The bulk-action bar shown while rows are selected. `hidden` counts selected rows
// the current search or folder does not show, so they are never acted on unseen.
const SelectionBar = ({ count, hidden = 0, onClear, children, sx }) => (
  <Stack
    direction="row"
    role="region"
    aria-label="Selected entries"
    spacing={1}
    sx={[
      (theme) => ({
        alignItems: "center",
        minHeight: 40,
        pl: 0.5,
        pr: 0.75,
        borderRadius: 1,
        border: 1,
        borderColor: alpha(theme.palette.secondary.main, 0.45),
        // Opaque, so it can sit on top of the filters on narrow screens.
        bgcolor: "background.paper",
        backgroundImage: `linear-gradient(${tint(theme)}, ${tint(theme)})`,
        animation: "selectionBarIn 140ms ease-out",
        "@keyframes selectionBarIn": {
          from: { opacity: 0, transform: "translateY(-2px)" },
          to: { opacity: 1, transform: "none" },
        },
      }),
      ...(Array.isArray(sx) ? sx : [sx]),
    ]}
  >
    <Tooltip title="Clear selection">
      <IconButton size="small" onClick={onClear} aria-label="Clear selection">
        <CloseIcon fontSize="small" />
      </IconButton>
    </Tooltip>
    <Box sx={{ minWidth: 0, flex: 1, display: "flex", alignItems: "baseline", gap: 1 }}>
      <Typography variant="body2" sx={{ fontWeight: 600, whiteSpace: "nowrap" }}>
        {count} selected
      </Typography>
      {hidden > 0 && (
        <Tooltip title="Selected earlier, but hidden by the current search or folder. They are included in bulk actions.">
          <Typography
            variant="caption"
            sx={{
              color: "text.secondary",
              whiteSpace: "nowrap",
              overflow: "hidden",
              textOverflow: "ellipsis",
              minWidth: 0,
              cursor: "help",
            }}
          >
            {hidden} hidden by filter
          </Typography>
        </Tooltip>
      )}
    </Box>
    <Stack direction="row" spacing={1} sx={{ flexShrink: 0 }}>
      {children}
    </Stack>
  </Stack>
);

export default SelectionBar;
