import { Divider, ListItemIcon, ListItemText, Menu, MenuItem, Typography } from "@mui/material";
import ClearAllIcon from "@mui/icons-material/ClearAll";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutlined";
import EditIcon from "@mui/icons-material/Edit";
import KeyIcon from "@mui/icons-material/Key";
import LinkIcon from "@mui/icons-material/Link";
import LibraryAddOutlinedIcon from "@mui/icons-material/LibraryAddOutlined";
import OpenInNewIcon from "@mui/icons-material/OpenInNew";
import PersonOutlineIcon from "@mui/icons-material/PersonOutlined";
import PinOutlinedIcon from "@mui/icons-material/PinOutlined";
import StarIcon from "@mui/icons-material/Star";
import StarBorderIcon from "@mui/icons-material/StarBorder";
import StickyNote2OutlinedIcon from "@mui/icons-material/StickyNote2Outlined";

import { DELETE_KEY_LABEL } from "../../lib/shortcuts";

const Item = ({ icon, label, hint, onClick, danger = false }) => (
  <MenuItem onClick={onClick} sx={danger ? { color: "error.main" } : undefined}>
    <ListItemIcon sx={danger ? { color: "error.main" } : undefined}>{icon}</ListItemIcon>
    <ListItemText>{label}</ListItemText>
    {hint && (
      <Typography variant="caption" sx={{ color: "text.disabled", ml: 3 }}>
        {hint}
      </Typography>
    )}
  </MenuItem>
);

const Heading = ({ children }) => (
  <Typography
    component="li"
    variant="caption"
    sx={{
      display: "block",
      px: 2,
      pt: 0.5,
      pb: 0.75,
      maxWidth: 280,
      color: "text.secondary",
      fontWeight: 600,
      overflow: "hidden",
      textOverflow: "ellipsis",
      whiteSpace: "nowrap",
    }}
  >
    {children}
  </Typography>
);

// The right-click menu of a vault row: the copy actions people reach for most, then
// the entry's own actions. Opened on a row that is part of a larger selection, it
// offers the actions that apply to the whole selection instead.
const EntryContextMenu = ({ menu, onClose, actions }) => {
  const row = menu?.row;
  const run = (action) => () => {
    onClose();
    action();
  };

  let items = [];
  if (menu?.selection > 1) {
    items = [
      <Heading key="heading">{menu.selection} selected</Heading>,
      <Item
        key="trash"
        danger
        icon={<DeleteOutlineIcon fontSize="small" />}
        label={`Move ${menu.selection} to Trash`}
        hint={DELETE_KEY_LABEL}
        onClick={run(actions.trashSelection)}
      />,
      <Item
        key="clear"
        icon={<ClearAllIcon fontSize="small" />}
        label="Clear selection"
        hint="Esc"
        onClick={run(actions.clearSelection)}
      />,
    ];
  } else if (row) {
    const note = row.kind === "note";
    items = [
      <Heading key="heading">{row.password_name}</Heading>,
      row.username && (
        <Item
          key="username"
          icon={<PersonOutlineIcon fontSize="small" />}
          label="Copy username"
          onClick={run(() => actions.copy(row.username, "Username"))}
        />
      ),
      <Item
        key="value"
        icon={note ? <StickyNote2OutlinedIcon fontSize="small" /> : <KeyIcon fontSize="small" />}
        label={note ? "Copy note" : "Copy password"}
        onClick={run(() => actions.copy(row.password_value, note ? "Note" : "Password"))}
      />,
      row.totp_secret && (
        <Item
          key="totp"
          icon={<PinOutlinedIcon fontSize="small" />}
          label="Copy 2FA code"
          onClick={run(() => actions.copyTotp(row.totp_secret))}
        />
      ),
      row.url && (
        <Item
          key="url"
          icon={<LinkIcon fontSize="small" />}
          label="Copy website"
          onClick={run(() => actions.copy(row.url, "Website"))}
        />
      ),
      row.url && (
        <Item
          key="open"
          icon={<OpenInNewIcon fontSize="small" />}
          label="Open website"
          onClick={run(() => actions.openUrl(row.url))}
        />
      ),
      <Divider key="divider-entry" />,
      <Item
        key="edit"
        icon={<EditIcon fontSize="small" />}
        label="Edit"
        hint="Enter"
        onClick={run(() => actions.edit(row))}
      />,
      <Item
        key="duplicate"
        icon={<LibraryAddOutlinedIcon fontSize="small" />}
        label="Duplicate"
        onClick={run(() => actions.duplicate(row))}
      />,
      <Item
        key="favorite"
        icon={row.favorite ? <StarIcon fontSize="small" /> : <StarBorderIcon fontSize="small" />}
        label={row.favorite ? "Remove from favorites" : "Add to favorites"}
        onClick={run(() => actions.toggleFavorite(row))}
      />,
      <Divider key="divider-trash" />,
      <Item
        key="trash"
        danger
        icon={<DeleteOutlineIcon fontSize="small" />}
        label="Move to Trash"
        hint={DELETE_KEY_LABEL}
        onClick={run(() => actions.trash(row.password_name))}
      />,
    ].filter(Boolean);
  }

  return (
    <Menu
      open={!!menu}
      onClose={onClose}
      anchorReference="anchorPosition"
      anchorPosition={menu ? { top: menu.top, left: menu.left } : undefined}
      slotProps={{
        list: { dense: true, "aria-label": "Entry actions", sx: { minWidth: 220 } },
        // Right-clicking outside closes the menu rather than opening the browser's.
        root: {
          onContextMenu: (event) => {
            event.preventDefault();
            onClose();
          },
        },
      }}
    >
      {items}
    </Menu>
  );
};

export default EntryContextMenu;
