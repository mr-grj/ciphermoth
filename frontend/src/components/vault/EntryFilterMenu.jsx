import { useState } from "react";
import {
  Badge,
  Button,
  Checkbox,
  Divider,
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
  Tooltip,
  Typography,
} from "@mui/material";
import { alpha } from "@mui/material/styles";
import FilterListIcon from "@mui/icons-material/FilterList";

import { ENTRY_FILTERS } from "../../lib/entryFilters";

// The vault's quick filters (favorites, secure notes, notes, attachments, 2FA): a
// button that shows how many are on, and a menu that stays open while they are
// toggled, each with the number of entries it matches.
const EntryFilterMenu = ({ active, counts, onChange, compact = false }) => {
  const [anchor, setAnchor] = useState(null);
  const toggle = (key) => {
    const next = new Set(active);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    onChange(next);
  };
  const label = active.size ? `Filters (${active.size})` : "Filters";

  return (
    <>
      <Tooltip title={compact ? label : ""}>
        <Button
          variant="outlined"
          color="inherit"
          aria-label={label}
          aria-haspopup="menu"
          aria-expanded={!!anchor}
          onClick={(event) => setAnchor(event.currentTarget)}
          startIcon={compact ? undefined : <FilterListIcon />}
          sx={(theme) => ({
            height: 40,
            flexShrink: 0,
            color: active.size ? "text.primary" : "text.secondary",
            borderColor: active.size ? "secondary.main" : "divider",
            bgcolor: active.size ? alpha(theme.palette.secondary.main, 0.14) : "transparent",
            "&:hover": {
              borderColor: active.size ? "secondary.main" : "text.secondary",
              bgcolor: active.size ? alpha(theme.palette.secondary.main, 0.22) : "action.hover",
            },
            ...(compact && { minWidth: 40, px: 1 }),
          })}
        >
          {compact ? (
            <Badge color="secondary" badgeContent={active.size} invisible={!active.size}>
              <FilterListIcon />
            </Badge>
          ) : (
            label
          )}
        </Button>
      </Tooltip>
      <Menu
        anchorEl={anchor}
        open={!!anchor}
        onClose={() => setAnchor(null)}
        slotProps={{ list: { dense: true, "aria-label": "Filters", sx: { minWidth: 240 } } }}
      >
        {ENTRY_FILTERS.map((filter) => {
          const count = counts.get(filter.key) ?? 0;
          const on = active.has(filter.key);
          return (
            <MenuItem
              key={filter.key}
              onClick={() => toggle(filter.key)}
              // A filter nothing matches stays reachable when it is on, to turn it off.
              disabled={!count && !on}
              role="menuitemcheckbox"
              aria-checked={on}
            >
              <ListItemIcon>
                <Checkbox
                  edge="start"
                  size="small"
                  checked={on}
                  tabIndex={-1}
                  disableRipple
                  sx={{ p: 0 }}
                />
              </ListItemIcon>
              <ListItemText>{filter.label}</ListItemText>
              <Typography variant="caption" sx={{ color: "text.disabled", ml: 3 }}>
                {count}
              </Typography>
            </MenuItem>
          );
        })}
        <Divider />
        <MenuItem
          disabled={!active.size}
          onClick={() => {
            onChange(new Set());
            setAnchor(null);
          }}
        >
          <ListItemText inset>Clear filters</ListItemText>
        </MenuItem>
      </Menu>
    </>
  );
};

export default EntryFilterMenu;
