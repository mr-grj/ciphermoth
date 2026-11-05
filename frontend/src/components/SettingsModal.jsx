import { useEffect, useState } from "react";
import {
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  FormControlLabel,
  InputAdornment,
  Stack,
  Switch,
  Tab,
  Tabs,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import HelpOutlineIcon from "@mui/icons-material/HelpOutlined";
import { useStoreActions, useStoreState } from "easy-peasy";
import { useSnackbar } from "notistack";

import ExtensionSettings from "./extension/ExtensionSettings";
import SecuritySettings from "./security/SecuritySettings";
import { IS_DESKTOP } from "../platform";

const FIELDS = [
  {
    key: "inactivity_ms",
    label: "Inactivity timeout",
    tooltip:
      "How long the app waits without any user activity before logging you out automatically.",
    min: 30,
    max: 3600,
  },
  {
    key: "warn_before_ms",
    label: "Warning before logout",
    tooltip:
      "How far in advance of the inactivity timeout a warning is shown. Must be less than the inactivity timeout.",
    min: 5,
    max: 600,
  },
  {
    key: "hidden_ms",
    label: "Hidden tab timeout",
    tooltip:
      "How long the tab can stay in the background (minimised or switched away) before you are logged out.",
    min: 10,
    max: 3600,
  },
  {
    key: "debounce_ms",
    label: "Activity debounce",
    tooltip:
      "Minimum interval between activity detections. Prevents the inactivity timer from being reset too aggressively.",
    min: 1,
    max: 10,
  },
  {
    key: "clipboard_clear_ms",
    label: "Clipboard clear delay",
    tooltip: "How long after copying a password the clipboard is automatically wiped.",
    min: 5,
    max: 600,
  },
];

const toSec = (ms) => Math.round(ms / 1000);
const toMs = (sec) => Math.round(Number(sec)) * 1000;

const toForm = (settings) => ({
  ...Object.fromEntries(FIELDS.map(({ key }) => [key, toSec(settings[key])])),
  update_check_enabled: settings.update_check_enabled ?? true,
});

const isDirty = (form, settings) =>
  FIELDS.some(({ key }) => Number(form[key]) !== toSec(settings[key])) ||
  form.update_check_enabled !== (settings.update_check_enabled ?? true);

const SettingsModal = ({ open, onClose, initialTab = "general" }) => {
  const { enqueueSnackbar } = useSnackbar();

  const { update } = useStoreActions((a) => a.ciphermothModels.settings);
  const settings = useStoreState((s) => s.ciphermothModels.settings.settings);

  const [form, setForm] = useState(() => toForm(settings));
  const [formError, setFormError] = useState("");
  const [saving, setSaving] = useState(false);
  const [tab, setTab] = useState(initialTab);

  useEffect(() => {
    if (open) {
      setForm(toForm(settings));
      setFormError("");
    }
  }, [open, settings]);

  useEffect(() => {
    if (open) setTab(initialTab);
  }, [open, initialTab]);

  const handleChange = (key) => (e) => {
    setForm((prev) => ({ ...prev, [key]: e.target.value }));
    setFormError("");
  };

  const handleSave = async () => {
    if (Number(form.warn_before_ms) >= Number(form.inactivity_ms)) {
      setFormError("Warning before logout must be less than the inactivity timeout.");
      return;
    }
    setSaving(true);
    try {
      await update({
        ...Object.fromEntries(FIELDS.map(({ key }) => [key, toMs(form[key])])),
        update_check_enabled: form.update_check_enabled,
      });
      enqueueSnackbar("Settings saved.", { variant: "success" });
      onClose();
    } catch (err) {
      setFormError(err.message);
    } finally {
      setSaving(false);
    }
  };

  const dirty = isDirty(form, settings);

  return (
    <Dialog open={open} onClose={saving ? undefined : onClose} maxWidth="xs" fullWidth>
      <DialogTitle sx={{ pb: 0 }}>Settings</DialogTitle>
      <Tabs
        value={tab}
        onChange={(_, value) => setTab(value)}
        sx={{ px: 3, borderBottom: 1, borderColor: "divider" }}
      >
        <Tab label="General" value="general" />
        <Tab label="Security" value="security" />
        {!IS_DESKTOP && <Tab label="Browser extension" value="extension" />}
      </Tabs>
      <DialogContent>
        {tab === "security" && <SecuritySettings open={open} />}
        {tab === "extension" && <ExtensionSettings open={open} />}
        <Stack spacing={1.5} sx={{ mt: 1, display: tab === "general" ? "flex" : "none" }}>
          {FIELDS.map(({ key, label, tooltip, min, max }) => (
            <TextField
              key={key}
              label={label}
              type="number"
              size="small"
              value={form[key]}
              onChange={handleChange(key)}
              fullWidth
              slotProps={{
                htmlInput: { min, max, step: 1 },
                input: {
                  endAdornment: (
                    <InputAdornment position="end">
                      <Typography variant="caption" sx={{ color: "text.disabled", mr: 0.5 }}>
                        sec
                      </Typography>
                      <Tooltip title={tooltip} arrow placement="top">
                        <HelpOutlineIcon
                          fontSize="small"
                          sx={{ color: "text.disabled", cursor: "help" }}
                        />
                      </Tooltip>
                    </InputAdornment>
                  ),
                },
              }}
            />
          ))}
          <Divider sx={{ my: 0.5 }} />
          <FormControlLabel
            sx={{ ml: 0, justifyContent: "space-between" }}
            labelPlacement="start"
            control={
              <Switch
                checked={form.update_check_enabled}
                onChange={(e) =>
                  setForm((prev) => ({
                    ...prev,
                    update_check_enabled: e.target.checked,
                  }))
                }
              />
            }
            label={
              <Stack direction="row" spacing={0.5} sx={{ alignItems: "center" }}>
                <Typography variant="body2">Check for updates</Typography>
                <Tooltip
                  title="Asks GitHub whether a newer CipherMoth release exists. No vault data is sent. You choose when to install; turn this off to stop checking."
                  arrow
                  placement="top"
                >
                  <HelpOutlineIcon
                    fontSize="small"
                    sx={{ color: "text.disabled", cursor: "help" }}
                  />
                </Tooltip>
              </Stack>
            }
          />
          {formError && (
            <Typography variant="body2" color="error">
              {formError}
            </Typography>
          )}
        </Stack>
      </DialogContent>
      <DialogActions>
        {tab === "general" ? (
          <>
            <Button onClick={onClose} disabled={saving}>
              Cancel
            </Button>
            <Button variant="contained" onClick={handleSave} loading={saving} disabled={!dirty}>
              Save
            </Button>
          </>
        ) : (
          <Button onClick={onClose}>Close</Button>
        )}
      </DialogActions>
    </Dialog>
  );
};

export default SettingsModal;
