import { useEffect, useState } from "react";
import {
  Box,
  Button,
  Chip,
  Divider,
  IconButton,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Stack,
  Tooltip,
  Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import DeleteOutlinedIcon from "@mui/icons-material/DeleteOutlined";
import KeyOutlinedIcon from "@mui/icons-material/KeyOutlined";
import LockResetIcon from "@mui/icons-material/LockReset";
import PasswordIcon from "@mui/icons-material/Password";
import UsbIcon from "@mui/icons-material/Usb";
import { useStoreActions, useStoreState } from "easy-peasy";
import { useSnackbar } from "notistack";

import BiometricUnlockSection from "../BiometricUnlockSection";
import AddSecurityKeyDialog from "./AddSecurityKeyDialog";
import ChangeMasterPasswordDialog from "./ChangeMasterPasswordDialog";
import ConfirmIdentityDialog from "./ConfirmIdentityDialog";
import RecoveryCodeDialog from "./RecoveryCodeDialog";
import { formatAgo, formatDay } from "../../lib/dates";
import { WARN } from "../../lib/brand";

const Section = ({ icon, title, status, children }) => (
  <Box component="section" aria-label={title}>
    <Stack direction="row" spacing={1} sx={{ alignItems: "center", mb: 0.75 }}>
      <Box sx={{ color: "text.secondary", display: "flex" }}>{icon}</Box>
      <Typography variant="subtitle2" sx={{ fontWeight: 700, flex: 1 }}>
        {title}
      </Typography>
      {status}
    </Stack>
    <Stack spacing={1.25} sx={{ pl: 3.75 }}>
      {children}
    </Stack>
  </Box>
);

const Hint = ({ children, color = "text.secondary" }) => (
  <Typography variant="body2" sx={{ color, lineHeight: 1.5 }}>
    {children}
  </Typography>
);

const StatusChip = ({ on, onLabel, offLabel }) => (
  <Chip
    size="small"
    label={on ? onLabel : offLabel}
    color={on ? "secondary" : "default"}
    variant={on ? "filled" : "outlined"}
    sx={{ fontWeight: 600 }}
  />
);

const SecuritySettings = ({ open }) => {
  const { enqueueSnackbar } = useSnackbar();
  const { load, removeKey, createRecoveryCode, removeRecoveryCode } = useStoreActions(
    (a) => a.ciphermothModels.security
  );
  const { status, support } = useStoreState((s) => s.ciphermothModels.security);

  // One dialog at a time: "password", "add-key", "remove-key", "create-code",
  // "remove-code".
  const [dialog, setDialog] = useState(null);
  const [target, setTarget] = useState(null);
  const [code, setCode] = useState(null);

  useEffect(() => {
    if (open) load();
    else setDialog(null);
  }, [open, load]);

  const keys = status?.security_keys ?? [];
  const required = Boolean(status?.security_key_required);
  const hasCode = Boolean(status?.recovery_code);
  const close = () => setDialog(null);

  const handleKeyAdded = (first) => {
    close();
    enqueueSnackbar(
      first
        ? "Security key added. Unlocking now needs your master password and the key."
        : "Security key added.",
      { variant: "success" }
    );
  };

  const handleRemoveKey = async (masterPassword) => {
    await removeKey({ id: target.id, masterPassword });
    close();
    const last = keys.length === 1;
    enqueueSnackbar(
      last
        ? "Security key removed. Your master password alone unlocks the vault again."
        : `${target.name} removed.`,
      { variant: "success" }
    );
  };

  const handleCreateCode = async (masterPassword) => {
    const created = await createRecoveryCode(masterPassword);
    close();
    setCode(created);
  };

  const handleRemoveCode = async (masterPassword) => {
    await removeRecoveryCode(masterPassword);
    close();
    enqueueSnackbar("Recovery code removed. It no longer works.", { variant: "success" });
  };

  return (
    <Stack spacing={2.5} sx={{ mt: 1 }}>
      <Section icon={<PasswordIcon fontSize="small" />} title="Master password">
        <Hint>Change it whenever you like. Every entry is encrypted again with a new key.</Hint>
        <Box>
          <Button variant="outlined" size="small" onClick={() => setDialog("password")}>
            Change master password
          </Button>
        </Box>
      </Section>

      <Divider />

      <Section
        icon={<UsbIcon fontSize="small" />}
        title="Security keys"
        status={status && <StatusChip on={required} onLabel="Required" offLabel="Off" />}
      >
        <Hint>
          Require a FIDO2 security key, such as a YubiKey, as well as your master password. The key
          takes part in the encryption itself, so a copy of your vault is useless without it.
        </Hint>
        {keys.length > 0 && (
          <List dense disablePadding aria-label="Registered security keys">
            {keys.map((key) => (
              <ListItem
                key={key.id}
                disableGutters
                secondaryAction={
                  <Tooltip title={`Remove ${key.name}`}>
                    <IconButton
                      edge="end"
                      size="small"
                      aria-label={`Remove ${key.name}`}
                      onClick={() => {
                        setTarget(key);
                        setDialog("remove-key");
                      }}
                    >
                      <DeleteOutlinedIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                }
              >
                <ListItemIcon sx={{ minWidth: 32 }}>
                  <KeyOutlinedIcon fontSize="small" />
                </ListItemIcon>
                <ListItemText
                  primary={key.name}
                  secondary={[
                    `Added ${formatDay(key.created)}`,
                    key.last_used ? `used ${formatAgo(key.last_used)}` : "not used yet",
                    key.rp_id !== window.location.hostname ? `for ${key.rp_id}` : null,
                  ]
                    .filter(Boolean)
                    .join(" · ")}
                />
              </ListItem>
            ))}
          </List>
        )}
        {required && keys.length === 1 && !hasCode && (
          <Hint color={WARN}>
            One key and no recovery code: if you lose this key, the vault is gone. Add a backup key
            or create a recovery code.
          </Hint>
        )}
        {support && !support.available ? (
          <Hint>{support.reason}</Hint>
        ) : (
          <Box>
            <Button
              variant="outlined"
              size="small"
              startIcon={<AddIcon />}
              disabled={!status || !support}
              onClick={() => setDialog("add-key")}
            >
              {keys.length ? "Add another key" : "Add security key"}
            </Button>
          </Box>
        )}
      </Section>

      <Divider />

      <Section
        icon={<LockResetIcon fontSize="small" />}
        title="Recovery code"
        status={status && <StatusChip on={hasCode} onLabel="Set up" offLabel="None" />}
      >
        <Hint>
          A one-time code that sets a new master password if you forget yours, and gets you in if
          you lose your security keys. Without it, a forgotten master password cannot be recovered.
        </Hint>
        {hasCode && (
          <Typography variant="caption" sx={{ color: "text.secondary" }}>
            Created {formatDay(status.recovery_code_created)}. It is never shown again; replace it
            if you lost it.
          </Typography>
        )}
        <Stack direction="row" spacing={1}>
          <Button
            variant="outlined"
            size="small"
            disabled={!status}
            onClick={() => setDialog("create-code")}
          >
            {hasCode ? "Replace code" : "Create recovery code"}
          </Button>
          {hasCode && (
            <Button size="small" color="error" onClick={() => setDialog("remove-code")}>
              Remove
            </Button>
          )}
        </Stack>
      </Section>

      <Divider />

      <BiometricUnlockSection open={open} />

      <ChangeMasterPasswordDialog
        open={dialog === "password"}
        onClose={close}
        securityKeyRequired={required}
      />
      <AddSecurityKeyDialog
        open={dialog === "add-key"}
        onClose={close}
        onAdded={handleKeyAdded}
        status={status}
      />
      <ConfirmIdentityDialog
        open={dialog === "remove-key"}
        title={`Remove ${target?.name ?? "security key"}?`}
        description={
          keys.length === 1
            ? "This is your only key. Removing it turns the security key requirement off: your master password alone will unlock the vault."
            : "This key will no longer unlock the vault. Lost it? Also change your master password afterwards."
        }
        confirmLabel="Remove key"
        danger
        securityKeyRequired={required}
        onConfirm={handleRemoveKey}
        onClose={close}
      />
      <ConfirmIdentityDialog
        open={dialog === "create-code"}
        title={hasCode ? "Replace recovery code" : "Create a recovery code"}
        description={
          hasCode
            ? "Your current code stops working and a new one is shown once."
            : "The code is shown once. Write it down or print it and keep it somewhere safe."
        }
        confirmLabel={hasCode ? "Replace code" : "Create code"}
        securityKeyRequired={required}
        onConfirm={handleCreateCode}
        onClose={close}
      />
      <ConfirmIdentityDialog
        open={dialog === "remove-code"}
        title="Remove the recovery code?"
        description="Without it, a forgotten master password (or lost security keys) means losing the vault."
        confirmLabel="Remove code"
        danger
        securityKeyRequired={required}
        onConfirm={handleRemoveCode}
        onClose={close}
      />
      <RecoveryCodeDialog code={code} onDone={() => setCode(null)} />
    </Stack>
  );
};

export default SecuritySettings;
