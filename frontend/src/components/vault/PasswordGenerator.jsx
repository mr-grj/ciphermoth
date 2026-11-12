import { Box, Chip, IconButton, Paper, Slider, Stack, Tooltip, Typography } from "@mui/material";
import RefreshIcon from "@mui/icons-material/Refresh";

const CHAR_OPTS = [
  { key: "uppercase", label: "A–Z" },
  { key: "lowercase", label: "a–z" },
  { key: "numbers", label: "0–9" },
  { key: "symbols", label: "!@#" },
];

const CHAR_KEYS = CHAR_OPTS.map((o) => o.key);

const PasswordGenerator = ({ options, onChangeLength, onToggleClass, onRegenerate }) => (
  <Paper variant="outlined" sx={{ px: 2, py: 1.5, borderRadius: 1.5 }}>
    <Stack spacing={1.5}>
      <Box>
        <Stack
          direction="row"
          sx={{ justifyContent: "space-between", alignItems: "center", mb: 0.5 }}
        >
          <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 500 }}>
            Length
          </Typography>
          <Typography variant="caption" sx={{ fontWeight: 700 }}>
            {options.length}
          </Typography>
        </Stack>
        <Slider
          aria-label="Length"
          size="small"
          value={options.length}
          min={8}
          max={64}
          step={1}
          onChange={(_, value) => onChangeLength(value)}
        />
      </Box>
      <Stack direction="row" spacing={0.75} sx={{ alignItems: "center", flexWrap: "wrap" }}>
        {CHAR_OPTS.map(({ key, label }) => (
          <Chip
            key={key}
            label={label}
            size="small"
            onClick={() => onToggleClass(key)}
            aria-pressed={options[key]}
            color={options[key] ? "primary" : "default"}
            variant={options[key] ? "filled" : "outlined"}
            sx={{ fontFamily: "'Space Mono', monospace", fontWeight: 600 }}
          />
        ))}
        <Box sx={{ flex: 1 }} />
        <Tooltip title="Regenerate">
          <IconButton size="small" onClick={onRegenerate}>
            <RefreshIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Stack>
    </Stack>
  </Paper>
);

export { CHAR_KEYS };
export default PasswordGenerator;
