import { Box, Typography } from "@mui/material";

const SHOWN = 200;

// The names a bulk action is about to touch, so a confirmation never hides what it
// confirms. Long lists scroll; past SHOWN names the rest are counted.
const NameList = ({ names, aside }) => {
  const extra = names.length - SHOWN;
  return (
    <Box
      component="ul"
      aria-label="Affected entries"
      sx={{
        listStyle: "none",
        m: 0,
        mt: 2,
        px: 1.5,
        py: 1,
        maxHeight: 176,
        overflowY: "auto",
        border: 1,
        borderColor: "divider",
        borderRadius: 1.5,
      }}
    >
      {names.slice(0, SHOWN).map((name, index) => (
        <Box
          component="li"
          key={`${index}:${name}`}
          sx={{ display: "flex", gap: 1, alignItems: "baseline", py: 0.25 }}
        >
          <Typography
            variant="body2"
            sx={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
          >
            {name}
          </Typography>
          {aside?.(index) && (
            <Typography
              variant="caption"
              sx={{ color: "text.secondary", whiteSpace: "nowrap", ml: "auto" }}
            >
              {aside(index)}
            </Typography>
          )}
        </Box>
      ))}
      {extra > 0 && (
        <Typography component="li" variant="caption" sx={{ color: "text.secondary", pt: 0.5 }}>
          and {extra} more
        </Typography>
      )}
    </Box>
  );
};

export default NameList;
