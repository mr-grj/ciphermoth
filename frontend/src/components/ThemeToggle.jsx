import { useEffect, useRef, useState } from "react";
import { IconButton, Tooltip } from "@mui/material";

import { useColorMode } from "../hooks/useColorMode";
import MothIcon from "./MothIcon";
import { GLOW } from "../lib/brand";

const FLIGHT_MS = 1050;

const ThemeToggle = ({ zIndex = 1200 }) => {
  const { mode, toggle } = useColorMode();
  const [flying, setFlying] = useState(false);
  const timer = useRef();
  const dark = mode === "dark";

  useEffect(() => () => clearTimeout(timer.current), []);

  const handleClick = () => {
    setFlying(true);
    toggle();
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setFlying(false), FLIGHT_MS);
  };

  return (
    <Tooltip
      placement="left"
      title={dark ? "Coax the moth into the light" : "Send the moth back into the dark"}
    >
      <IconButton
        aria-label={dark ? "Switch to light theme" : "Switch to dark theme"}
        onClick={handleClick}
        className={flying ? "cmFlying" : undefined}
        sx={{
          position: "fixed",
          // Sits inside the vault grid's footer row, next to the page arrows.
          bottom: { xs: 20, sm: 24 },
          right: { xs: 20, sm: 24 },
          zIndex,
          width: { xs: 44, sm: 52 },
          height: { xs: 44, sm: 52 },
          // A landscape phone has no free corner: it would float over the rows.
          "@media (max-height: 480px)": { display: "none" },
          color: GLOW,
          bgcolor: dark ? "rgba(20,20,22,0.72)" : "rgba(255,255,255,0.82)",
          border: "1px solid",
          borderColor: dark ? "rgba(125,211,192,0.28)" : "rgba(11,11,12,0.1)",
          backdropFilter: "blur(6px)",
          boxShadow: "0 4px 18px rgba(0,0,0,0.18)",
          overflow: "visible",
          transition:
            "transform 200ms ease, box-shadow 320ms ease, background-color 320ms ease, border-color 320ms ease",
          "&:hover": {
            transform: "translateY(-2px)",
            boxShadow: `0 8px 22px rgba(0,0,0,0.22), 0 0 22px color-mix(in srgb, ${GLOW} 42%, transparent)`,
          },
          "&:hover .cmMoth": { animationDuration: "0.9s" },
          "& .cmMoth": {
            width: 26,
            height: 26,
            display: "flex",
            transformOrigin: "50% 45%",
            filter: `drop-shadow(0 0 6px color-mix(in srgb, ${GLOW} 55%, transparent))`,
            animation: "cmMothIdle 3.2s ease-in-out infinite",
          },
          "&.cmFlying": { zIndex: zIndex + 1 },
          "&.cmFlying .cmMoth": {
            animation: `cmMothFly ${FLIGHT_MS}ms cubic-bezier(0.34, 0.6, 0.4, 1) both`,
            filter: `drop-shadow(0 0 14px color-mix(in srgb, ${GLOW} 80%, transparent))`,
          },
          "&.cmFlying .cmMoth svg": {
            animation: "cmWingFlutter 90ms ease-in-out 10",
            transformOrigin: "50% 42%",
          },
          "&.cmFlying::after": {
            content: '""',
            position: "absolute",
            inset: 0,
            borderRadius: "50%",
            animation: "cmMothBurst 700ms ease-out",
          },
          "@keyframes cmMothIdle": {
            "0%, 100%": { transform: "scaleX(1) translateY(0)" },
            "50%": { transform: "scaleX(0.88) translateY(-1px)" },
          },
          "@keyframes cmMothFly": {
            "0%": { transform: "translate(0, 0) rotate(0deg) scale(1)" },
            "14%": { transform: "translate(-9px, -18px) rotate(-20deg) scale(1.14)" },
            "32%": { transform: "translate(14px, -40px) rotate(18deg) scale(1.18)" },
            "50%": { transform: "translate(-12px, -56px) rotate(-14deg) scale(1.12)" },
            "66%": { transform: "translate(10px, -42px) rotate(12deg) scale(1.1)" },
            "82%": { transform: "translate(-5px, -20px) rotate(-7deg) scale(1.05)" },
            "100%": { transform: "translate(0, 0) rotate(0deg) scale(1)" },
          },
          "@keyframes cmWingFlutter": {
            "0%, 100%": { transform: "scaleX(1)" },
            "50%": { transform: "scaleX(0.62)" },
          },
          "@keyframes cmMothBurst": {
            "0%": { boxShadow: `0 0 0 0 color-mix(in srgb, ${GLOW} 55%, transparent)` },
            "100%": { boxShadow: "0 0 0 26px transparent" },
          },
        }}
      >
        <span className="cmMoth">
          <MothIcon width="100%" height="100%" style={{ display: "block", overflow: "visible" }} />
        </span>
      </IconButton>
    </Tooltip>
  );
};

export default ThemeToggle;
