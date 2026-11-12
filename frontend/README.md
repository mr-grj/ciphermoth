# CipherMoth frontend

React 19 + [Vite](https://vite.dev/) + MUI v9. State via easy-peasy, toasts via notistack.

## Scripts

| Command | What |
|---|---|
| `npm run dev` | Start the Vite dev server on `http://localhost:3000` (HMR) |
| `npm run build` | Production build to `dist/` |
| `npm run preview` | Preview the production build locally |
| `npm run format` / `npm run format:check` | Prettier write / check |

## Configuration

| Variable | Default | Description |
|---|---|---|
| `VITE_API_URL` | `http://localhost:8000/api` | Backend API base URL (embedded at build time) |

For running the whole stack (backend with SQLite + frontend) with Docker, see the [root README](../README.md).
