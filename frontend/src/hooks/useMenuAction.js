import { useEffect, useRef } from "react";

import { IS_DESKTOP } from "../platform";
import { onMenuAction } from "../platform/menu";

// Runs `handler` when the desktop menu bar sends `id`, for as long as the calling
// component is mounted. The handler may change on every render.
const useMenuAction = (id, handler) => {
  const latest = useRef(handler);
  useEffect(() => {
    latest.current = handler;
  });
  useEffect(() => {
    if (!IS_DESKTOP) return undefined;
    return onMenuAction(id, () => latest.current());
  }, [id]);
};

export default useMenuAction;
