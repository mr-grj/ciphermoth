// Clipboard clearing, shared by Chromium's offscreen document and Firefox's
// background page (both have a DOM).

import { sha256Hex } from "../shared/browser";

export interface ClearRequest {
  digest: string;
  onlyOurs: boolean;
}

const readClipboard = async (): Promise<string | null> => {
  try {
    if (navigator.clipboard?.readText) return await navigator.clipboard.readText();
  } catch {
    // Fall back to the paste command below.
  }
  const area = document.createElement("textarea");
  document.body.append(area);
  area.focus();
  try {
    return document.execCommand("paste") ? area.value : null;
  } finally {
    area.remove();
  }
};

const writeEmpty = async (): Promise<void> => {
  const onCopy = (event: ClipboardEvent) => {
    event.clipboardData?.setData("text/plain", "");
    event.preventDefault();
  };
  document.addEventListener("copy", onCopy);
  try {
    if (document.execCommand("copy")) return;
  } finally {
    document.removeEventListener("copy", onCopy);
  }
  await navigator.clipboard?.writeText("").catch(() => {});
};

export const clearClipboard = async ({ digest, onlyOurs }: ClearRequest): Promise<boolean> => {
  if (onlyOurs) {
    const current = await readClipboard();
    // Unreadable, or the user copied something else since: leave it alone.
    if (current === null || (await sha256Hex(current)) !== digest) return false;
  }
  await writeEmpty();
  return true;
};
