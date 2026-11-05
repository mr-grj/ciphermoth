import { ext } from "../shared/browser";
import type { Message, Reply } from "../shared/messages";

export class BackgroundError extends Error {
  constructor(
    message: string,
    readonly code: string | null
  ) {
    super(message);
  }
}

// One request to the background; its answer, or a BackgroundError.
export const send = async <T,>(message: Message): Promise<T> => {
  const reply = (await ext.runtime.sendMessage(message)) as Reply<T> | undefined;
  if (!reply) throw new BackgroundError("CipherMoth did not answer.", null);
  if (!reply.ok) throw new BackgroundError(reply.error, reply.code ?? null);
  return reply.value;
};

export const MothIcon = ({ size = 22 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 100 100" fill="currentColor" aria-hidden="true">
    <path d="M50 24 C46 24 44 29 44 37 C44 53 47 69 50 82 C53 69 56 53 56 37 C56 29 54 24 50 24 Z" />
    <circle cx="50" cy="21" r="5" />
    <path d="M50 30 C66 21 80 19 88 23 C91 31 88 44 81 49 C69 53 58 51 50 50 Z" />
    <path d="M50 53 C63 53 75 59 78 68 C80 77 73 83 65 82 C57 80 52 72 50 70 Z" />
    <path d="M50 30 C34 21 20 19 12 23 C9 31 12 44 19 49 C31 53 42 51 50 50 Z" />
    <path d="M50 53 C37 53 25 59 22 68 C20 77 27 83 35 82 C43 80 48 72 50 70 Z" />
    <g fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
      <path d="M52 18 C58 11 65 9 70 10" />
      <path d="M48 18 C42 11 35 9 30 10" />
    </g>
    <circle cx="70" cy="10" r="2.4" />
    <circle cx="30" cy="10" r="2.4" />
  </svg>
);

const ICONS = {
  lock: "M7 10V7a5 5 0 0 1 10 0v3h1a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1v-9a1 1 0 0 1 1-1h1Zm2 0h6V7a3 3 0 0 0-6 0v3Z",
  gear: "M12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7Zm8.6 4.6-1.9-.4a6.9 6.9 0 0 1-.6 1.5l1.1 1.6-1.6 1.6-1.6-1.1c-.5.3-1 .5-1.5.6l-.4 1.9h-2.2l-.4-1.9a6.9 6.9 0 0 1-1.5-.6l-1.6 1.1-1.6-1.6 1.1-1.6c-.3-.5-.5-1-.6-1.5l-1.9-.4v-2.2l1.9-.4c.1-.5.3-1 .6-1.5L5.3 6.6l1.6-1.6 1.6 1.1c.5-.3 1-.5 1.5-.6l.4-1.9h2.2l.4 1.9c.5.1 1 .3 1.5.6l1.6-1.1 1.6 1.6-1.1 1.6c.3.5.5 1 .6 1.5l1.9.4v2.2Z",
  user: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm0 2c-4 0-7 2-7 4.5V20h14v-1.5C19 16 16 14 12 14Z",
  key: "M14.5 3a6.5 6.5 0 0 0-6.2 8.4L3 16.7V21h4.3v-2h2v-2h2l1.3-1.3A6.5 6.5 0 1 0 14.5 3Zm1.5 6a2 2 0 1 1 0-4 2 2 0 0 1 0 4Z",
  timer: "M10 2h4v2h-4V2Zm2 4a8 8 0 1 1 0 16 8 8 0 0 1 0-16Zm-1 4v5l4 2 .8-1.6-2.8-1.4V10h-2Z",
  search:
    "M10.5 3a7.5 7.5 0 0 1 6 12l4.3 4.3-1.4 1.4-4.3-4.3A7.5 7.5 0 1 1 10.5 3Zm0 2a5.5 5.5 0 1 0 0 11 5.5 5.5 0 0 0 0-11Z",
  star: "m12 3 2.6 5.6 6.1.7-4.5 4.2 1.2 6L12 16.6 6.6 19.5l1.2-6L3.3 9.3l6.1-.7L12 3Z",
  shield:
    "M12 2 4 5v6c0 5 3.4 9.6 8 11 4.6-1.4 8-6 8-11V5l-8-3Zm-1 13-3.5-3.5 1.4-1.4 2.1 2.1 4.6-4.6 1.4 1.4L11 15Z",
} as const;

export const Icon = ({ name, size = 18 }: { name: keyof typeof ICONS; size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
    <path d={ICONS[name]} />
  </svg>
);
