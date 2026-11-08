// An error the extension did not expect (not an ApiError) reaches the user as
// "Something went wrong."; this leaves a trace in the background console so it
// can be diagnosed. Like the backend's unhandled-error log: the type and the
// code locations only, never the message (a JSON SyntaxError quotes the body
// it failed on, which may hold a secret).
export const reportUnexpected = (error: unknown): void => {
  const name = error instanceof Error ? error.name : typeof error;
  const frames =
    error instanceof Error && typeof error.stack === "string"
      ? error.stack
          .split("\n")
          // Chromium frames ("    at f (url:1:2)"), Firefox frames ("f@url:1:2");
          // Chromium's first line is "Name: message" and matches neither.
          .filter((line) => /^\s+at\s\S/.test(line) || /^\S*@\S+:\d+:\d+$/.test(line))
          .slice(0, 5)
          .map((line) => line.trim())
      : [];
  console.error(`CipherMoth: unexpected ${name}`, frames);
};
