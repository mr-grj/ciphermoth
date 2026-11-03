// The recovery code as people type it. The server is the authority; this only
// helps them see a typo before sending. Crockford base32, read like the server:
// case, spaces and dashes do not matter, and O, I and L count as 0, 1 and 1.

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const LENGTH = 32;
const LOOKALIKES = { O: "0", I: "1", L: "1" };

export const canonicalRecoveryCode = (text) =>
  text
    .toUpperCase()
    .replace(/[\s-]/g, "")
    .replace(/[OIL]/g, (c) => LOOKALIKES[c]);

export const isRecoveryCode = (text) => {
  const code = canonicalRecoveryCode(text);
  return code.length === LENGTH && [...code].every((c) => ALPHABET.includes(c));
};

// Groups of four for display and as the user types.
export const groupRecoveryCode = (text) =>
  canonicalRecoveryCode(text)
    .slice(0, LENGTH)
    .replace(/(.{4})(?=.)/g, "$1-");
