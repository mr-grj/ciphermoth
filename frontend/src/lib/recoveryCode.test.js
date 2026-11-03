import { describe, expect, it } from "vitest";

import { canonicalRecoveryCode, groupRecoveryCode, isRecoveryCode } from "./recoveryCode";

const CODE = "09CP-HWPN-NZF7-2E4D-XBQW-YWRG-MGJ3-XWXA";

describe("recovery codes", () => {
  it("accepts the code however it was typed", () => {
    expect(isRecoveryCode(CODE)).toBe(true);
    expect(isRecoveryCode(CODE.toLowerCase())).toBe(true);
    expect(isRecoveryCode(CODE.replace(/-/g, " "))).toBe(true);
    expect(isRecoveryCode(` ${CODE.replace(/-/g, "")}\n`)).toBe(true);
  });

  it("reads look-alike letters like the server", () => {
    expect(canonicalRecoveryCode("oIl")).toBe("011");
    expect(isRecoveryCode(CODE.replace("0", "O"))).toBe(true);
  });

  it("refuses codes of the wrong length or with letters it never uses", () => {
    expect(isRecoveryCode(CODE.slice(0, -1))).toBe(false);
    expect(isRecoveryCode(`${CODE}A`)).toBe(false);
    expect(isRecoveryCode(CODE.replace("X", "U"))).toBe(false);
  });

  it("groups by four as the user types", () => {
    expect(groupRecoveryCode("09cphwpn")).toBe("09CP-HWPN");
    expect(groupRecoveryCode("09CP-HWP")).toBe("09CP-HWP");
    expect(groupRecoveryCode(`${CODE}XYZ`)).toBe(CODE);
  });
});
