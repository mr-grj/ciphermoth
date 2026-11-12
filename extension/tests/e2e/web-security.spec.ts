import { expect, test } from "@playwright/test";

import { type Browser, MASTER_PASSWORD, launch, startStack } from "./harness";

test("the web vault registers a PRF key and refuses forged or rolled-back assertions", async () => {
  const stack = await startStack();
  let browser: Browser | undefined;
  try {
    browser = await launch(stack);
    const page = await browser.context.newPage();
    const cdp = await browser.context.newCDPSession(page);
    await cdp.send("WebAuthn.enable", { enableUI: false });
    const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        ctap2Version: "ctap2_1",
        transport: "usb",
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
        hasPrf: true,
      },
    });
    await page.goto("https://vault.test/");
    await page.getByLabel(/^Master Password/).fill(MASTER_PASSWORD);
    await page.getByLabel(/^Confirm Master Password/).fill(MASTER_PASSWORD);
    await page.getByRole("checkbox").check();
    await page.getByRole("button", { name: "Create Vault", exact: true }).click();
    await page.getByRole("button", { name: "Settings", exact: true }).click();
    await page.getByRole("tab", { name: "Security", exact: true }).click();
    await page.getByRole("button", { name: "Add security key", exact: true }).click();
    const add = page.getByRole("dialog", { name: "Require a security key", exact: true });
    await add.getByLabel("Key name", { exact: true }).fill("Virtual QA key");
    await add.getByLabel(/^Master Password/).fill(MASTER_PASSWORD);
    await add.getByRole("checkbox").check();
    await add.getByRole("button", { name: "Add key and turn on", exact: true }).click();
    await expect(add).toBeHidden();
    await expect(page.getByRole("list", { name: "Registered security keys" })).toContainText(
      "Virtual QA key"
    );
    await page
      .getByRole("dialog", { name: "Settings", exact: true })
      .getByRole("button", { name: "Close", exact: true })
      .click();

    const unlock = async () => {
      await page.getByLabel(/^Master Password/).fill(MASTER_PASSWORD);
      const pending = page.waitForResponse(
        (response) =>
          response.url().endsWith("/api/master_password/unlock") &&
          response.request().method() === "POST"
      );
      await page.getByRole("button", { name: "Unlock Vault", exact: true }).click();
      return pending;
    };
    await page.getByRole("button", { name: "Log out", exact: true }).click();
    expect((await unlock()).status()).toBe(200);
    await expect(page.getByRole("button", { name: "Settings", exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Log out", exact: true }).click();

    await cdp.send("WebAuthn.setResponseOverrideBits", { authenticatorId, isBogusSignature: true });
    expect((await unlock()).status()).toBe(403);
    await expect(page.getByRole("button", { name: "Unlock Vault", exact: true })).toBeVisible();
    expect(await page.evaluate(() => sessionStorage.getItem("ciphermothSession"))).toBeNull();
    await cdp.send("WebAuthn.setResponseOverrideBits", { authenticatorId });
    expect((await unlock()).status()).toBe(200);
    await expect(page.getByRole("button", { name: "Settings", exact: true })).toBeVisible();

    const challenge = await browser.context.request.post(
      `${stack.backend}/master_password/unlock/challenge`
    );
    expect(challenge.status()).toBe(200);
    // The server supplies the public credential id; no authenticator private
    // key is exported to inspect or manipulate its counter.
    const { keys } = await challenge.json();
    const credentialId = Buffer.from(keys[0].credential_id, "base64url").toString("base64");
    await page.getByRole("button", { name: "Log out", exact: true }).click();
    await cdp.send("WebAuthn.setCredentialProperties", {
      authenticatorId,
      credentialId,
      signCount: 0,
    });
    expect((await unlock()).status()).toBe(403);
    await expect(page.getByRole("alert")).toContainText("counter went backwards");
    expect(await page.evaluate(() => sessionStorage.getItem("ciphermothSession"))).toBeNull();

    await cdp.send("WebAuthn.setCredentialProperties", {
      authenticatorId,
      credentialId,
      signCount: 1000,
    });
    expect((await unlock()).status()).toBe(200);
    await expect(page.getByRole("button", { name: "Settings", exact: true })).toBeVisible();
  } finally {
    try {
      await browser?.close();
    } finally {
      await stack.stop();
    }
  }
});
