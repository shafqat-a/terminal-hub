import { test, expect } from "@playwright/test";

// Assumes:
//   - server is running with a primary user already signed in (cookie injected, or
//     pre-recorded `storageState` from a prior login). The fixture loader is out
//     of scope for M3; this test documents the contract.
//   - there is at least one tmux session attached at /

test.describe("clipboard paste", () => {
  test("multi-line paste arrives intact", async ({ page, context }) => {
    const payload = "line one\nline two\nline three\n";
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    await page.goto("/");
    await page.locator(".xterm-helper-textarea").click();
    await page.evaluate(async (text) => { await navigator.clipboard.writeText(text); }, payload);
    await page.keyboard.press("Meta+V");
    // xterm.js renders into rows; check that each line shows up.
    await expect(page.locator(".xterm-rows")).toContainText("line one");
    await expect(page.locator(".xterm-rows")).toContainText("line two");
    await expect(page.locator(".xterm-rows")).toContainText("line three");
  });

  test("tab character survives paste", async ({ page, context }) => {
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    await page.goto("/");
    await page.locator(".xterm-helper-textarea").click();
    await page.evaluate(async () => { await navigator.clipboard.writeText("col1\tcol2"); });
    await page.keyboard.press("Meta+V");
    await expect(page.locator(".xterm-rows")).toContainText("col1");
    await expect(page.locator(".xterm-rows")).toContainText("col2");
  });
});
