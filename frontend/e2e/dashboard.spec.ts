import { test, expect } from "@playwright/test";

test("real fixture scan, evidence, coverage and history", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("Access token").fill("e2e-local-only-token");
  await page.getByRole("button", { name: "Open workspace" }).click();
  await page
    .getByRole("button", { name: "Connect vulnerable fixture" })
    .click();
  await expect(page.getByRole("button", { name: "Run scan" })).toBeEnabled();
  await page.getByRole("button", { name: "Run scan" }).click();
  await expect(
    page.getByText("succeeded", { exact: true }).first(),
  ).toBeVisible({ timeout: 30_000 });
  const pythonCoverage = page
    .locator(".coverage-row")
    .filter({ hasText: "RG-PY-SHELL" });
  const pythonScanned = (await pythonCoverage.innerText()).includes("scanned");
  await expect(page.locator(".score-ring strong")).toHaveText(
    pythonScanned ? "41" : "37",
  );
  await expect(page.locator("details.finding")).toHaveCount(
    pythonScanned ? 7 : 6,
  );
  await page.locator("details.finding summary").first().click();
  await expect(page.locator(".finding-detail:visible pre")).not.toBeEmpty();
  if (pythonScanned)
    await expect(pythonCoverage).toContainText("supported input");
  else await expect(pythonCoverage).toContainText(/engine (unavailable|error)/);
  await expect(page.locator(".history-row")).toHaveCount(1);
  const timeoutFinding = page
    .locator("details.finding")
    .filter({ hasText: "RG-CI-TIMEOUT" });
  await timeoutFinding.locator("summary").first().click();
  await timeoutFinding.getByRole("button", { name: "Propose fix" }).click();
  await expect(timeoutFinding.locator(".proposal-card pre")).toContainText(
    "timeout-minutes: 15",
  );
  await expect(timeoutFinding.locator(".proposal-heading")).toContainText(
    "pending",
  );
  await timeoutFinding
    .getByRole("button", { name: "Validate in isolation" })
    .click();
  await expect(
    timeoutFinding.getByRole("alert", { name: "Proposal error" }),
  ).toHaveText("isolation_unavailable");
  await expect(
    timeoutFinding.getByRole("button", { name: "Approve this exact patch" }),
  ).toHaveCount(0);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({
    path: "../.runtime/dashboard-desktop.png",
    fullPage: true,
  });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBeTruthy();
  await page.screenshot({
    path: "../.runtime/dashboard-mobile.png",
    fullPage: true,
  });
  expect(
    await page.evaluate(() => ({
      local: localStorage.length,
      session: sessionStorage.length,
    })),
  ).toEqual({ local: 0, session: 0 });
  await page.getByRole("button", { name: "Disconnect" }).click();
  await expect(page.getByLabel("Access token")).toBeVisible();
});

test("permission error and mobile layout", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBeTruthy();
  await page.getByLabel("Access token").fill("invalid-token");
  await page.getByRole("button", { name: "Open workspace" }).click();
  await expect(page.getByRole("alert", { name: "Workspace error" })).toHaveText(
    "invalid credential",
  );
});
