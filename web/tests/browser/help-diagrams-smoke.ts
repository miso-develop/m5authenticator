const DESKTOP_WIDTH_PX = 1280;
const MOBILE_WIDTH_PX = 390;
const FRAME_HEIGHT_PX = 5000;
const GEOMETRY_EPSILON_PX = 1;

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

async function waitUntil(predicate: () => boolean, message: string, timeoutMs = 4000): Promise<void> {
  const deadline = performance.now() + timeoutMs;
  while (!predicate()) {
    if (performance.now() >= deadline) throw new Error(message);
    await new Promise<void>((resolve) => window.setTimeout(resolve, 10));
  }
}

function required<T extends Element>(root: ParentNode, selector: string): T {
  const value = root.querySelector<T>(selector);
  if (!value) throw new Error(`Missing Help diagram smoke element: ${selector}`);
  return value;
}

function frameDocument(frame: HTMLIFrameElement): Document {
  const doc = frame.contentDocument;
  if (!doc) throw new Error("Help diagram iframe document is unavailable");
  return doc;
}

function frameWindow(frame: HTMLIFrameElement): Window {
  const value = frame.contentWindow;
  if (!value) throw new Error("Help diagram iframe window is unavailable");
  return value;
}

function flushLayout(doc: Document): void {
  void doc.documentElement.offsetWidth;
}

async function loadHelpFrame(widthPx: number): Promise<HTMLIFrameElement> {
  const frame = document.createElement("iframe");
  frame.width = String(widthPx);
  frame.height = String(FRAME_HEIGHT_PX);
  frame.style.position = "fixed";
  frame.style.left = "-20000px";
  frame.style.top = "0";
  frame.style.border = "0";
  frame.src = new URL("help.html", new URL(import.meta.env.BASE_URL, window.location.origin)).toString();

  const loaded = new Promise<void>((resolve, reject) => {
    frame.addEventListener("load", () => resolve(), { once: true });
    frame.addEventListener("error", () => reject(new Error("Failed to load production Help route")), { once: true });
  });
  document.body.append(frame);
  await loaded;
  await waitUntil(
    () => frame.contentDocument?.querySelectorAll("figure.help-diagram").length === 3,
    "Production Help route did not render all required explanatory figures",
  );
  return frame;
}

function assertAccessibleFigures(doc: Document): void {
  const figures = Array.from(doc.querySelectorAll<HTMLElement>("figure.help-diagram"));
  assert(figures.length === 3, "Help page must render exactly three required explanatory figures");

  for (const [index, figure] of figures.entries()) {
    const labelledBy = figure.getAttribute("aria-labelledby");
    const describedBy = figure.getAttribute("aria-describedby");
    assert(labelledBy !== null && labelledBy.length > 0, `Help figure ${index + 1} must have aria-labelledby`);
    assert(describedBy !== null && describedBy.length > 0, `Help figure ${index + 1} must have aria-describedby`);
    assert(doc.getElementById(labelledBy)?.tagName === "FIGCAPTION", `Help figure ${index + 1} aria-labelledby must target its figcaption`);
    assert(doc.getElementById(describedBy)?.textContent?.trim().length !== 0, `Help figure ${index + 1} must expose an accessible description`);
    assert(figure.querySelector("button, a, input, select, textarea") === null, `Help figure ${index + 1} must not introduce focusable decorative controls`);
  }
}

function assertEnglishBoundaries(doc: Document): void {
  const setup = required<HTMLElement>(doc, "#help-setup-flow");
  const trust = required<HTMLElement>(doc, "#help-trust-storage");
  const reset = required<HTMLElement>(doc, "#help-reset-paths");

  assert(setup.textContent?.includes("Device · physical confirmation") === true, "Setup diagram must label physical Device confirmations");
  assert(setup.textContent?.includes("fresh UNLOCK REQUEST") === true, "Daily Unlock diagram must retain fresh physical confirmation");
  assert(trust.textContent?.includes("does not export TOTP secrets") === true, "Trust diagram must state the no-secret-export boundary");
  assert(trust.textContent?.includes("not erased by Device Factory Reset") === true, "Trust diagram must keep Recovery Package outside Device Factory Reset");
  assert(reset.textContent?.includes("Normal firmware Update") === true, "Reset diagram must include the normal Update path");
  assert(reset.textContent?.includes("First install / erase") === true, "Reset diagram must distinguish First install / erase");
  assert(reset.textContent?.includes("Recovery Factory Reset") === true, "Reset diagram must include Recovery Factory Reset");
  assert(reset.textContent?.includes("not a routine substitute") === true, "Recovery Factory Reset must be explicitly exceptional");
}

function assertNoHorizontalOverflow(frame: HTMLIFrameElement): void {
  const doc = frameDocument(frame);
  const win = frameWindow(frame);
  flushLayout(doc);

  assert(
    doc.documentElement.scrollWidth <= win.innerWidth + GEOMETRY_EPSILON_PX,
    `Help route overflowed horizontally at ${win.innerWidth}px viewport width`,
  );

  const shell = required<HTMLElement>(doc, "#help-app > .help-shell").getBoundingClientRect();
  for (const [index, figure] of Array.from(doc.querySelectorAll<HTMLElement>("figure.help-diagram")).entries()) {
    const rect = figure.getBoundingClientRect();
    assert(rect.left >= shell.left - GEOMETRY_EPSILON_PX, `Help figure ${index + 1} escaped the shell on the left`);
    assert(rect.right <= shell.right + GEOMETRY_EPSILON_PX, `Help figure ${index + 1} escaped the shell on the right`);
  }

  const sampleLabel = required<HTMLElement>(doc, ".help-flow-copy");
  assert(parseFloat(getComputedStyle(sampleLabel).fontSize) >= 12, "Help diagram labels must remain legible at the tested viewport");
}

export async function runHelpDiagramsSmoke(): Promise<void> {
  const desktop = await loadHelpFrame(DESKTOP_WIDTH_PX);
  const mobile = await loadHelpFrame(MOBILE_WIDTH_PX);
  try {
    const desktopDoc = frameDocument(desktop);
    const englishButton = required<HTMLButtonElement>(desktopDoc, '[data-language="en"]');
    englishButton.click();
    await waitUntil(
      () => desktopDoc.documentElement.lang === "en" &&
        required<HTMLElement>(desktopDoc, "#help-setup-flow-caption").textContent === "Normal setup and daily use",
      "Help diagrams did not render English without reload",
    );

    assertAccessibleFigures(desktopDoc);
    assertEnglishBoundaries(desktopDoc);
    assertNoHorizontalOverflow(desktop);

    const japaneseButton = required<HTMLButtonElement>(desktopDoc, '[data-language="ja"]');
    japaneseButton.click();
    await waitUntil(
      () => desktopDoc.documentElement.lang === "ja" &&
        required<HTMLElement>(desktopDoc, "#help-setup-flow-caption").textContent === "通常セットアップと日常利用の流れ" &&
        required<HTMLElement>(desktopDoc, "#help-trust-storage-caption").textContent === "Trusted stateとRecovery materialの保存場所" &&
        required<HTMLElement>(desktopDoc, "#help-reset-paths-caption").textContent === "Update・erase・resetは別の操作です",
      "Help diagram labels did not update to Japanese without reload",
    );
    assertAccessibleFigures(desktopDoc);
    assert(
      required<HTMLElement>(desktopDoc, "#help-reset-paths").textContent?.includes("通常のFactory Resetの代替ではありません") === true,
      "Japanese Help copy must keep Recovery Factory Reset exceptional",
    );

    // Restore the shared origin preference so later production-route smoke remains deterministic.
    required<HTMLButtonElement>(desktopDoc, '[data-language="en"]').click();
    await waitUntil(() => desktopDoc.documentElement.lang === "en", "Help smoke could not restore English preference");

    assertNoHorizontalOverflow(mobile);
    document.body.dataset.helpDiagramsStatus = "pass";
  } finally {
    desktop.remove();
    mobile.remove();
  }
}
