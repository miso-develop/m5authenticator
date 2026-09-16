import "./style.css";
import {
  getLanguage,
  hasJapaneseTranslation,
  onLanguageChange,
  setLanguage,
  translateConfirmation,
  translateUiText,
  type UiLanguage,
} from "./i18n";

interface TextBinding {
  source: string;
  rendered: string;
  prefix: string;
  suffix: string;
}

interface AttributeBinding {
  source: string;
  rendered: string;
}

const textBindings = new WeakMap<Text, TextBinding>();
const attributeBindings = new WeakMap<Element, Map<string, AttributeBinding>>();
const translatableAttributes = ["aria-label", "title", "placeholder"] as const;

export type NavigationPage = "provisioner" | "flash" | "help";

export function navigationPageFromPath(pathname: string): NavigationPage {
  if (pathname.endsWith("/flash.html") || pathname.endsWith("flash.html")) return "flash";
  if (pathname.endsWith("/help.html") || pathname.endsWith("help.html")) return "help";
  return "provisioner";
}

export function navigationLabels(language: UiLanguage): Record<NavigationPage, string> {
  return {
    provisioner: translateUiText("Provisioner", language),
    flash: translateUiText("Firmware Flash", language),
    help: translateUiText("Help", language),
  };
}

function recognizedSource(source: string): boolean {
  return translateUiText(source, "en") !== source || hasJapaneseTranslation(source);
}

function splitOuterWhitespace(value: string): { prefix: string; source: string; suffix: string } {
  const leading = /^\s*/.exec(value)?.[0] ?? "";
  const trailing = /\s*$/.exec(value)?.[0] ?? "";
  return {
    prefix: leading,
    source: value.slice(leading.length, value.length - trailing.length),
    suffix: trailing,
  };
}

function localizeTextNode(node: Text): void {
  const existing = textBindings.get(node);
  let source: string;
  let prefix: string;
  let suffix: string;

  if (existing && node.data === existing.rendered) {
    ({ source, prefix, suffix } = existing);
  } else {
    const split = splitOuterWhitespace(node.data);
    source = split.source;
    prefix = split.prefix;
    suffix = split.suffix;
    if (source.length === 0 || !recognizedSource(source)) {
      textBindings.delete(node);
      return;
    }
  }

  const rendered = `${prefix}${translateUiText(source)}${suffix}`;
  textBindings.set(node, { source, rendered, prefix, suffix });
  if (node.data !== rendered) node.data = rendered;
}

function localizeAttribute(element: Element, attribute: string): void {
  const current = element.getAttribute(attribute);
  if (current === null) return;
  const map = attributeBindings.get(element) ?? new Map<string, AttributeBinding>();
  const existing = map.get(attribute);
  const source = existing && current === existing.rendered ? existing.source : current;
  if (!recognizedSource(source)) {
    map.delete(attribute);
    return;
  }
  const rendered = translateUiText(source);
  map.set(attribute, { source, rendered });
  attributeBindings.set(element, map);
  if (current !== rendered) element.setAttribute(attribute, rendered);
}

function localizeNode(node: Node): void {
  if (node instanceof Text) {
    localizeTextNode(node);
    return;
  }
  if (!(node instanceof Element)) return;
  for (const attribute of translatableAttributes) localizeAttribute(node, attribute);
  for (const child of node.childNodes) localizeNode(child);
}

export function sourceTextOf(element: Element): string {
  const values: string[] = [];
  const visit = (node: Node): void => {
    if (node instanceof Text) {
      const binding = textBindings.get(node);
      values.push(binding?.source ?? node.data);
      return;
    }
    for (const child of node.childNodes) visit(child);
  };
  visit(element);
  return translateUiText(values.join("").trim(), "en");
}

function renderNavigation(): void {
  const root = document.querySelector<HTMLElement>("#site-header");
  if (!root) return;
  const language = getLanguage();
  const active = navigationPageFromPath(window.location.pathname);
  const labels = navigationLabels(language);
  root.innerHTML = `
    <div class="site-nav-shell">
      <a class="product-mark" href="./">M5Authenticator</a>
      <nav class="site-tabs" aria-label="${translateUiText("M5Authenticator sections", language)}">
        <a href="./" ${active === "provisioner" ? 'aria-current="page"' : ""}>${labels.provisioner}</a>
        <a href="./flash.html" ${active === "flash" ? 'aria-current="page"' : ""}>${labels.flash}</a>
        <a href="./help.html" ${active === "help" ? 'aria-current="page"' : ""}>${labels.help}</a>
      </nav>
      <div class="language-switcher" role="group" aria-label="${translateUiText("Language", language)}">
        <button class="language-button" type="button" data-language="en" aria-pressed="${language === "en"}">EN</button>
        <button class="language-button" type="button" data-language="ja" aria-pressed="${language === "ja"}">日本語</button>
      </div>
    </div>
  `;
  root.querySelectorAll<HTMLButtonElement>("[data-language]").forEach((button) => {
    button.addEventListener("click", () => {
      const next = button.dataset.language;
      if (next === "en" || next === "ja") setLanguage(next);
    });
  });
}

function localizeExistingUi(): void {
  // Bind only known application UI strings. User-provided account names, SSIDs,
  // identifiers, protocol values, and other unknown text remain untouched.
  localizeNode(document.documentElement);
}

function installMutationLocalization(): MutationObserver {
  const observer = new MutationObserver((records) => {
    for (const record of records) {
      if (record.type === "characterData") {
        localizeTextNode(record.target as Text);
        continue;
      }
      for (const node of record.addedNodes) localizeNode(node);
    }
  });
  observer.observe(document.documentElement, { childList: true, characterData: true, subtree: true });
  return observer;
}

function installLocalizedConfirm(): void {
  const nativeConfirm = window.confirm.bind(window);
  window.confirm = (message?: string): boolean => nativeConfirm(translateConfirmation(String(message ?? "")));
}

function install(): void {
  renderNavigation();
  localizeExistingUi();
  const observer = installMutationLocalization();
  installLocalizedConfirm();
  onLanguageChange(() => {
    renderNavigation();
    localizeExistingUi();
  });
  window.addEventListener("pagehide", () => observer.disconnect(), { once: true });
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", install, { once: true });
  } else {
    install();
  }
}
