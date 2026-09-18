import "./post-provisioning-layout.css";
import {
  buildIdentityLabels,
  currentWebBuildIdentity,
  formatCompactBuildIdentity,
  formatFullBuildCommit,
} from "./build-identity";
import { getLanguage, onLanguageChange, translateUiText } from "./i18n";

export function installWebBuildInfo(
  shell: HTMLElement | null = document.querySelector<HTMLElement>("#app > .shell"),
): void {
  if (!shell || shell.querySelector("#web-build-info-section")) return;

  const section = document.createElement("section");
  section.id = "web-build-info-section";
  section.className = "panel build-info-section";
  section.setAttribute("aria-labelledby", "web-build-info-heading");

  const heading = document.createElement("h2");
  heading.id = "web-build-info-heading";

  const block = document.createElement("dl");
  block.id = "web-build-identity";
  block.className = "build-identity";
  const identityRow = document.createElement("div");
  const identityLabel = document.createElement("dt");
  const identityValue = document.createElement("dd");
  identityValue.dataset.i18nLiteral = "true";
  const commitRow = document.createElement("div");
  const commitLabel = document.createElement("dt");
  const commitValue = document.createElement("dd");
  commitValue.dataset.i18nLiteral = "true";
  identityRow.append(identityLabel, identityValue);
  commitRow.append(commitLabel, commitValue);
  block.append(identityRow, commitRow);

  const identity = currentWebBuildIdentity();
  const render = () => {
    const language = getLanguage();
    const labels = buildIdentityLabels("web", language);
    heading.textContent = translateUiText("Build information", language);
    identityLabel.textContent = labels.identity;
    commitLabel.textContent = labels.commit;
    identityValue.textContent = formatCompactBuildIdentity(identity);
    commitValue.textContent = formatFullBuildCommit(identity);
  };
  render();
  onLanguageChange(render);

  section.append(heading, block);
  shell.append(section);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => installWebBuildInfo(), { once: true });
} else {
  installWebBuildInfo();
}
