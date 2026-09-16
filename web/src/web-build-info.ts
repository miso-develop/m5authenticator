import {
  buildIdentityLabels,
  currentWebBuildIdentity,
  formatCompactBuildIdentity,
  formatFullBuildCommit,
} from "./build-identity";
import { getLanguage, onLanguageChange } from "./i18n";

function install(): void {
  const shell = document.querySelector<HTMLElement>("#app > .shell");
  if (!shell || shell.querySelector("#web-build-identity")) return;

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
    const labels = buildIdentityLabels("web", getLanguage());
    identityLabel.textContent = labels.identity;
    commitLabel.textContent = labels.commit;
    identityValue.textContent = formatCompactBuildIdentity(identity);
    commitValue.textContent = formatFullBuildCommit(identity);
  };
  render();
  onLanguageChange(render);

  const description = shell.querySelector(".description");
  if (description) description.insertAdjacentElement("afterend", block);
  else shell.prepend(block);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", install, { once: true });
} else {
  install();
}
