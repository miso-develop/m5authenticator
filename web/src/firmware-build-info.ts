import "./post-provisioning-layout.css";
import {
  buildIdentityLabels,
  formatCompactBuildIdentity,
  formatFullBuildCommit,
  type BuildIdentity,
} from "./build-identity";
import { getLanguage, onLanguageChange, translateUiText } from "./i18n";

export type FirmwareBuildInfoState =
  | { readonly status: "loading" }
  | { readonly status: "ready"; readonly identity: BuildIdentity }
  | { readonly status: "unavailable" };

export function installFirmwareBuildInfo(shell: HTMLElement): (state: FirmwareBuildInfoState) => void {
  const existing = shell.querySelector<HTMLElement>("#firmware-build-info-section");
  if (existing) existing.remove();

  const section = document.createElement("section");
  section.id = "firmware-build-info-section";
  section.className = "panel build-info-section";
  section.setAttribute("aria-labelledby", "firmware-build-info-heading");

  const heading = document.createElement("h2");
  heading.id = "firmware-build-info-heading";

  const block = document.createElement("dl");
  block.id = "firmware-build-identity";
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

  let current: FirmwareBuildInfoState = { status: "loading" };

  const render = () => {
    const language = getLanguage();
    const labels = buildIdentityLabels("firmware", language);
    heading.textContent = translateUiText("Build information", language);
    identityLabel.textContent = labels.identity;
    commitLabel.textContent = labels.commit;

    if (current.status === "loading") {
      identityValue.textContent = labels.loading;
      commitValue.textContent = "—";
      return;
    }
    if (current.status === "unavailable") {
      identityValue.textContent = labels.unavailable;
      commitValue.textContent = "—";
      return;
    }

    identityValue.textContent = formatCompactBuildIdentity(current.identity);
    commitValue.textContent = formatFullBuildCommit(current.identity);
  };

  section.append(heading, block);
  shell.append(section);

  render();
  onLanguageChange(render);

  return (state) => {
    current = state;
    render();
  };
}
