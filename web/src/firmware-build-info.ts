import {
  buildIdentityLabels,
  formatCompactBuildIdentity,
  formatFullBuildCommit,
  type BuildIdentity,
} from "./build-identity";
import { loadFirmwareArtifactIdentity } from "./firmware-update";
import { getLanguage, onLanguageChange } from "./i18n";

const flashEnabled = import.meta.env.VITE_M5AUTH_FLASH_ENABLED === "true";
const manifestPath = `${import.meta.env.BASE_URL}firmware/update-manifest.json`;

function install(): void {
  const shell = document.querySelector<HTMLElement>("#flash-app > .shell");
  if (!shell || shell.querySelector("#firmware-build-identity")) return;

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

  let identity: BuildIdentity | undefined;
  let loadFailed = !flashEnabled;
  let loading = flashEnabled;

  const render = () => {
    const labels = buildIdentityLabels("firmware", getLanguage());
    identityLabel.textContent = labels.identity;
    commitLabel.textContent = labels.commit;
    if (loading) {
      identityValue.textContent = labels.loading;
      commitValue.textContent = "—";
      return;
    }
    if (loadFailed || !identity) {
      identityValue.textContent = labels.unavailable;
      commitValue.textContent = "—";
      return;
    }
    identityValue.textContent = formatCompactBuildIdentity(identity);
    commitValue.textContent = formatFullBuildCommit(identity);
  };

  render();
  onLanguageChange(render);

  const description = shell.querySelector(".description");
  if (description) description.insertAdjacentElement("afterend", block);
  else shell.prepend(block);

  if (!flashEnabled) return;
  void loadFirmwareArtifactIdentity(manifestPath)
    .then((loaded) => {
      identity = loaded;
      loadFailed = false;
    })
    .catch(() => {
      identity = undefined;
      loadFailed = true;
    })
    .finally(() => {
      loading = false;
      render();
    });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", install, { once: true });
} else {
  install();
}
