import { decodeQrImage } from "../../src/import/qr";
import { ImportSession } from "../../src/import/session";

// Synthetic-only Google Authenticator migration QR:
// - top-level metadata version 2
// - one QR part containing 4 disposable TOTP accounts
// - QR version 16, EC=M, 2 px/module, four-module quiet zone
// The intentionally low pixels/module isolates the dense-image decode path while
// remaining representative of a single symbol carrying multiple accounts.
const denseSyntheticMigrationQrPngBase64 =
  "iVBORw0KGgoAAAANSUhEUgAAALIAAACyAQAAAADO8ajFAAAE3UlEQVR4nNVXQYfnSRKNf0fTmiCauS5z6WsRRDGGaFHMaWj6Myz9AZo5zWkMw5yGZU5Lf4mlr0OULNqSJYs6DcUY+gNkyT9liL/Y+5rKue7+julJL1++ePl+h4I/+y6f/OkywP/e+uEpnF/Di1dXV4fLp/f353Bxf7h4FA/la5qPKdCNl2pIaHk8jhddQX2mUgiiZqjiHj+9Cc7KqgCZs/0VfqhOkAxhsDWM1xbvi1uUe9bsrjGGrQ3/Qx1Q/mvtdOPfP75/VZ+BjiAy3VEbV9WGjzVKERAHWYDmin2LFzZdaj2rKiCAe5+78/YgaMPQQMSsEbW9PmkNOL3RjN6oIRb3HR9AW6VCIMI2vGn0sdV/ZBUDaq8pMARjbfEda/TZVmhXYVK2IY/zeQLH5xfHb/5Gr5y+of6p3Z0eoD/ufyjDxGxO7gNI1jBeuTvvMB5BbZQO79pRh7QdfrbinLTEzMy9wgN25105FaYPrWzBYAFqu/0Th0kbhUxTV4zS7Fv9K2zQ7OXswAEYxVs/NCMIm2ED1ZR7iO3wLcU1bfY2KTOVGo8dfwIAduApxuDuzUC2fnCsIOfZfTmE9e6888PD8eyEcTy9efnT9VH8R4Hj2S4Pie4e6CXJ5cU7o9vzLz/7gnCXhwCWKwEnLANglITN/T4B7B8/uwCn1/orNr9/3m+nbf0ZiZ61GsgaZe7JW/+oh3KN9CRJFmo8tv6RWQN0apGPcFs1YKsnfX7194TX/3ilcIZXP1xfHlm2/GfpbKwJ6aM0x5S25U+tabHUJJ2zBPoun6F4AfKIaU0stbUq2vCHMppaIAhm0xolU239XDoLYwCHr9ZzVW97/oyW2BkacAwv9tzmeSiRTgeQ0tYbUkpu59dnSODKSQUeNPvY4hE0lVssRncCJvA93pBgmGQ5CqsH7vZ/AqdjIp7d8leH++CX//6Bv4Tz2PghzTJRctXIIGRk2ub5s4erm9s/fn72+gDnDPDyl2Pwbh6n6zIc3CKpjyCdc5s/CVLCoEEEwKMp7ef3mf921T/4HcJUvz99+x7cd3mSx5fPby6O8rW++OfR3x1Bj5eP63Ooc4K4eQdXfxwvGE638On6O4hH+yRUgdowoJCGAKMsQXf3ayTUC3tJd0kaE3ju9MGpqBGBs0ZWR+C1fV9aai+NwjY5ECUAtv5vC5sRVnOchtQ0bDNfh7p88zvDwRAATh9uvoKgt7/wRh+cnhGTk0rCmhO2bd9ItpWDW60Ok0qsr61/lqgMNQcS9aWDF9J2vohyEvbJtihGtoaw7Q8hUW2Y6QrPrj138wI1k5LCo/fkGOhG5ju8zrVojNGlMU7VmXOfh6yrI0AKWdnoPmCr52o8nG22FTmpW+d9f1AOjCbGXDoLrGRt8ucp0O94Qvr5pF+/ev/6Y/B5uzvu3qORnVPaSsu0htEDt/05llIAs4CtQHVvvulLT4Dvbj690dMH7Dcnmu+P16fvY8cnprsiiBkB6KhF+/mtouLp1kZNx5YU+/5zeDovBY8fn7+75KPRU6HjaZdXPl/gh1/J4Cc40fVbvf2CZMdfdLghgEMRiHLqPj8B3t4/5CxYLybA+3/h3cz9f2sQHD9/cXp99mC/vfvu1dnFsx0fXx2gicaC0nTsKlv/AwKCezSCHExN3Td5ePg//9//D88OfPYsWMvtAAAAAElFTkSuQmCC";

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export async function runDenseMigrationQrSmoke(): Promise<void> {
  const pngBytes = decodeBase64(denseSyntheticMigrationQrPngBase64);
  try {
    document.body.dataset.stage = "qr-dense-raster-decode";
    const file = new File([pngBytes], "synthetic-dense-migration.png", { type: "image/png" });
    const decoded = await decodeQrImage(file);
    document.body.dataset.stage = "qr-dense-import-session";
    const session = new ImportSession();
    try {
      const update = session.importDecodedText(decoded);
      if (update.batch !== undefined || update.accounts.length !== 4) {
        throw new Error("Dense synthetic migration QR did not reach the expected import-session state");
      }
      document.body.dataset.stage = "qr-dense-validated";
    } finally {
      session.clear();
    }
  } finally {
    pngBytes.fill(0);
  }
}
