import { describe, expect, it } from "vitest";

import {
  hasCoreValidationTranslation,
  translateCoreValidationText,
} from "./core-validation-i18n";

const CORE_VALIDATION_SOURCES = [
  "The QR code is not a valid TOTP URI.",
  "Only standard TOTP QR codes are supported.",
  "The TOTP QR code is missing required secret metadata.",
  "This TOTP algorithm is not supported by V1.",
  "Only 6-digit TOTP accounts are supported by V1.",
  "Only a 30-second TOTP period is supported by V1.",
  "The TOTP account label is invalid.",
  "The TOTP QR code does not contain an account name.",
  "The TOTP issuer metadata is inconsistent.",
  "The QR code contains an invalid TOTP secret encoding.",
  "The imported TOTP secret is empty.",
  "The QR code is not a valid Google Authenticator migration URI.",
  "The QR code is not a Google Authenticator migration export.",
  "The Google Authenticator migration QR code is missing its payload.",
  "The Google Authenticator migration payload is invalid.",
  "The Google Authenticator migration QR code contains no accounts.",
  "The Google Authenticator migration contains an account unsupported by V1.",
  "The Google Authenticator migration contains an account without a name.",
  "The migration exceeds the V1 account limit.",
  "This QR code does not belong to the active Google Authenticator migration batch.",
  "The Google Authenticator migration batch metadata is invalid.",
  "The Google Authenticator migration batch is incomplete.",
  "The Google Authenticator migration payload encoding is invalid.",
  "Finish or clear the active Google Authenticator migration batch first.",
  "The import session has reached the V1 limit of 32 accounts.",
  "The QR code format is not supported.",
  "Finish the active Google Authenticator migration batch before provisioning.",
  "No imported accounts are ready for provisioning.",
  "The import session is inconsistent.",
  "Select an image file containing a QR code.",
  "The selected image could not be rasterized by this browser.",
  "The selected image has invalid dimensions.",
  "The selected image pixels could not be read for QR decoding.",
  "No supported QR code could be decoded from the selected image.",
  "Firmware update manifest must be same-origin",
  "Firmware update manifest is invalid",
  "Firmware update manifest has an unsupported build",
  "Firmware update manifest has an invalid firmware part",
  "Firmware update manifest has an invalid firmware part offset",
  "Firmware update manifest has an invalid firmware path",
  "Firmware update files must be same-origin",
  "Canonical Vault state changed before Recovery Package export; refresh and retry",
  "Recovery Package export is blocked until Device replacement is confirmed and this browser becomes active",
  "Choose a Recovery Package file first",
  "Enter the Recovery Passphrase",
  "This browser already has canonical state for that Vault. Import will not overwrite an active or pending Trusted Browser implicitly.",
  "New Passphrase confirmation does not match",
  "No browser canonical Vault is selected",
  "Canonical Vault state changed before Passphrase update; refresh and retry",
  "Recovery Passphrase changes are blocked while Device replacement is pending",
  "Canonical Vault generation conflict; recovery or explicit conflict resolution is required",
] as const;

const DYNAMIC_VALIDATION_SOURCES = [
  "The TOTP QR code contains duplicate secret metadata.",
  "The TOTP QR code is missing required issuer metadata.",
  "Unsupported Google Authenticator migration metadata: version=3, batchSize=1, batchIndex=0.",
  "Invalid Google Authenticator migration metadata: version=2, batchSize=0, batchIndex=0.",
  "Firmware update manifest is missing the bootloader image",
  "Firmware update ota_0 application image has an invalid size",
  "Firmware update partition table image exceeds its allowed flash window",
  "Firmware update manifest could not be loaded (404)",
  "Firmware update image could not be loaded (503)",
] as const;

describe("core validation localization", () => {
  it.each(CORE_VALIDATION_SOURCES)("translates core Japanese validation: %s", (source) => {
    expect(hasCoreValidationTranslation(source)).toBe(true);
    const translated = translateCoreValidationText(source, "ja");
    expect(translated).toBeDefined();
    expect(translated).not.toBe(source);
  });

  it.each(DYNAMIC_VALIDATION_SOURCES)("translates dynamic Japanese validation: %s", (source) => {
    expect(hasCoreValidationTranslation(source)).toBe(true);
    const translated = translateCoreValidationText(source, "ja");
    expect(translated).toBeDefined();
    expect(translated).not.toBe(source);
  });

  it("keeps canonical English unchanged", () => {
    const source = "Firmware update manifest is invalid";
    expect(translateCoreValidationText(source, "en")).toBe(source);
  });
});
