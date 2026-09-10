import { decodeBase32Secret } from "./base32";
import { ImportError, type ImportedTotpAccount } from "./types";

export function parseStandardTotpUri(source: string): ImportedTotpAccount {
  let url: URL;
  try {
    url = new URL(source);
  } catch {
    throw new ImportError("The QR code is not a valid TOTP URI.");
  }

  if (url.protocol !== "otpauth:" || url.hostname.toLowerCase() !== "totp") {
    throw new ImportError("Only standard TOTP QR codes are supported.");
  }

  const secretValue = getSingleParameter(url.searchParams, "secret", true);
  if (!secretValue) {
    throw new ImportError("The TOTP QR code is missing required secret metadata.");
  }
  const issuerParameter = getSingleParameter(url.searchParams, "issuer", false);
  const algorithmValue = getSingleParameter(url.searchParams, "algorithm", false) ?? "SHA1";
  const digitsValue = getSingleParameter(url.searchParams, "digits", false) ?? "6";
  const periodValue = getSingleParameter(url.searchParams, "period", false) ?? "30";

  const algorithm = algorithmValue.replaceAll("-", "").toUpperCase();
  if (algorithm !== "SHA1") {
    throw new ImportError("This TOTP algorithm is not supported by V1.");
  }
  if (digitsValue !== "6") {
    throw new ImportError("Only 6-digit TOTP accounts are supported by V1.");
  }
  if (periodValue !== "30") {
    throw new ImportError("Only a 30-second TOTP period is supported by V1.");
  }

  let label: string;
  try {
    label = decodeURIComponent(url.pathname.replace(/^\//, ""));
  } catch {
    throw new ImportError("The TOTP account label is invalid.");
  }

  const separatorIndex = label.indexOf(":");
  const labelIssuer = separatorIndex >= 0 ? label.slice(0, separatorIndex).trim() : "";
  const account = (separatorIndex >= 0 ? label.slice(separatorIndex + 1) : label).trim();
  const parameterIssuer = issuerParameter?.trim() ?? "";

  if (account.length === 0) {
    throw new ImportError("The TOTP QR code does not contain an account name.");
  }
  if (labelIssuer && parameterIssuer && labelIssuer !== parameterIssuer) {
    throw new ImportError("The TOTP issuer metadata is inconsistent.");
  }

  return {
    issuer: parameterIssuer || labelIssuer,
    account,
    secret: decodeBase32Secret(secretValue),
    algorithm: "SHA1",
    digits: 6,
    period: 30,
  };
}

function getSingleParameter(
  parameters: URLSearchParams,
  name: string,
  required: boolean,
): string | undefined {
  const values = parameters.getAll(name);
  if (values.length > 1) {
    throw new ImportError(`The TOTP QR code contains duplicate ${name} metadata.`);
  }
  const value = values[0];
  if (required && (!value || value.length === 0)) {
    throw new ImportError(`The TOTP QR code is missing required ${name} metadata.`);
  }
  return value ?? undefined;
}
