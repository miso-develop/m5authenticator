import { decodeQrImage } from "../../src/import/qr";

const syntheticQrPngBase64 =
  "iVBORw0KGgoAAAANSUhEUgAAAjoAAAI6AQAAAAAGM99tAAAFc0lEQVR4nO2dQYrzOBCFX40NvZShD5CjODeYI/WZ/htYR+kDNMjLgE3NQiWplAzMQCeM/umnRZPE9ocN1cXTk6osiqeM+MdzOABBBBFEEEEEEUQQQQT9X0BiYwaiiAC7COJyisgCIC4Aosxov8l1LxddX3FHBBH0FNCqqqrJPiFeVOW6vynWzxly3WcA4SbA/qY57oFJVVW1Bz3tjggi6Cmg3ZKvyHKKfHzOAMIBINxEt3DAAj2doqpHvihn+RfdEUEEfWfMD7/krHyKxut8aFySypoAjddTFOGYBeELiv1Fd0QQQS8BrekUkcsB+dCbyHUXQaxyOi6AbpgeXfDf4NEI+kkgZK1sOtsiVjcA5etkB1Y97n9z127jPRpBBGVHJPsga5pUPtKkcgWANQH5E/a3/rczWyMvuiOCCPrWyDrbi4twE8TLTcwMAaDYT2knKHAACL0iGe/RCPrRoKJGEgBgUt0AZOWxheIE1gO6hSMfdVco1QhB44FgkamHN7XtwGFxj6BZXWe3G0HtPwDBTmFkEzQYyM8gN5TJo6XrSS1JpxLoG6ac4NsBziAJGhFkOjsuCUBIwKrnDOCcFTl2T2i8KGT99a6yFnEtwAx1Cn28RyPoR4OKmAi2rFh0timUIjpKRu9Vi25UIwQNCipKGuZYm22d54hTkd05sqcS7f1XRjZBA4JKYKJGMarOrjNIE9Za1nFCnVoC1NkEDQmq7ke1+cpA9vrygTZbPMoKZZ54MmcTNCao6mxL3Fl51OV0736E4o2gZe8GGO/RCPrRIKgfNj20A9X1y7Z1ajNIi3E3GNkEjQVy3ohtdwolhVeZ0unssmmqziWpswkaEQQfwLmiYFKL2NTcD0vc98vuazUBGdkEjQXq1EiacjznAxtKpl5TUx5+30jbysrIJmgwkDM5ihDp8rP3s5sGaQYJvRGCxgR1kQ14X29zZ7W5pLq0bl8Z2QSNB/KRvarFaYndWjqTp5ZeZ5eTqbMJGhNUKnz3dxXs7weiTJa+1+0UABNk/QUo9jnvfxKEfMWBKDV7j/doBBEEq5+pS41AK4a0TyLLpLmgzK5obspL7ogggr41nOsHoK43eu8abb8U0AvwQDVC0Jig4voloC2sl9jtlthrTY0p89RtamVkEzQWyNWDNeXhItYCfaqun/r+DDXQGdkEDQbyu1i3tuHPJW4Apktag5F+NZKRTdB4oE6NALCNfNW2rjWPbmtJnWTS9SNoWFBX4etKxiY3q3R7V1dt9QYHdTZB44J6nT3VKvaSmp2SRqlYd44IwMgmaEhQXakRaPzzgMblawbCl2hcpgOxNoda0wJZE1Sy7N4XKEKCPPmOCCLoKcNyNlqPVRMiWjewWsVNqalxPUg2+tkEDQp6LGgsdkc+6jsKT/fhrdzrR9CoINf9rHl9tgZZStTLtqhidAN4WL1hZBM0JmifUTqwHpCPdEqeHub2w5eb5Ncw5REOIF4O6IaTXYYJGhL0ULvuamXqVlbfgbWuRibqbIIGBtU1yMeeOtXwszUbrXVjXYEkdTZBI4Jc97PmZ/vdqfW8rfy5P8qcTdCAoL7fSO101pqJ1MnjhjqDLBqE/bMJGhbkG/S1hgx5SbI0zGm160D5agVl1NkEDQp6fLdY6CaU6FpZlv5/rWiSOZugMUH+PTW+Jr3vMgwvSVi7TtDvCMrm3udsqTle1MI7+9lBFfFSTcBPvjWPoDFBf/N26iVHsQBWxS4IN8mv+Vg/BVh/zYfG5Su/5uPZd0QQQU8Zdzrbm9WtUCxYwz+4YsjU7+0e79EI+tGge2+kVIEdRU4HX82rbd9Ie3UeI5ugAUGi/3zOvxlxvEcjiCCCCCKIIIIIIoig/wz0F9J/ar9HlIugAAAAAElFTkSuQmCC";

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function finish(status: "pass" | "fail") {
  document.body.dataset.status = status;
  document.body.textContent = status === "pass" ? "QR_SMOKE_PASS" : "QR_SMOKE_FAIL";
}

try {
  const file = new File([decodeBase64(syntheticQrPngBase64)], "synthetic-qr.png", { type: "image/png" });
  const decoded = await decodeQrImage(file);
  const isExpectedSyntheticTotp =
    decoded.startsWith("otpauth://totp/") &&
    decoded.includes("M5Authenticator%20CI") &&
    decoded.includes("synthetic%40example.invalid");
  finish(isExpectedSyntheticTotp ? "pass" : "fail");
} catch {
  finish("fail");
}
