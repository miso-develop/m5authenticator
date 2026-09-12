import { decodeQrImage } from "../../src/import/qr";

const baselineSyntheticQrPngBase64 =
  "iVBORw0KGgoAAAANSUhEUgAAAjoAAAI6AQAAAAAGM99tAAAFc0lEQVR4nO2dQYrzOBCFX40NvZShD5CjODeYI/WZ/htYR+kDNMjLgE3NQiWplAzMQCeM/umnRZPE9ocN1cXTk6osiqeM+MdzOABBBBFEEEEEEUQQQQT9X0BiYwaiiAC7COJyisgCIC4Aosxov8l1LxddX3FHBBH0FNCqqqrJPiFeVOW6vynWzxly3WcA4SbA/qY57oFJVVW1Bz3tjggi6Cmg3ZKvyHKKfHzOAMIBINxEt3DAAj2doqpHvihn+RfdEUEEfWfMD7/krHyKxut8aFySypoAjddTFOGYBeELiv1Fd0QQQS8BrekUkcsB+dCbyHUXQaxyOi6AbpgeXfDf4NEI+kkgZK1sOtsiVjcA5etkB1Y97n9z127jPRpBBGVHJPsga5pUPtKkcgWANQH5E/a3/rczWyMvuiOCCPrWyDrbi4twE8TLTcwMAaDYT2knKHAACL0iGe/RCPrRoKJGEgBgUt0AZOWxheIE1gO6hSMfdVco1QhB44FgkamHN7XtwGFxj6BZXWe3G0HtPwDBTmFkEzQYyM8gN5TJo6XrSS1JpxLoG6ac4NsBziAJGhFkOjsuCUBIwKrnDOCcFTl2T2i8KGT99a6yFnEtwAx1Cn28RyPoR4OKmAi2rFh0timUIjpKRu9Vi25UIwQNCipKGuZYm22d54hTkd05sqcS7f1XRjZBA4JKYKJGMarOrjNIE9Za1nFCnVoC1NkEDQmq7ke1+cpA9vrygTZbPMoKZZ54MmcTNCao6mxL3Fl51OV0736E4o2gZe8GGO/RCPrRIKgfNj20A9X1y7Z1ajNIi3E3GNkEjQVy3ohtdwolhVeZ0unssmmqziWpswkaEQQfwLmiYFKL2NTcD0vc98vuazUBGdkEjQXq1EiacjznAxtKpl5TUx5+30jbysrIJmgwkDM5ihDp8rP3s5sGaQYJvRGCxgR1kQ14X29zZ7W5pLq0bl8Z2QSNB/KRvarFaYndWjqTp5ZeZ5eTqbMJGhNUKnz3dxXs7weiTJa+1+0UABNk/QUo9jnvfxKEfMWBKDV7j/doBBEEq5+pS41AK4a0TyLLpLmgzK5obspL7ogggr41nOsHoK43eu8abb8U0AvwQDVC0Jig4voloC2sl9jtlthrTY0p89RtamVkEzQWyNWDNeXhItYCfaqun/r+DDXQGdkEDQbyu1i3tuHPJW4Apktag5F+NZKRTdB4oE6NALCNfNW2rjWPbmtJnWTS9SNoWFBX4etKxiY3q3R7V1dt9QYHdTZB44J6nT3VKvaSmp2SRqlYd44IwMgmaEhQXakRaPzzgMblawbCl2hcpgOxNoda0wJZE1Sy7N4XKEKCPPmOCCLoKcNyNlqPVRMiWjewWsVNqalxPUg2+tkEDQp6LGgsdkc+6jsKT/fhrdzrR9CoINf9rHl9tgZZStTLtqhidAN4WL1hZBM0JmifUTqwHpCPdEqeHub2w5eb5Ncw5REOIF4O6IaTXYYJGhL0ULvuamXqVlbfgbWuRibqbIIGBtU1yMeeOtXwszUbrXVjXYEkdTZBI4Jc97PmZ/vdqfW8rfy5P8qcTdCAoL7fSO101pqJ1MnjhjqDLBqE/bMJGhbkG/S1hgx5SbI0zGm160D5agVl1NkEDQp6fLdY6CaU6FpZlv5/rWiSOZugMUH+PTW+Jr3vMgwvSVi7TtDvCMrm3udsqTle1MI7+9lBFfFSTcBPvjWPoDFBf/N26iVHsQBWxS4IN8mv+Vg/BVh/zYfG5Su/5uPZd0QQQU8Zdzrbm9WtUCxYwz+4YsjU7+0e79EI+tGge2+kVIEdRU4HX82rbd9Ie3UeI5ugAUGi/3zOvxlxvEcjiCCCCCKIIIIIIoig/wz0F9J/ar9HlIugAAAAAElFTkSuQmCC";

// Fixed mask 3, QR version 8, EC=M. This synthetic/disposable URI shape
// reproduces the finder-pattern sensitivity observed in #76 while carrying
// no real credential material.
const fixedMask3SyntheticQrPngBase64 =
  "iVBORw0KGgoAAAANSUhEUgAAAjoAAAI6AQAAAAAGM99tAAAFe0lEQVR4nO2dW27kNhBFT0UC/KnegZci7cBLMmZJswNpKb0AA+rPAdSofJBFUnaABDPtCRNf/litx4EElInLetGch4ztj8dwQCCBBBJIIIEEEkgggf4vIMtjTEdwM2O73M3sAmwXYLORes6WWzy0fMYbCSTQQ0Czu7vvANNBst3XfXBfb2bA3Zj3u9nrdSTODe7u7mfQw95IIIF+aYz57+0C83dwbiO+LeCb5Ws273fYXo7Rt+djNKa39JjBcDz6jQQS6DNAZpfBmXcABvd1cgcGh9tIXABff9cbCSTQI0DJYrfL4LZwN+arGZuN2Ksf2MIQhv673kgggX5qJK2cdfbg7n7AvA/OHEfuO6Sr61Tu20Nnz+7ua3+fJpBAsJkVn8dTTMhxZAuD2wLY63UkHS3cLTtSPuWNBBLo14afB0zuvobe8JU8P8cFstiez89pzhaoL1CokT1LbHc/iHXjeaE4ZcdgI0nW6UBqRKAeQWXOPk5ObcLGyzwODElTN7M3U75Fli1QZ6Cw7B2SUc97ESJTWVp6K0SaJ9YI18iyBeoMVHwjB2kGXiHN3lWhMKfZ+4Dk4w5Hd9LjUiMCdQhKwUTfLm+kWEwZDkf+vV12Z1vAU5zdgflqONOb+YPfSCCBHg6aDrKmvo0pGmkLkTwyu3uKUG5mBpOnq7Z84hsJJNDPjuobaeMzJUizhvxId8+x0gzXn1aQAvUJCr3xnNKdcCJ+bttlgKQ3pjdj/n5J9/pm4OBYA+rv0wQSiJzudB0B7mYL95y7yu3Jma9jeLZDiudbbk9SIwJ1CSoe61AZlKBjkhr7KbVkJdyB2ZEi34hAfYJCJk8HbRB9ym7qbPJ7secSdq+xSlm2QB2CSuXBkxvTD3NuBmDAtAMMbjAcNl8N3172/MD28pYO5PUTqF+QLdMPY76OmD3npBAA3K8j/u1yj8XizSzP1HGLLZ/xRgIJ9IvjFIPMuiRkd9bZNVEkNMjRpk/J6ydQh6CSBVLKZKbIefJq2VDWkjXOjvzZAvULKitI98Y3skKZmqOm5q/CNQ2gv08T6EuDSgxyKNI5juZIgWpLxkK11Jtl2QL1CGrVSDsNH6XoIBv1h3zWkxtcli1QZ6CmWizORJBmDVd2vu9U9ZtO1nRtWbZAfYGaOoKoBxu8TtdhyvVn/Btko9acLVCfoJhyKVUGZ8WdxlQ8IhGrzJUHUiMCdQpqs1jLnJ0vTd4mj1RXybnpiCxboB5BJzUCVH92zN7FqEtqSdHe1f8nyxaoM9CpwtdrWlTkQbU/cxuG2rMhIjqybIG6A526MuxAdmCX9FbCsmu/kff/C7JsgfoDFQOODjklbyQKxWKUzlDveupIjQjUI6iJrseikJNRTyV6s9NO6zVIozlboA5B57yRVmfX8oPa6eydeddopCxboM5Ajc6uQZqmHqxadpM3Ah+iN7JsgfoCnfpnN839SrZIac1QkqFy9WO5KjUiUIegVmevQPaDwKm3SFh76+huHCSybIG6A7XR9Xz0IbmvmnLksw6hX+T1E6hrkKX9Z24jMP1IW+KR+42YsV3AV+5N55y0eWSzQUKvnybQlwZ5SXeyhdomZ0x7MbnvedOxXOvbNCe5a6dTgboENZEasp/6VAe51poa91PFzT6o8kCgfkHv9xaLGjHODr/SMqqat5fMKVm2QP2B3vdibRaFbckYVMfgKeIur59A/w2QLYAtsbN6U2fzzczyFqhT6VAinS1Qp6Dx/YnNBmd7dmxe05bro2/LQPREGw+H++jcLsAU2yJ0+GkCfWnQhz1816nq56O92lSG1SN1ZRCoU9AH30hbtl6Djh/bQzUbn8qyBeoPZP739/yTsfX3aQIJJJBAAgkkkEACCfSvgf4ELKJHBCXn4GwAAAAASUVORK5CYII=";

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function finish(status: "pass" | "fail", fixture: string, stage: string) {
  document.body.dataset.status = status;
  document.body.dataset.fixture = fixture;
  document.body.dataset.stage = stage;
  document.body.textContent = status === "pass" ? "QR_SMOKE_PASS" : "QR_SMOKE_FAIL";
}

function isExpectedSyntheticTotp(decoded: string): boolean {
  return (
    decoded.startsWith("otpauth://totp/") &&
    decoded.includes("M5Authenticator%20CI") &&
    decoded.includes("synthetic%40example.invalid")
  );
}

const requestedFixture = new URLSearchParams(location.search).get("fixture") ?? "mask3";
const fixture =
  requestedFixture === "baseline"
    ? ["baseline", "synthetic-qr.png", baselineSyntheticQrPngBase64] as const
    : ["mask3", "synthetic-qr-mask3.png", fixedMask3SyntheticQrPngBase64] as const;

try {
  const [fixtureName, filename, pngBase64] = fixture;
  document.body.dataset.fixture = fixtureName;
  document.body.dataset.stage = "before-decode";
  const file = new File([decodeBase64(pngBase64)], filename, { type: "image/png" });
  const decoded = await decodeQrImage(file);
  document.body.dataset.stage = "decoded";
  finish(isExpectedSyntheticTotp(decoded) ? "pass" : "fail", fixtureName, "validated");
} catch {
  finish("fail", fixture[0], "caught");
}
