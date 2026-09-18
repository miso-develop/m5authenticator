export function settleDeviceActionNotice(
  startMessage: string,
  currentMessage: string,
  successMessage: string,
): string {
  const trimmed = currentMessage.trimEnd();
  const stillShowsStartMessage = trimmed === startMessage.trimEnd();
  const stillLooksInProgress = trimmed.endsWith("…") || trimmed.endsWith("...");

  if (stillShowsStartMessage || stillLooksInProgress) return successMessage;
  return currentMessage;
}
