const CANONICAL_STATE_LOCK_NAME = "m5authenticator-canonical-browser-state-v1";
export const CANONICAL_BROWSER_STATE_CHANGED_EVENT = "m5authenticator:canonical-browser-state-changed";

interface BrowserLockManager {
  request<T>(name: string, callback: () => Promise<T>): Promise<T>;
}

let fallbackTail: Promise<void> = Promise.resolve();

export async function withCanonicalBrowserStateLock<T>(action: () => Promise<T>): Promise<T> {
  const navigatorWithLocks = typeof navigator === "undefined"
    ? undefined
    : navigator as Navigator & { locks?: BrowserLockManager };
  if (navigatorWithLocks?.locks) {
    return navigatorWithLocks.locks.request(CANONICAL_STATE_LOCK_NAME, action);
  }

  const previous = fallbackTail;
  let release: (() => void) | null = null;
  fallbackTail = new Promise<void>((resolve) => { release = resolve; });
  await previous;
  try {
    return await action();
  } finally {
    release?.();
  }
}

export function notifyCanonicalBrowserStateChanged(): void {
  if (typeof window !== "undefined") {
    window.dispatchEvent(new Event(CANONICAL_BROWSER_STATE_CHANGED_EVENT));
  }
}
