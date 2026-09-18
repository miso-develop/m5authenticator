export interface BrowserLifecycleManagement {
  disconnectTransport(): Promise<void>;
}

export interface BrowserLifecycleSerialSession {
  close(): Promise<void>;
}

export interface BrowserLifecycleCleanup {
  abortPending(): void;
  clearTransientState(): void;
  management: BrowserLifecycleManagement | null;
  serialSession: BrowserLifecycleSerialSession | null;
}

export function cleanupBrowserLifecycle(resources: BrowserLifecycleCleanup): void {
  resources.abortPending();
  resources.clearTransientState();

  const release = resources.management
    ? resources.management.disconnectTransport()
    : resources.serialSession
      ? resources.serialSession.close()
      : null;

  if (release) {
    void release.catch(() => {
      // Page/browser teardown is best-effort. Transport failure here must not
      // be reinterpreted as a Device Lock boundary.
    });
  }
}
