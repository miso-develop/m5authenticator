// Minimal browser Web Serial type seam required by esp-web-tools declarations.
// M5Authenticator application code continues to use its narrower local transport interfaces.
interface SerialPort {
  readonly readable: ReadableStream<Uint8Array> | null;
  readonly writable: WritableStream<Uint8Array> | null;
  open(options: { baudRate: number }): Promise<void>;
  close(): Promise<void>;
}
