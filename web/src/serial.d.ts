interface SerialPortOptions {
  baudRate: number;
}

interface SerialPortLike {
  readable: ReadableStream<Uint8Array> | null;
  writable: WritableStream<Uint8Array> | null;
  open(options: SerialPortOptions): Promise<void>;
  close(): Promise<void>;
}

interface SerialLike {
  requestPort(): Promise<SerialPortLike>;
}

declare global {
  interface Navigator {
    serial?: SerialLike;
  }
}

export {};
