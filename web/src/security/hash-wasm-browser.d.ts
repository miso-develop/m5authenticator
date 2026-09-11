export {};

declare global {
  /**
   * hash-wasm 4.12.0 exposes Node's Buffer in a public input union even though
   * the browser Argon2id path used here only consumes typed arrays. This is a
   * type-only structural declaration; it does not create or require a runtime
   * Buffer global and keeps the Web build browser-only.
   */
  interface Buffer extends Uint8Array {}
}
