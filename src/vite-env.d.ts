/// <reference types="vite/client" />

declare module '*.wasm?url' {
  const url: string;
  export default url;
}

declare module '*.wasm' {
  const init: (options?: unknown) => Promise<unknown>;
  export default init;
}
