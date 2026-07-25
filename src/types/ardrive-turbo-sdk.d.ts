// Minimal ambient shape for the OPTIONAL `@ardrive/turbo-sdk` peer dependency
// (peerDependenciesMeta: optional — see package.json). It is never a devDependency:
// the turbo backend imports it lazily at runtime ONLY when actually used (uploads),
// and the whole point of that laziness is that a fresh machine needs neither the
// package nor its types to build/typecheck/pull. Declaring the narrow surface this
// codebase actually calls (rather than installing the real (heavy) package just for
// `tsc --noEmit`) keeps that property while still getting real type-checking on the
// call sites in src/lib/backends/turbo.ts and src/mcp.ts.
declare module '@ardrive/turbo-sdk' {
  export interface TurboUploadCost {
    winc: string;
  }

  export interface TurboBalance {
    winc: string;
  }

  export interface TurboFiatRate {
    rate: number;
  }

  /**
   * Upload progress callbacks (#283). `onProgress` covers both phases and carries
   * `step` to say which one; the SDK also exposes per-phase variants we do not use.
   *
   * Because this file is a HAND-WRITTEN shape rather than the package's own types, a
   * compiler error is not available to tell us whether the real SDK still accepts this:
   * declaring it here makes our call site type-check either way. The evidence that it
   * does is upstream's README plus `package.json`'s `^1.42.0` floor (events landed in
   * v1.26.0). A version that dropped them would be caught at runtime by progress simply
   * never appearing — which is why the smoke test asserts the reporter's behaviour
   * directly, where it CAN be verified, instead of pretending this declaration proves
   * anything.
   */
  export interface TurboUploadEvents {
    onProgress?: (e: { totalBytes: number; processedBytes: number; step?: string }) => void;
  }

  export interface TurboUploadFileOpts {
    fileStreamFactory: () => NodeJS.ReadableStream;
    fileSizeFactory: () => number;
    dataItemOpts?: {
      tags?: { name: string; value: string }[];
      paidBy?: string[];
    };
    events?: TurboUploadEvents;
  }

  export interface TurboUploadResult {
    id: string;
  }

  export interface TurboUnauthenticatedClient {
    getUploadCosts(opts: { bytes: number[] }): Promise<TurboUploadCost[]>;
    getFiatToAR(opts: { currency: string }): Promise<TurboFiatRate>;
  }

  export interface TurboAuthenticatedClient extends TurboUnauthenticatedClient {
    getBalance(): Promise<TurboBalance>;
    uploadFile(opts: TurboUploadFileOpts): Promise<TurboUploadResult>;
  }

  export const TurboFactory: {
    unauthenticated(): TurboUnauthenticatedClient;
    authenticated(opts: { signer: unknown }): TurboAuthenticatedClient;
  };

  export class ArweaveSigner {
    constructor(jwk: unknown);
  }
}
