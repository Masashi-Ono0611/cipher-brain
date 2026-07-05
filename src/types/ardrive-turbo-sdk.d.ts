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

  export interface TurboUploadFileOpts {
    fileStreamFactory: () => NodeJS.ReadableStream;
    fileSizeFactory: () => number;
    dataItemOpts?: {
      tags?: { name: string; value: string }[];
      paidBy?: string[];
    };
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
