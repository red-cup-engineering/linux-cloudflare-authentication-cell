export interface AuthenticationRequest {
  profile: string;
  expectedAccountId: string;
  scopes: string[];
  settlementDirectory: string;
  browser?: true;
  callbackHost?: "localhost";
  callbackPort?: 8976;
}

export interface OpaqueAuthorityReference {
  profile: "org.red-cup-engineering.opaque-authority-reference.v1";
  type: "OpaqueAuthorityReference";
  reference: string;
  content: string;
  secretBytesReturned: false;
  readonly [field: string]: unknown;
}

export interface AuthenticationRmnProjection {
  mediaType: "application/rmn+cbor";
  semanticId: string;
  term: readonly unknown[];
}

export interface AuthenticationReceipt {
  type: "LinuxCloudflareAuthenticationReceipt";
  profile: string;
  account: { id: string };
  scopes: string[];
  settlementDirectory: string;
  credentialCustody: "linux-secret-service";
  authority: OpaqueAuthorityReference | null;
  rmn: AuthenticationRmnProjection;
  activity: Readonly<Record<string, unknown>>;
  credentialReturned: false;
  verified: true;
}

export interface AuthenticationInspection {
  type: "LinuxCloudflareAuthenticationInspection";
  profile: string;
  account: { id: string };
  settlementDirectory: string;
  secretToolProbe: "compatible";
  credentialCustody: "linux-secret-service";
  credentialReturned: false;
  verified: true;
}

export interface AuthenticationProgress {
  type: "LinuxCloudflareAuthenticationProgress";
  phase: "profile-probe" | "profile-reused" | "reauthorization-required" | "profile-verification" | "profile-activation";
  message: string;
  reason?: string;
}

export interface AuthenticationOptions {
  onProgress?: (event: AuthenticationProgress) => void;
}

export declare class LinuxCloudflareAuthenticationRefusal extends Error {
  readonly code: string;
  readonly evidence: Readonly<Record<string, unknown>>;
  constructor(code: string, message: string, evidence?: Record<string, unknown>);
  toJSON(): {
    type: "LinuxCloudflareAuthenticationRefusal";
    code: string;
    message: string;
    evidence: Readonly<Record<string, unknown>>;
    credentialReturned: false;
    verified: false;
  };
}

export declare function authenticateLinuxColonyWithCloudflare(request: AuthenticationRequest, options?: AuthenticationOptions): Promise<AuthenticationReceipt>;
export declare function inspectLinuxCloudflareAuthentication(request: AuthenticationRequest): Promise<AuthenticationInspection>;
