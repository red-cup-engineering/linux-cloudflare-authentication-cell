export interface AuthenticationRequest {
  profile: string;
  expectedAccountId: string;
  scopes: string[];
  settlementDirectory: string;
  browser?: boolean;
  callbackHost?: "localhost" | "127.0.0.1" | "::1";
  callbackPort?: number;
}

export interface AuthenticationReceipt {
  type: "LinuxCloudflareAuthenticationReceipt";
  profile: string;
  account: { id: string };
  scopes: string[];
  settlementDirectory: string;
  credentialCustody: "linux-secret-service";
  credentialReturned: false;
  verified: true;
}

export declare function authenticateLinuxColonyWithCloudflare(request: AuthenticationRequest): Promise<AuthenticationReceipt>;
