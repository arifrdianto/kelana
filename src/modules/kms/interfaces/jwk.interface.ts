/**
 * RFC 7517 compliant JWK interfaces
 */

export interface JWK {
  // Required parameters
  kty: 'RSA' | 'EC' | 'oct';

  // Optional common parameters
  use?: 'sig' | 'enc';
  key_ops?: KeyOperation[];
  alg?: string;
  kid?: string;

  // X.509 parameters
  x5u?: string;
  x5c?: string[];
  x5t?: string;
  'x5t#S256'?: string;

  // Lifecycle parameters
  nbf?: number;
  exp?: number;

  // RSA-specific parameters
  n?: string; // Modulus
  e?: string; // Exponent
  d?: string; // Private exponent (should not be in public JWKs)

  // EC-specific parameters
  crv?: string;
  x?: string;
  y?: string;

  // Symmetric key parameters
  k?: string;
}

export interface JWKS {
  keys: JWK[];
}

export type KeyOperation =
  | 'sign'
  | 'verify'
  | 'encrypt'
  | 'decrypt'
  | 'wrapKey'
  | 'unwrapKey'
  | 'deriveKey'
  | 'deriveBits';

export interface JWKValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

export interface KeyPairExtended {
  privateKey: string;
  publicKey: string;
  kid: string;
  algorithm: 'RS256';
  createdAt: Date;
  expiresAt: Date;
  keyUsage: 'signing' | 'encryption';
}
