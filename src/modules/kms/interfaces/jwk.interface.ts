/**
 * RFC 7517 compliant JWK interfaces
 */

import { SignOptions, VerifyOptions } from 'jsonwebtoken';

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

export interface JwtSignOptions extends Omit<SignOptions, 'algorithm' | 'keyid'> {
  expiresIn?: SignOptions['expiresIn'];
  notBefore?: SignOptions['notBefore'];
  audience?: SignOptions['audience'];
  issuer?: SignOptions['issuer'];
  subject?: SignOptions['subject'];
  noTimestamp?: SignOptions['noTimestamp'];
  header?: SignOptions['header'];
  kid?: string; // Allow override of key ID
}

export interface JwtVerifyOptions extends Omit<VerifyOptions, 'complete'> {
  ignoreExpiration?: boolean;
  ignoreNotBefore?: boolean;
  clockTolerance?: number;
}
