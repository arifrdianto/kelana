// src/modules/kms/interfaces/jwk.interface.ts
/**
 * RFC 7517 compliant JWK interfaces with comprehensive type safety
 * Supports RSA, EC, and symmetric keys per IANA registry
 */

// Base64url encoded string type for better type safety
export type Base64UrlString = string & { readonly __brand: 'Base64Url' };
export type Base64String = string & { readonly __brand: 'Base64' };

/**
 * RFC 7517 Section 4 - JSON Web Key Parameters
 */
export interface JWKBase {
  // Required parameter
  kty: KeyType;

  // Optional common parameters
  use?: PublicKeyUse;
  key_ops?: KeyOperation[];
  alg?: string;
  kid?: string;

  // X.509 Certificate Chain parameters (RFC 7517 Section 4.6-4.10)
  x5u?: string; // X.509 URL
  x5c?: Base64String[]; // X.509 Certificate Chain
  x5t?: Base64UrlString; // X.509 Certificate SHA-1 Thumbprint
  'x5t#S256'?: Base64UrlString; // X.509 Certificate SHA-256 Thumbprint

  // Lifecycle parameters (RFC 7517 Section 4.4-4.5)
  nbf?: number; // Not Before (NumericDate)
  exp?: number; // Expiration Time (NumericDate)
}

/**
 * RSA Key Type (RFC 7518 Section 6.3)
 */
export interface RSAKey extends JWKBase {
  kty: 'RSA';

  // Public key parameters (required for public keys)
  n: Base64UrlString; // Modulus
  e: Base64UrlString; // Exponent

  // Private key parameters (MUST NOT be present in public JWKs)
  d?: Base64UrlString; // Private Exponent
  p?: Base64UrlString; // First Prime Factor
  q?: Base64UrlString; // Second Prime Factor
  dp?: Base64UrlString; // First Factor CRT Exponent
  dq?: Base64UrlString; // Second Factor CRT Exponent
  qi?: Base64UrlString; // First CRT Coefficient
  oth?: RSAOtherPrimesInfo[]; // Other Primes Info
}

/**
 * RSA Other Primes Info (RFC 7518 Section 6.3.2.7)
 */
export interface RSAOtherPrimesInfo {
  r: Base64UrlString; // Prime Factor
  d: Base64UrlString; // Factor CRT Exponent
  t: Base64UrlString; // Factor CRT Coefficient
}

/**
 * Elliptic Curve Key Type (RFC 7518 Section 6.2)
 */
export interface ECKey extends JWKBase {
  kty: 'EC';

  // Public key parameters
  crv: ECCurve; // Curve
  x: Base64UrlString; // X Coordinate
  y: Base64UrlString; // Y Coordinate

  // Private key parameter (MUST NOT be present in public JWKs)
  d?: Base64UrlString; // ECC Private Key
}

/**
 * Symmetric Key Type (RFC 7518 Section 6.4)
 */
export interface SymmetricKey extends JWKBase {
  kty: 'oct';

  // Symmetric key value
  k: Base64UrlString; // Key Value
}

/**
 * Union type for all JWK types
 */
export type JWK = RSAKey | ECKey | SymmetricKey;

/**
 * JSON Web Key Set (RFC 7517 Section 5)
 */
export interface JWKS {
  keys: JWK[];
}

/**
 * Key Type values from IANA registry
 */
export type KeyType = 'RSA' | 'EC' | 'oct' | 'OKP';

/**
 * Public Key Use values (RFC 7517 Section 4.2)
 */
export type PublicKeyUse = 'sig' | 'enc';

/**
 * Key Operations (RFC 7517 Section 4.3)
 */
export type KeyOperation =
  | 'sign' // Compute digital signature or MAC
  | 'verify' // Verify digital signature or MAC
  | 'encrypt' // Encrypt content
  | 'decrypt' // Decrypt content and validate decryption, if applicable
  | 'wrapKey' // Encrypt key
  | 'unwrapKey' // Decrypt key and validate decryption, if applicable
  | 'deriveKey' // Derive key
  | 'deriveBits'; // Derive bits not to be used as a key

/**
 * Elliptic Curve values (RFC 7518 Section 6.2.1.1)
 */
export type ECCurve = 'P-256' | 'P-384' | 'P-521' | 'secp256k1';

/**
 * JWK Validation Result interface
 */
export interface JWKValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  keyId?: string;
  keyType?: KeyType;
  algorithm?: string;
  securityLevel?: SecurityLevel;
}

/**
 * Security level assessment for keys
 */
export type SecurityLevel = 'low' | 'medium' | 'high' | 'very-high';

/**
 * Extended Key Pair interface for internal use
 */
export interface KeyPairExtended {
  privateKey: string;
  publicKey: string;
  kid: string;
  algorithm: SupportedAlgorithm;
  keyType: KeyType;
  createdAt: Date;
  expiresAt: Date;
  keyUsage: KeyUsage;
  securityLevel: SecurityLevel;
}

/**
 * Supported algorithms (RFC 7518)
 */
export type SupportedAlgorithm =
  // RSA PKCS#1 v1.5
  | 'RS256'
  | 'RS384'
  | 'RS512'
  // RSA PSS
  | 'PS256'
  | 'PS384'
  | 'PS512'
  // ECDSA
  | 'ES256'
  | 'ES384'
  | 'ES512'
  // EdDSA (RFC 8037)
  | 'EdDSA';

/**
 * Key usage enumeration
 */
export type KeyUsage = 'signing' | 'encryption' | 'key-agreement';

/**
 * JWK Thumbprint Calculation (RFC 7638)
 */
export interface JWKThumbprintOptions {
  hashAlgorithm: 'sha256' | 'sha1';
  canonicalization: 'RFC7638';
}

/**
 * JWKS URI Configuration
 */
export interface JWKSConfiguration {
  uri: string;
  cacheMaxAge: number;
  staleWhileRevalidate: number;
  timeout: number;
  retryAttempts: number;
  retryDelay: number;
}

/**
 * Key Rotation Event interface
 */
export interface KeyRotationEvent {
  id: string;
  timestamp: Date;
  oldKeyId?: string;
  newKeyId: string;
  rotationType: RotationType;
  reason: string;
  triggeredBy: string;
  duration: number;
  success: boolean;
  error?: string;
}

/**
 * Key Rotation Types
 */
export type RotationType = 'initial' | 'scheduled' | 'emergency' | 'manual';

/**
 * Enhanced JWKS metadata for caching and monitoring
 */
export interface JWKSMetadata {
  lastUpdated: Date;
  keyCount: number;
  nextKeyExpiry?: Date;
  cacheHeaders: {
    etag: string;
    lastModified: string;
    maxAge: number;
  };
  securityInfo: {
    validKeys: number;
    expiredKeys: number;
    weakKeys: number;
    algorithmDistribution: Record<string, number>;
  };
}

/**
 * Key Health Status
 */
export interface KeyHealthStatus {
  overall: HealthStatus;
  activeKeys: number;
  expiredKeys: number;
  expiringKeys: number;
  weakKeys: number;
  nextExpiry?: Date;
  oldestKey?: Date;
  issues: KeyHealthIssue[];
}

/**
 * Health Status enumeration
 */
export type HealthStatus = 'healthy' | 'degraded' | 'unhealthy';

/**
 * Key Health Issues
 */
export interface KeyHealthIssue {
  severity: 'info' | 'warning' | 'error' | 'critical';
  message: string;
  keyId?: string;
  recommendation?: string;
}

/**
 * JWK Set Statistics
 */
export interface JWKSStatistics {
  totalKeys: number;
  validKeys: number;
  expiredKeys: number;
  certificateKeys: number;
  algorithmDistribution: Record<SupportedAlgorithm, number>;
  keyTypeDistribution: Record<KeyType, number>;
  securityLevelDistribution: Record<SecurityLevel, number>;
  averageKeyAge: number;
  keyRotationFrequency: number;
}

/**
 * Type guards for JWK validation
 */
export function isRSAKey(jwk: JWK): jwk is RSAKey {
  return jwk.kty === 'RSA';
}

export function isECKey(jwk: JWK): jwk is ECKey {
  return jwk.kty === 'EC';
}

export function isSymmetricKey(jwk: JWK): jwk is SymmetricKey {
  return jwk.kty === 'oct';
}

export function isValidKeyOperation(op: string): op is KeyOperation {
  return [
    'sign',
    'verify',
    'encrypt',
    'decrypt',
    'wrapKey',
    'unwrapKey',
    'deriveKey',
    'deriveBits',
  ].includes(op);
}

export function isValidPublicKeyUse(use: string): use is PublicKeyUse {
  return ['sig', 'enc'].includes(use);
}

/**
 * Utility functions for Base64url encoding/decoding
 */
export function isBase64Url(str: string): str is Base64UrlString {
  if (!str) return false;
  const base64UrlPattern = /^[A-Za-z0-9_-]+$/;
  return base64UrlPattern.test(str);
}

export function isBase64(str: string): str is Base64String {
  if (!str) return false;
  const base64Pattern = /^[A-Za-z0-9+/]*={0,2}$/;
  return base64Pattern.test(str);
}

/**
 * JWK Builder for creating well-formed JWKs
 */
export class JWKBuilder {
  private jwk: Partial<JWK>;

  constructor(keyType: KeyType) {
    this.jwk = { kty: keyType };
  }

  static forRSA(): RSAKeyBuilder {
    return new RSAKeyBuilder();
  }

  static forEC(curve: ECCurve): ECKeyBuilder {
    return new ECKeyBuilder(curve);
  }

  static forSymmetric(): SymmetricKeyBuilder {
    return new SymmetricKeyBuilder();
  }
}

export class RSAKeyBuilder {
  private jwk: Partial<RSAKey> = { kty: 'RSA' };

  modulus(n: string): this {
    this.jwk.n = n as Base64UrlString;
    return this;
  }

  exponent(e: string): this {
    this.jwk.e = e as Base64UrlString;
    return this;
  }

  keyId(kid: string): this {
    this.jwk.kid = kid;
    return this;
  }

  algorithm(alg: SupportedAlgorithm): this {
    this.jwk.alg = alg;
    return this;
  }

  use(use: PublicKeyUse): this {
    this.jwk.use = use;
    return this;
  }

  keyOperations(ops: KeyOperation[]): this {
    this.jwk.key_ops = ops;
    return this;
  }

  expiration(exp: number): this {
    this.jwk.exp = exp;
    return this;
  }

  build(): RSAKey {
    if (!this.jwk.n || !this.jwk.e) {
      throw new Error('RSA key requires modulus (n) and exponent (e)');
    }
    return this.jwk as RSAKey;
  }
}

export class ECKeyBuilder {
  private jwk: Partial<ECKey>;

  constructor(curve: ECCurve) {
    this.jwk = { kty: 'EC', crv: curve };
  }

  coordinates(x: string, y: string): this {
    this.jwk.x = x as Base64UrlString;
    this.jwk.y = y as Base64UrlString;
    return this;
  }

  keyId(kid: string): this {
    this.jwk.kid = kid;
    return this;
  }

  algorithm(alg: SupportedAlgorithm): this {
    this.jwk.alg = alg;
    return this;
  }

  use(use: PublicKeyUse): this {
    this.jwk.use = use;
    return this;
  }

  build(): ECKey {
    if (!this.jwk.x || !this.jwk.y) {
      throw new Error('EC key requires x and y coordinates');
    }
    return this.jwk as ECKey;
  }
}

export class SymmetricKeyBuilder {
  private jwk: Partial<SymmetricKey> = { kty: 'oct' };

  keyValue(k: string): this {
    this.jwk.k = k as Base64UrlString;
    return this;
  }

  keyId(kid: string): this {
    this.jwk.kid = kid;
    return this;
  }

  algorithm(alg: string): this {
    this.jwk.alg = alg;
    return this;
  }

  build(): SymmetricKey {
    if (!this.jwk.k) {
      throw new Error('Symmetric key requires key value (k)');
    }
    return this.jwk as SymmetricKey;
  }
}
