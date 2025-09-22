import { createHash, createPublicKey } from 'crypto';

import { Injectable, Logger } from '@nestjs/common';

import { JWK, JWKValidationResult, KeyOperation } from '../interfaces/jwk.interface';

@Injectable()
export class KeyValidationService {
  private readonly logger = new Logger(KeyValidationService.name);

  /**
   * Validate JWK compliance with RFC 7517
   */
  public validateJWK(jwk: JWK): JWKValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // RFC 7517 Section 4.1 - kty is REQUIRED
      if (!jwk.kty) {
        errors.push('Missing required parameter: kty (Key Type)');
      } else {
        this.validateKeyType(jwk.kty, errors);
      }

      // Key-type specific validation
      if (jwk.kty === 'RSA') {
        this.validateRSAParameters(jwk, errors, warnings);
      } else if (jwk.kty === 'EC') {
        this.validateECParameters(jwk, errors, warnings);
      } else if (jwk.kty === 'oct') {
        this.validateSymmetricParameters(jwk, errors, warnings);
      }

      // RFC 7517 Section 4.2 - use parameter validation
      if (jwk.use) {
        this.validateUseParameter(jwk.use, errors);
      }

      // RFC 7517 Section 4.3 - key_ops parameter validation
      if (jwk.key_ops) {
        this.validateKeyOperations(jwk.key_ops, errors);
      }

      // RFC 7517 Section 4.4 - alg parameter validation
      if (jwk.alg) {
        this.validateAlgorithm(jwk.alg, warnings);
      }

      // RFC 7517 Section 4.5 - kid parameter validation
      if (jwk.kid) {
        this.validateKeyId(jwk.kid, warnings);
      } else {
        warnings.push('Missing recommended parameter: kid (Key ID) for key identification');
      }

      // X.509 parameters validation (Sections 4.6-4.9)
      this.validateX509Parameters(jwk, errors, warnings);

      // Lifecycle parameters validation
      this.validateLifecycleParameters(jwk, errors, warnings);

      // Cross-parameter validation
      this.validateParameterConsistency(jwk, errors, warnings);
    } catch (error) {
      errors.push(`Validation error: ${error.message}`);
      this.logger.error('JWK validation failed', error.stack);
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Validate key type parameter
   */
  private validateKeyType(kty: string, errors: string[]): void {
    const validKeyTypes = ['RSA', 'EC', 'oct'];
    if (!validKeyTypes.includes(kty)) {
      errors.push(`Invalid key type: ${kty}. Must be one of: ${validKeyTypes.join(', ')}`);
    }
  }

  /**
   * Validate RSA-specific parameters
   */
  private validateRSAParameters(jwk: JWK, errors: string[], warnings: string[]): void {
    // RFC 7517 + JWA - RSA keys must have n and e
    if (!jwk.n) {
      errors.push('Missing required RSA parameter: n (modulus)');
    } else if (!this.isValidBase64Url(jwk.n)) {
      errors.push('Invalid base64url encoding for RSA parameter: n');
    } else if (jwk.n.length < 342) {
      // ~2048 bits
      warnings.push('RSA modulus appears to be less than 2048 bits (security concern)');
    }

    if (!jwk.e) {
      errors.push('Missing required RSA parameter: e (exponent)');
    } else if (!this.isValidBase64Url(jwk.e)) {
      errors.push('Invalid base64url encoding for RSA parameter: e');
    }

    // Private key parameters should not be present in public JWKs
    if (jwk.d) {
      warnings.push('Private key parameter (d) present in JWK - ensure this is intentional');
    }

    // Validate key size
    if (jwk.n) {
      try {
        const modulusBits = this.getModulusBitLength(jwk.n);
        if (modulusBits < 2048) {
          errors.push(`RSA key size ${modulusBits} bits is below minimum 2048 bits`);
        } else if (modulusBits < 3072) {
          warnings.push(
            `RSA key size ${modulusBits} bits. Consider 3072+ bits for better security`,
          );
        }
      } catch {
        warnings.push('Unable to determine RSA key size');
      }
    }
  }

  /**
   * Validate EC-specific parameters
   */
  private validateECParameters(jwk: JWK, errors: string[], warnings: string[]): void {
    if (!jwk.crv) {
      errors.push('Missing required EC parameter: crv (curve)');
    } else {
      const validCurves = ['P-256', 'P-384', 'P-521', 'secp256k1'];
      if (!validCurves.includes(jwk.crv)) {
        warnings.push(`Non-standard EC curve: ${jwk.crv}`);
      }
    }

    if (!jwk.x) {
      errors.push('Missing required EC parameter: x (x-coordinate)');
    } else if (!this.isValidBase64Url(jwk.x)) {
      errors.push('Invalid base64url encoding for EC parameter: x');
    }

    if (!jwk.y) {
      errors.push('Missing required EC parameter: y (y-coordinate)');
    } else if (!this.isValidBase64Url(jwk.y)) {
      errors.push('Invalid base64url encoding for EC parameter: y');
    }
  }

  /**
   * Validate symmetric key parameters
   */
  private validateSymmetricParameters(jwk: JWK, errors: string[], warnings: string[]): void {
    if (!jwk.k) {
      errors.push('Missing required symmetric key parameter: k');
    } else if (!this.isValidBase64Url(jwk.k)) {
      errors.push('Invalid base64url encoding for symmetric key parameter: k');
    } else {
      // Check key size
      const keyBits = ((jwk.k.length * 6) / 8) * 8; // Convert base64url length to bits
      if (keyBits < 128) {
        errors.push(`Symmetric key size ${keyBits} bits is too small (minimum 128 bits)`);
      } else if (keyBits < 256) {
        warnings.push(`Symmetric key size ${keyBits} bits. Consider 256+ bits for better security`);
      }
    }
  }

  /**
   * Validate use parameter
   */
  private validateUseParameter(use: string, errors: string[]): void {
    const validUses = ['sig', 'enc'];
    if (!validUses.includes(use)) {
      errors.push(`Invalid use parameter: ${use}. Must be 'sig' or 'enc'`);
    }
  }

  /**
   * Validate key_ops parameter
   */
  private validateKeyOperations(keyOps: KeyOperation[], errors: string[]): void {
    const validOperations: KeyOperation[] = [
      'sign',
      'verify',
      'encrypt',
      'decrypt',
      'wrapKey',
      'unwrapKey',
      'deriveKey',
      'deriveBits',
    ];

    const invalidOps = keyOps.filter((op) => !validOperations.includes(op));
    if (invalidOps.length > 0) {
      errors.push(`Invalid key operations: ${invalidOps.join(', ')}`);
    }

    // Check for duplicate operations
    const uniqueOps = [...new Set(keyOps)];
    if (uniqueOps.length !== keyOps.length) {
      errors.push('Duplicate key operations found');
    }

    // RFC 7517 Section 4.3 - validate operation combinations
    this.validateKeyOperationCombinations(keyOps, errors);
  }

  /**
   * Validate key operation combinations per RFC 7517
   */
  private validateKeyOperationCombinations(keyOps: KeyOperation[], errors: string[]): void {
    // RFC 7517: "Multiple unrelated key operations SHOULD NOT be specified"
    const hasSign = keyOps.includes('sign');
    const hasVerify = keyOps.includes('verify');
    const hasEncrypt = keyOps.includes('encrypt');
    const hasDecrypt = keyOps.includes('decrypt');
    const hasWrapKey = keyOps.includes('wrapKey');
    const hasUnwrapKey = keyOps.includes('unwrapKey');

    // Valid combinations: sign+verify, encrypt+decrypt, wrapKey+unwrapKey
    const validCombinations = [
      [hasSign, hasVerify],
      [hasEncrypt, hasDecrypt],
      [hasWrapKey, hasUnwrapKey],
    ];

    const activeCombinations = validCombinations.filter((combo) =>
      combo.some((operation) => operation),
    ).length;

    if (activeCombinations > 1) {
      errors.push(
        'Multiple unrelated key operations specified (violates RFC 7517 recommendations)',
      );
    }
  }

  /**
   * Validate algorithm parameter
   */
  private validateAlgorithm(alg: string, warnings: string[]): void {
    // Common algorithms - this could be expanded
    const commonAlgorithms = [
      'RS256',
      'RS384',
      'RS512',
      'ES256',
      'ES384',
      'ES512',
      'HS256',
      'HS384',
      'HS512',
      'PS256',
      'PS384',
      'PS512',
    ];

    if (!commonAlgorithms.includes(alg)) {
      warnings.push(`Non-standard algorithm: ${alg}`);
    }
  }

  /**
   * Validate key ID parameter
   */
  private validateKeyId(kid: string, warnings: string[]): void {
    if (kid.length === 0) {
      warnings.push('Empty key ID provided');
    } else if (kid.length > 100) {
      warnings.push('Key ID is unusually long (>100 characters)');
    }
  }

  /**
   * Validate X.509 parameters
   */
  private validateX509Parameters(jwk: JWK, errors: string[], warnings: string[]): void {
    // x5u validation
    if (jwk.x5u) {
      try {
        new URL(jwk.x5u);
        if (!jwk.x5u.startsWith('https://')) {
          warnings.push('X.509 URL should use HTTPS for security');
        }
      } catch {
        errors.push('Invalid X.509 URL format');
      }
    }

    // x5c validation
    if (jwk.x5c) {
      if (!Array.isArray(jwk.x5c) || jwk.x5c.length === 0) {
        errors.push('X.509 certificate chain must be a non-empty array');
      } else {
        jwk.x5c.forEach((cert, index) => {
          if (!this.isValidBase64(cert)) {
            errors.push(`Invalid base64 encoding in X.509 certificate chain at index ${index}`);
          }
        });
      }
    }

    // x5t and x5t#S256 validation
    if (jwk.x5t && !this.isValidBase64Url(jwk.x5t)) {
      errors.push('Invalid base64url encoding for X.509 certificate SHA-1 thumbprint');
    }

    if (jwk['x5t#S256'] && !this.isValidBase64Url(jwk['x5t#S256'])) {
      errors.push('Invalid base64url encoding for X.509 certificate SHA-256 thumbprint');
    }
  }

  /**
   * Validate lifecycle parameters
   */
  private validateLifecycleParameters(jwk: JWK, errors: string[], warnings: string[]): void {
    const now = Math.floor(Date.now() / 1000);

    if (jwk.nbf !== undefined) {
      if (!Number.isInteger(jwk.nbf) || jwk.nbf < 0) {
        errors.push('Invalid nbf (not before) parameter - must be a positive integer');
      } else if (jwk.nbf > now + 300) {
        // 5 minutes clock skew tolerance
        warnings.push('Key is not yet valid (nbf is in the future)');
      }
    }

    if (jwk.exp !== undefined) {
      if (!Number.isInteger(jwk.exp) || jwk.exp < 0) {
        errors.push('Invalid exp (expiration) parameter - must be a positive integer');
      } else if (jwk.exp < now - 300) {
        // 5 minutes clock skew tolerance
        warnings.push('Key has expired');
      }
    }

    if (jwk.nbf !== undefined && jwk.exp !== undefined && jwk.nbf >= jwk.exp) {
      errors.push('Invalid lifecycle: nbf (not before) must be less than exp (expiration)');
    }
  }

  /**
   * Validate parameter consistency
   */
  private validateParameterConsistency(jwk: JWK, errors: string[], warnings: string[]): void {
    // RFC 7517 Section 4.3: use and key_ops should not be used together
    if (jwk.use && jwk.key_ops) {
      warnings.push(
        'Both "use" and "key_ops" parameters present - RFC 7517 recommends using only one',
      );

      // Validate consistency if both are present
      const useCompatibleOps =
        jwk.use === 'sig' ? ['sign', 'verify'] : ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'];

      const hasIncompatibleOps = jwk.key_ops.some((op) => !useCompatibleOps.includes(op));
      if (hasIncompatibleOps) {
        errors.push(`Inconsistent "use" and "key_ops" parameters`);
      }
    }

    // Algorithm and key type consistency
    if (jwk.alg && jwk.kty) {
      const algKeyTypeMap: Record<string, string[]> = {
        RS256: ['RSA'],
        RS384: ['RSA'],
        RS512: ['RSA'],
        PS256: ['RSA'],
        PS384: ['RSA'],
        PS512: ['RSA'],
        ES256: ['EC'],
        ES384: ['EC'],
        ES512: ['EC'],
        HS256: ['oct'],
        HS384: ['oct'],
        HS512: ['oct'],
      };

      const expectedKeyTypes = algKeyTypeMap[jwk.alg];
      if (expectedKeyTypes && !expectedKeyTypes.includes(jwk.kty)) {
        errors.push(`Algorithm ${jwk.alg} is incompatible with key type ${jwk.kty}`);
      }
    }
  }

  /**
   * Validate base64url encoding
   */
  private isValidBase64Url(str: string): boolean {
    if (!str || typeof str !== 'string') return false;

    // Base64url uses A-Z, a-z, 0-9, -, _ and no padding
    const base64UrlRegex = /^[A-Za-z0-9_-]+$/;
    return base64UrlRegex.test(str) && str.length > 0;
  }

  /**
   * Validate standard base64 encoding (with padding)
   */
  private isValidBase64(str: string): boolean {
    if (!str || typeof str !== 'string') return false;

    try {
      // Base64 uses A-Z, a-z, 0-9, +, / and = for padding
      const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
      return base64Regex.test(str) && Buffer.from(str, 'base64').toString('base64') === str;
    } catch {
      return false;
    }
  }

  /**
   * Get RSA modulus bit length
   */
  private getModulusBitLength(n: string): number {
    try {
      const buffer = Buffer.from(n, 'base64url');
      return buffer.length * 8;
    } catch {
      throw new Error('Invalid modulus format');
    }
  }

  /**
   * Create a compliant JWK from key pair
   */
  public createCompliantJWK(
    publicKey: string,
    kid: string,
    keyUsage: 'signing' | 'encryption' = 'signing',
    algorithm: string = 'RS256',
    expiresAt?: Date,
    certificateChain?: string[],
  ): JWK {
    try {
      const keyObject = createPublicKey(publicKey);

      if (keyObject.asymmetricKeyType !== 'rsa') {
        throw new Error('Only RSA keys are currently supported');
      }

      const keyData = keyObject.export({ format: 'jwk' }) as { n?: string; e?: string };

      if (!keyData.n || !keyData.e) {
        throw new Error('Failed to extract RSA parameters from public key');
      }

      const jwk: JWK = {
        kty: 'RSA',
        use: keyUsage === 'signing' ? 'sig' : 'enc',
        key_ops: this.getKeyOperations(keyUsage),
        alg: algorithm,
        kid,
        n: keyData.n,
        e: keyData.e,
        nbf: Math.floor(Date.now() / 1000),
      };

      // Add expiration if provided
      if (expiresAt) {
        jwk.exp = Math.floor(expiresAt.getTime() / 1000);
      }

      // Add certificate chain if provided
      if (certificateChain && certificateChain.length > 0) {
        jwk.x5c = certificateChain;

        // Generate thumbprints
        try {
          const cert = Buffer.from(certificateChain[0], 'base64');
          jwk.x5t = this.generateCertificateThumbprint(cert, 'sha1');
          jwk['x5t#S256'] = this.generateCertificateThumbprint(cert, 'sha256');
        } catch (error) {
          this.logger.warn('Failed to generate certificate thumbprints', error);
        }
      }

      // Validate the created JWK
      const validation = this.validateJWK(jwk);
      if (!validation.valid) {
        throw new Error(`Generated JWK is not RFC 7517 compliant: ${validation.errors.join(', ')}`);
      }

      if (validation.warnings.length > 0) {
        this.logger.warn('JWK validation warnings', { warnings: validation.warnings });
      }

      return jwk;
    } catch (error) {
      this.logger.error('Failed to create compliant JWK', error.stack);
      throw new Error(`JWK creation failed: ${error.message}`);
    }
  }

  /**
   * Get appropriate key operations based on usage
   */
  private getKeyOperations(usage: 'signing' | 'encryption'): KeyOperation[] {
    switch (usage) {
      case 'signing':
        return ['sign', 'verify'];
      case 'encryption':
        return ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'];
      default:
        return ['verify']; // Safe default
    }
  }

  /**
   * Generate certificate thumbprint
   */
  private generateCertificateThumbprint(cert: Buffer, algorithm: 'sha1' | 'sha256'): string {
    const hash = createHash(algorithm);
    hash.update(cert);
    return hash.digest('base64url');
  }
}
