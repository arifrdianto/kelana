import { HttpException, HttpStatus } from '@nestjs/common';

export class KMSException extends HttpException {
  constructor(message: string, status: HttpStatus = HttpStatus.INTERNAL_SERVER_ERROR) {
    super(message, status);
  }
}

export class KeyNotFoundException extends KMSException {
  constructor(kid: string) {
    super(`Key not found: ${kid}`, HttpStatus.NOT_FOUND);
  }
}

export class InvalidJWKException extends KMSException {
  constructor(errors: string[]) {
    super(`Invalid JWK: ${errors.join(', ')}`, HttpStatus.BAD_REQUEST);
  }
}

export class JWKValidationException extends KMSException {
  constructor(errors: string[]) {
    super(`JWK validation failed: ${errors.join(', ')}`, HttpStatus.BAD_REQUEST);
  }
}

export class JWKSUnavailableException extends KMSException {
  constructor(reason: string = 'No valid keys available') {
    super(`JWKS service unavailable: ${reason}`, HttpStatus.SERVICE_UNAVAILABLE);
  }
}

export class KeyRotationException extends KMSException {
  constructor(message: string, cause?: Error) {
    super(
      `Key rotation failed: ${message}${cause ? ` (${cause.message})` : ''}`,
      HttpStatus.INTERNAL_SERVER_ERROR,
    );
  }
}
