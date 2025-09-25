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
