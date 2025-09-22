import { ValidationPipe, VersioningType } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';

import helmet from 'helmet';
import { Logger, LoggerErrorInterceptor, PinoLogger } from 'nestjs-pino';

import { setupSwagger } from '@/config/swagger.config';

import { AppModule } from './app.module';

async function bootstrap() {
  // Initialize the NestJS application
  const app = await NestFactory.create(AppModule, {
    bufferLogs: true,
  });

  // Enable API versioning
  app.enableVersioning({
    type: VersioningType.URI,
    prefix: 'v',
  });

  // Basic security headers
  app.use(helmet());

  // CORS configuration
  app.enableCors({
    origin: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: process.env.CORS_CREDENTIALS === 'true',
    methods: process.env.CORS_METHODS?.split(',') || [
      'GET',
      'POST',
      'PUT',
      'DELETE',
      'PATCH',
      'OPTIONS',
    ],
    allowedHeaders: process.env.CORS_ALLOWED_HEADERS?.split(',') || [
      'Content-Type',
      'Authorization',
      'Accept',
    ],
  });

  // API Documentation
  setupSwagger(app);

  // Global validation pipe with transformation enabled
  app.useGlobalPipes(new ValidationPipe({ transform: true }));

  // Logger
  app.useLogger(app.get(Logger));
  app.useGlobalInterceptors(new LoggerErrorInterceptor());

  const port = process.env.PORT || 3000;
  await app.listen(port);
}

bootstrap().catch((error: Error) => {
  PinoLogger.root.error({ error }, `Failed to start application: ${error.message}`);
  process.exit(1);
});
