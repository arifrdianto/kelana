import { Logger, ValidationPipe, VersioningType } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';

import helmet from 'helmet';
import { Logger as PinoLogger, LoggerErrorInterceptor } from 'nestjs-pino';

import { setupSwagger } from '@/config/swagger.config';

import { AppModule } from './app.module';

async function bootstrap() {
  const logger = new Logger('Bootstrap');

  try {
    logger.log('Starting application...');

    // Initialize the NestJS application
    const app = await NestFactory.create(AppModule, {
      bufferLogs: true,
    });

    // Enable API versioning
    app.enableVersioning({
      type: VersioningType.URI,
      prefix: 'v',
      defaultVersion: '1',
    });

    // Security headers
    app.use(
      helmet({
        crossOriginEmbedderPolicy: false, // Needed for Swagger UI
        contentSecurityPolicy: {
          directives: {
            imgSrc: ["'self'", 'data:', 'https:'],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", 'https:'],
          },
        },
      }),
    );

    // CORS configuration
    app.enableCors({
      origin: process.env.CORS_ORIGINS?.split(',') || [
        'http://localhost:3000',
        'https://localhost:3000',
      ],
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
        'X-Request-ID',
      ],
    });

    // API Documentation (Swagger)
    setupSwagger(app);

    // Global validation pipe with transformation
    app.useGlobalPipes(
      new ValidationPipe({
        transform: true,
        whitelist: true,
        forbidNonWhitelisted: true,
        transformOptions: {
          enableImplicitConversion: true,
        },
      }),
    );

    // Logger setup
    app.useLogger(app.get(PinoLogger));
    app.useGlobalInterceptors(new LoggerErrorInterceptor());

    // Graceful shutdown handlers
    process.on('SIGTERM', () => {
      logger.log('Received SIGTERM signal. Starting graceful shutdown...');
      app
        .close()
        .then(() => {
          logger.log('Application closed.');
          process.exit(0);
        })
        .catch((error) => {
          logger.error('Error during shutdown:', error);
          process.exit(1);
        });
    });

    process.on('SIGINT', () => {
      logger.log('Received SIGINT signal. Starting graceful shutdown...');
      app
        .close()
        .then(() => {
          logger.log('Application closed.');
          process.exit(0);
        })
        .catch((error) => {
          logger.error('Error during shutdown:', error);
          process.exit(1);
        });
    });

    const port = process.env.PORT || 3000;
    await app.listen(port);

    logger.log(`Application is running on: http://localhost:${port}`);
    logger.log(`Swagger documentation available at: http://localhost:${port}/docs`);
  } catch (error) {
    logger.error(`Failed to start application: ${error.message}`, error.stack);
    process.exit(1);
  }
}

bootstrap().catch((error: Error) => {
  const logger = new Logger('Bootstrap');
  logger.error(`Application failed to start: ${error.message}`, error.stack);
  process.exit(1);
});
