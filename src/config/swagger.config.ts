import type { INestApplication } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

export function setupSwagger(app: INestApplication): void {
  const environment = process.env.NODE_ENV ?? 'development';

  if (!['development', 'staging'].includes(environment)) {
    return;
  }

  const port = process.env.PORT ? Number(process.env.PORT) : 3000;
  const serviceName = process.env.SERVICE_NAME ?? 'Kelana';
  const serviceHost = process.env.SERVICE_HOST ?? 'localhost';

  const config = new DocumentBuilder()
    .setTitle('Kelana API')
    .setDescription('API documentation for Kelana')
    .setVersion('1.0.0')
    .addBearerAuth({
      type: 'http',
      scheme: 'bearer',
      bearerFormat: 'JWT',
      name: 'JWT',
      description: 'Enter JWT token',
      in: 'header',
    })
    .addServer(`http://localhost:${port}`, 'Local server')
    .addServer(`http://${serviceHost}:${port}`, 'Production server')
    .setContact('API Support', 'https://example.com/support', 'support@example.com')
    .setLicense('MIT', 'https://opensource.org/licenses/MIT')
    .build();

  const document = SwaggerModule.createDocument(app, config);

  SwaggerModule.setup('docs', app, document, {
    swaggerOptions: {
      persistAuthorization: true,
      displayRequestDuration: true,
      docExpansion: 'none',
      filter: true,
    },
    customSiteTitle: `${serviceName} API Documentation`,
    customJs: [
      'https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/4.15.5/swagger-ui-bundle.min.js',
      'https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/4.15.5/swagger-ui-standalone-preset.min.js',
    ],
    customCssUrl: ['https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/4.15.5/swagger-ui.min.css'],
  });
}
