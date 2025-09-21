import path from 'path';

import { ConfigService } from '@nestjs/config';
import { TypeOrmModuleAsyncOptions } from '@nestjs/typeorm';

export const databaseConfig: TypeOrmModuleAsyncOptions = {
  inject: [ConfigService],
  useFactory: (configService: ConfigService) => {
    const baseConfig = {
      type: 'postgres' as const,
      host: configService.get<string>('DATABASE_HOST'),
      port: parseInt(configService.get<string>('DATABASE_PORT') || '5432', 10),
      username: configService.get<string>('DATABASE_USERNAME'),
      password: configService.get<string>('DATABASE_PASSWORD'),
      database: configService.get<string>('DATABASE_NAME'),
      entities: [path.join(__dirname, '/../**/*.entity{.ts,.js}')],
      synchronize: false,
      autoLoadEntities: true,
    };

    return baseConfig;
  },
};
