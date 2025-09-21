import { ConfigService } from '@nestjs/config';
import type { ThrottlerAsyncOptions } from '@nestjs/throttler';

export const throttlerConfig: ThrottlerAsyncOptions = {
  inject: [ConfigService],
  useFactory: (configService: ConfigService) => [
    {
      ttl: +configService.get<number>('RATE_LIMIT_TTL', 60) * 1000,
      limit: +configService.get<number>('RATE_LIMIT_LIMIT', 100),
    },
  ],
};
