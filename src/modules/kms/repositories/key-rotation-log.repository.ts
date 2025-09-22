import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';

import { Repository } from 'typeorm';

import { BaseRepository } from '@/shared/repositories/base.repository';

import { KeyRotationLog } from '../entities/key-rotation-log.entity';

export interface IKeyRotationLogRepository {
  findLogsByKeyId(kid: string): Promise<KeyRotationLog[]>;
  findLogsByType(rotationType: 'scheduled' | 'emergency' | 'manual'): Promise<KeyRotationLog[]>;
  findRecentLogs(limit: number): Promise<KeyRotationLog[]>;
}

@Injectable()
export class KeyRotationLogRepository
  extends BaseRepository<KeyRotationLog>
  implements IKeyRotationLogRepository
{
  constructor(
    @InjectRepository(KeyRotationLog)
    repository: Repository<KeyRotationLog>,
  ) {
    super(repository);
  }

  async findLogsByKeyId(kid: string): Promise<KeyRotationLog[]> {
    return this.repository.find({
      where: [{ oldKid: kid }, { newKid: kid }],
      order: { createdAt: 'DESC' },
    });
  }

  async findLogsByType(
    rotationType: 'scheduled' | 'emergency' | 'manual',
  ): Promise<KeyRotationLog[]> {
    return this.repository.find({
      where: { rotationType },
      order: { createdAt: 'DESC' },
    });
  }

  async findRecentLogs(limit: number): Promise<KeyRotationLog[]> {
    return this.repository.find({
      order: { createdAt: 'DESC' },
      take: limit,
    });
  }
}
