import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';

import { Repository } from 'typeorm';

import { BaseRepository } from '@/shared/repositories/base.repository';

import { CryptographicKey } from '../entities/cryptographic-key.entity';

export interface ICryptographicKeyRepository {
  findOneByKid(kid: string): Promise<CryptographicKey | null>;
  findActiveKeys(): Promise<CryptographicKey[]>;
  findExpiredKeys(): Promise<CryptographicKey[]>;
  deactivateKey(kid: string): Promise<void>;
}

@Injectable()
export class CryptographicKeyRepository
  extends BaseRepository<CryptographicKey>
  implements ICryptographicKeyRepository
{
  constructor(
    @InjectRepository(CryptographicKey)
    repository: Repository<CryptographicKey>,
  ) {
    super(repository);
  }

  async findOneByKid(kid: string): Promise<CryptographicKey | null> {
    return this.repository.findOne({ where: { kid } });
  }

  async findActiveKeys(): Promise<CryptographicKey[]> {
    return this.repository.find({ where: { isActive: true } });
  }

  async findExpiredKeys(): Promise<CryptographicKey[]> {
    return this.repository
      .createQueryBuilder('key')
      .where('key.expiresAt < :now', { now: new Date() })
      .andWhere('key.isActive = :isActive', { isActive: true })
      .getMany();
  }

  async deactivateKey(kid: string): Promise<void> {
    await this.repository.update({ kid }, { isActive: false });
  }
}
