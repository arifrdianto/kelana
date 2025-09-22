import { Column, Entity } from 'typeorm';

import { BaseEntity } from '@/database/entities/base.entity';

@Entity('cryptographic_keys')
export class CryptographicKey extends BaseEntity {
  @Column({ name: 'kid', type: 'varchar', unique: true, nullable: false, length: 255 })
  kid: string;

  @Column({ name: 'algorithm', type: 'varchar', default: 'RS256', length: 20 })
  algorithm: string;

  @Column({ name: 'public_key', type: 'text', nullable: false })
  publicKey: string;

  @Column({ name: 'private_key', type: 'text', nullable: false })
  privateKey: string;

  @Column({ name: 'is_active', type: 'boolean', default: true })
  isActive: boolean;

  @Column({ name: 'expires_at', type: 'timestamp', nullable: true })
  expiresAt: Date;

  @Column({ name: 'key_usage', type: 'varchar', default: 'signing', length: 50 })
  keyUsage: string;

  @Column({ name: 'rotation_reason', type: 'varchar', nullable: true, length: 255 })
  rotationReason: string | null;
}
