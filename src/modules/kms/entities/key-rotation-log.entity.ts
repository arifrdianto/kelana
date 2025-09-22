import { Column, Entity } from 'typeorm';

import { BaseEntity } from '@/database/entities/base.entity';

@Entity('key_rotation_log')
export class KeyRotationLog extends BaseEntity {
  @Column({ name: 'old_kid', type: 'varchar', nullable: true, length: 255 })
  oldKid: string | null;

  @Column({ name: 'new_kid', type: 'varchar', nullable: true, length: 255 })
  newKid: string | null;

  @Column({ name: 'rotation_type', type: 'varchar', length: 50 })
  rotationType: 'scheduled' | 'emergency' | 'manual';

  @Column({ name: 'rotation_reason', type: 'text', nullable: true })
  rotationReason: string | null;

  @Column({ name: 'rotated_by', type: 'varchar', length: 255, default: 'system' })
  rotatedBy: string;
}
