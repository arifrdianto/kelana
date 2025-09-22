import { MigrationInterface, QueryRunner, Table } from 'typeorm';

export class CreateCryptographicKeys1758505751194 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'cryptographic_keys',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'gen_random_uuid()',
          },
          {
            name: 'created_at',
            type: 'timestamptz',
            default: 'now()',
          },
          {
            name: 'updated_at',
            type: 'timestamptz',
            default: 'now()',
          },
          {
            name: 'deleted_at',
            type: 'timestamptz',
            isNullable: true,
          },
          {
            name: 'version',
            type: 'integer',
            default: 1,
          },
          {
            name: 'kid',
            type: 'varchar',
            length: '255',
            isUnique: true,
            isNullable: false,
          },
          {
            name: 'algorithm',
            type: 'varchar',
            length: '20',
            default: "'RS256'",
          },
          {
            name: 'public_key',
            type: 'text',
            isNullable: false,
          },
          {
            name: 'private_key',
            type: 'text',
            isNullable: false,
          },
          {
            name: 'is_active',
            type: 'boolean',
            default: true,
          },
          {
            name: 'expires_at',
            type: 'timestamp',
            isNullable: true,
          },
          {
            name: 'rotated_at',
            type: 'timestamp',
            isNullable: true,
          },
          {
            name: 'key_usage',
            type: 'varchar',
            length: '50',
            default: "'signing'",
          },
          {
            name: 'rotation_reason',
            type: 'varchar',
            length: '255',
            isNullable: true,
          },
        ],
      }),
      true,
    );

    await queryRunner.createTable(
      new Table({
        name: 'key_rotation_log',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'gen_random_uuid()',
          },
          {
            name: 'created_at',
            type: 'timestamptz',
            default: 'now()',
          },
          {
            name: 'updated_at',
            type: 'timestamptz',
            default: 'now()',
          },
          {
            name: 'deleted_at',
            type: 'timestamptz',
            isNullable: true,
          },
          {
            name: 'version',
            type: 'integer',
            default: 1,
          },
          {
            name: 'old_kid',
            type: 'varchar',
            length: '255',
            isNullable: true,
          },
          {
            name: 'new_kid',
            type: 'varchar',
            length: '255',
            isNullable: true,
          },
          {
            name: 'rotation_type',
            type: 'varchar',
            length: '50',
          },
          {
            name: 'rotation_reason',
            type: 'text',
            isNullable: true,
          },
          {
            name: 'rotated_at',
            type: 'timestamp',
            default: 'now()',
          },
          {
            name: 'rotated_by',
            type: 'varchar',
            length: '255',
            default: "'system'",
          },
        ],
      }),
      true,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('key_rotation_log');
    await queryRunner.dropTable('cryptographic_keys');
  }
}
