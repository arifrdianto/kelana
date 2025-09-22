import {
  DeepPartial,
  DeleteResult,
  FindManyOptions,
  FindOptionsWhere,
  Repository,
  UpdateResult,
} from 'typeorm';
import { QueryDeepPartialEntity } from 'typeorm/query-builder/QueryPartialEntity.js';

import { BaseEntity } from '@/database/entities/base.entity';

export abstract class BaseRepository<T extends BaseEntity> {
  constructor(protected readonly repository: Repository<T>) {}

  async findOneById(id: string): Promise<T | null> {
    return this.repository.findOneBy({ id } as FindOptionsWhere<T>);
  }

  async findOneBy(where: FindOptionsWhere<T>): Promise<T | null> {
    return this.repository.findOneBy(where);
  }

  async find(options?: FindManyOptions<T>): Promise<T[]> {
    return this.repository.find(options);
  }

  async findBy(where: FindOptionsWhere<T>): Promise<T[]> {
    return this.repository.findBy(where);
  }

  async create(entity: DeepPartial<T>): Promise<T> {
    const newEntity = this.repository.create(entity);
    return this.repository.save(newEntity);
  }

  async createMany(entities: DeepPartial<T>[]): Promise<T[]> {
    const newEntities = this.repository.create(entities);
    return this.repository.save(newEntities);
  }

  async update(
    criteria: string | string[] | FindOptionsWhere<T>,
    partialEntity: QueryDeepPartialEntity<T>,
  ): Promise<UpdateResult> {
    return this.repository.update(criteria, partialEntity);
  }

  async updateById(id: string, partialEntity: QueryDeepPartialEntity<T>): Promise<UpdateResult> {
    return this.repository.update(id, partialEntity);
  }

  async delete(criteria: string | string[] | FindOptionsWhere<T>): Promise<DeleteResult> {
    return this.repository.delete(criteria);
  }

  async deleteById(id: string): Promise<DeleteResult> {
    return this.repository.delete(id);
  }

  async softDelete(criteria: string | string[] | FindOptionsWhere<T>): Promise<UpdateResult> {
    return this.repository.softDelete(criteria);
  }

  async softDeleteById(id: string): Promise<UpdateResult> {
    return this.repository.softDelete(id);
  }

  async count(options?: FindManyOptions<T>): Promise<number> {
    return this.repository.count(options);
  }

  async countBy(where: FindOptionsWhere<T>): Promise<number> {
    return this.repository.countBy(where);
  }

  async exists(options: FindManyOptions<T>): Promise<boolean> {
    return this.repository.exists(options);
  }

  async existsBy(where: FindOptionsWhere<T>): Promise<boolean> {
    return this.repository.existsBy(where);
  }

  async save(entity: DeepPartial<T>): Promise<T>;
  async save(entities: DeepPartial<T>[]): Promise<T[]>;
  async save(entityOrEntities: DeepPartial<T> | DeepPartial<T>[]): Promise<T | T[]> {
    return Array.isArray(entityOrEntities)
      ? this.repository.save(entityOrEntities)
      : this.repository.save(entityOrEntities);
  }

  async remove(entity: T): Promise<T>;
  async remove(entities: T[]): Promise<T[]>;
  async remove(entityOrEntities: T | T[]): Promise<T | T[]> {
    return Array.isArray(entityOrEntities)
      ? this.repository.remove(entityOrEntities)
      : this.repository.remove(entityOrEntities);
  }
}
