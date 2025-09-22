import { NotFoundException } from '@nestjs/common';

import {
  DeepPartial,
  DeleteResult,
  EntityManager,
  FindManyOptions,
  FindOptionsWhere,
  InsertResult,
  RemoveOptions,
  Repository,
  UpdateResult,
} from 'typeorm';
import { QueryDeepPartialEntity } from 'typeorm/query-builder/QueryPartialEntity';

import { BaseEntity } from '@/database/entities/base.entity';

export abstract class BaseRepository<T extends BaseEntity> {
  constructor(protected readonly repository: Repository<T>) {}

  async findOneById(id: string, relations: string[] = []): Promise<T | null> {
    return this.repository.findOne({
      where: { id } as FindOptionsWhere<T>,
      relations,
    });
  }

  async findOneByIdOrFail(id: string, relations: string[] = []): Promise<T> {
    const entity = await this.findOneById(id, relations);
    if (!entity) throw new NotFoundException(`Entity with id "${id}" not found`);
    return entity;
  }

  async findOneBy(where: FindOptionsWhere<T>): Promise<T | null> {
    return this.repository.findOneBy(where);
  }

  async findOneByOrFail(where: FindOptionsWhere<T>): Promise<T> {
    const entity = await this.findOneBy(where);
    if (!entity) throw new NotFoundException(`Entity not found`);
    return entity;
  }

  async find(options?: FindManyOptions<T>): Promise<T[]> {
    return this.repository.find(options);
  }

  async findBy(where: FindOptionsWhere<T>): Promise<T[]> {
    return this.repository.findBy(where);
  }

  async create(entity: DeepPartial<T>): Promise<T> {
    return this.repository.save(this.repository.create(entity));
  }

  async createMany(entities: DeepPartial<T>[]): Promise<T[]> {
    return this.repository.save(this.repository.create(entities));
  }

  async insert(entities: QueryDeepPartialEntity<T>[]): Promise<InsertResult> {
    return this.repository.insert(entities);
  }

  async save<E extends DeepPartial<T>>(entity: E): Promise<T>;
  async save<E extends DeepPartial<T>>(entities: E[]): Promise<T[]>;
  async save<E extends DeepPartial<T>>(entityOrEntities: E | E[]): Promise<T | T[]> {
    if (Array.isArray(entityOrEntities)) {
      return (await this.repository.save(entityOrEntities as DeepPartial<T>[])) as unknown as T[];
    } else {
      return (await this.repository.save(entityOrEntities)) as unknown as T;
    }
  }

  async update(
    criteria: string | string[] | FindOptionsWhere<T>,
    partialEntity: QueryDeepPartialEntity<T>,
  ): Promise<UpdateResult> {
    return this.repository.update(criteria, partialEntity);
  }

  async delete(criteria: string | string[] | FindOptionsWhere<T>): Promise<DeleteResult> {
    return this.repository.delete(criteria);
  }

  async softDelete(criteria: string | string[] | FindOptionsWhere<T>): Promise<UpdateResult> {
    return this.repository.softDelete(criteria);
  }

  async restore(criteria: string | string[] | FindOptionsWhere<T>): Promise<UpdateResult> {
    return this.repository.restore(criteria);
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

  async remove(entity: T, options?: RemoveOptions): Promise<T>;
  async remove(entities: T[], options?: RemoveOptions): Promise<T[]>;
  async remove(entityOrEntities: T | T[], options?: RemoveOptions): Promise<T | T[]> {
    if (Array.isArray(entityOrEntities)) {
      return this.repository.remove(entityOrEntities, options);
    } else {
      return this.repository.remove(entityOrEntities, options);
    }
  }

  async withTransaction<R>(
    manager: EntityManager,
    fn: (transactionalRepo: Repository<T>) => Promise<R>,
  ): Promise<R> {
    const transactionalRepo = manager.getRepository(this.repository.target);
    return fn(transactionalRepo);
  }
}
