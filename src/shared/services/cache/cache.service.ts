import { Inject, Injectable, Logger } from '@nestjs/common';

import { Cacheable } from 'cacheable';

@Injectable()
export class CacheService {
  private readonly logger = new Logger(CacheService.name);

  constructor(@Inject('CACHE_INSTANCE') private readonly cache: Cacheable) {}

  async get<T>(key: string): Promise<T | undefined> {
    try {
      const value = await this.cache.get<T>(key);
      this.logger.debug(`Cache GET: ${key} - ${value ? 'HIT' : 'MISS'}`);
      return value;
    } catch (error) {
      this.logger.error(`Cache GET error for key ${key}:`, error);
      return undefined;
    }
  }

  async set<T>(key: string, value: T, ttl?: number | string): Promise<void> {
    try {
      await this.cache.set(key, value, ttl);
      this.logger.debug(`Cache SET: ${key} with TTL ${ttl || 'default'}`);
    } catch (error) {
      this.logger.error(`Cache SET error for key ${key}:`, error);
      throw error;
    }
  }

  async delete(key: string): Promise<void> {
    try {
      await this.cache.delete(key);
      this.logger.debug(`Cache DELETE: ${key}`);
    } catch (error) {
      this.logger.error(`Cache DELETE error for key ${key}:`, error);
      throw error;
    }
  }

  async has(key: string): Promise<boolean> {
    try {
      const value = await this.cache.get(key);
      return value !== undefined;
    } catch (error) {
      this.logger.error(`Cache HAS error for key ${key}:`, error);
      return false;
    }
  }

  async clear(): Promise<void> {
    try {
      await this.cache.clear();
      this.logger.log('Cache cleared');
    } catch (error) {
      this.logger.error('Cache CLEAR error:', error);
      throw error;
    }
  }

  async getMany<T>(keys: string[]): Promise<Map<string, T>> {
    const results = new Map<string, T>();

    try {
      const promises = keys.map(async (key) => {
        const value = await this.get<T>(key);
        if (value !== undefined) {
          results.set(key, value);
        }
      });

      await Promise.all(promises);
      this.logger.debug(`Cache GET_MANY: ${keys.length} keys, ${results.size} found`);
      return results;
    } catch (error) {
      this.logger.error('Cache GET_MANY error:', error);
      return results;
    }
  }

  async setMany<T>(entries: Map<string, T>, ttl?: number | string): Promise<void> {
    try {
      const promises = Array.from(entries.entries()).map(([key, value]) =>
        this.set(key, value, ttl),
      );

      await Promise.all(promises);
      this.logger.debug(`Cache SET_MANY: ${entries.size} keys set`);
    } catch (error) {
      this.logger.error('Cache SET_MANY error:', error);
      throw error;
    }
  }

  async deleteMany(keys: string[]): Promise<void> {
    try {
      const promises = keys.map((key) => this.delete(key));
      await Promise.all(promises);
      this.logger.debug(`Cache DELETE_MANY: ${keys.length} keys deleted`);
    } catch (error) {
      this.logger.error('Cache DELETE_MANY error:', error);
      throw error;
    }
  }

  async increment(key: string, amount: number = 1): Promise<number> {
    try {
      const current = (await this.get<number>(key)) || 0;
      const newValue = current + amount;
      await this.set(key, newValue);
      this.logger.debug(`Cache INCREMENT: ${key} by ${amount} = ${newValue}`);
      return newValue;
    } catch (error) {
      this.logger.error(`Cache INCREMENT error for key ${key}:`, error);
      throw error;
    }
  }

  async decrement(key: string, amount: number = 1): Promise<number> {
    return this.increment(key, -amount);
  }

  async getOrSet<T>(key: string, factory: () => Promise<T>, ttl?: number | string): Promise<T> {
    try {
      let value = await this.get<T>(key);

      if (value === undefined) {
        this.logger.debug(`Cache MISS for ${key}, generating value`);
        value = await factory();
        await this.set(key, value, ttl);
        this.logger.debug(`Cache SET after factory: ${key}`);
      } else {
        this.logger.debug(`Cache HIT for ${key}`);
      }

      return value;
    } catch (error) {
      this.logger.error(`Cache GET_OR_SET error for key ${key}:`, error);
      throw error;
    }
  }
}
