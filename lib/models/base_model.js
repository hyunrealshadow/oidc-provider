/* eslint-disable max-classes-per-file */

import snakeCase from '../helpers/_/snake_case.js';
import epochTime from '../helpers/epoch_time.js';
import pickBy from '../helpers/_/pick_by.js';
import instance from '../helpers/weak_cache.js';
import isConstructable from '../helpers/type_validators.js';

import hasFormat from './mixins/has_format.js';

const IN_PAYLOAD = [
  'iat',
  'exp',
  'jti',
  'kind',
];

const adapterCache = new WeakMap();

export default function getBaseModel(provider) {
  function adapter(ctx) {
    const obj = typeof ctx === 'function' ? ctx : ctx.constructor;

    if (!adapterCache.has(obj)) {
      if (isConstructable(instance(provider).Adapter)) {
        adapterCache.set(obj, new (instance(provider).Adapter)(obj.name));
      } else {
        adapterCache.set(obj, instance(provider).Adapter(obj.name));
      }
    }

    return adapterCache.get(obj);
  }

  class Class {
    constructor({ jti, kind, ...payload } = {}) {
      Object.assign(this, pickBy(
        payload,
        (val, key) => this.constructor.IN_PAYLOAD.includes(key),
      ));

      if (kind && kind !== this.constructor.name) {
        throw new TypeError('kind mismatch');
      }

      this.kind = kind || this.constructor.name;
      this.jti = jti;
    }

    static instantiate(payload) {
      return new this(payload);
    }

    async save(ttl) {
      if (!this.jti) {
        this.jti = this.generateTokenId();
      }

      // this is true for all BaseToken descendants
      if (typeof this.constructor.expiresIn !== 'function') {
        this.exp = epochTime() + ttl;
      }

      const { value, payload } = await this.getValueAndPayload();
      let returnValue = value;

      if (payload) {
        const upsertResult = await this.adapter.upsert(this.jti, payload, ttl);
        if (upsertResult) {
          returnValue = upsertResult;
        }
        this.emit('saved');
      } else {
        this.emit('issued');
      }

      return returnValue;
    }

    async destroy() {
      await this.adapter.destroy(this.jti);
      this.emit('destroyed');
    }

    static get adapter() {
      return adapter(this);
    }

    get adapter() {
      return adapter(this);
    }

    static get IN_PAYLOAD() { return IN_PAYLOAD; }

    static async find(value, { ignoreExpiration = false } = {}) {
      if (typeof value !== 'string') {
        return undefined;
      }

      const stored = await this.adapter.find(value);
      if (!stored) {
        return undefined;
      }

      try {
        const payload = await this.verify(stored, { ignoreExpiration });

        return this.instantiate(payload);
      } catch (err) {
        return undefined;
      }
    }

    emit(eventName) {
      provider.emit(`${snakeCase(this.kind)}.${eventName}`, this);
    }

    /*
     * ttlPercentagePassed
     * returns a Number (0 to 100) with the value being percentage of the token's ttl already
     * passed. The higher the percentage the older the token is. At 0 the token is fresh, at a 100
     * it is expired.
     */
    ttlPercentagePassed() {
      const now = epochTime();
      const percentage = Math.floor(100 * ((now - this.iat) / (this.exp - this.iat)));
      return Math.max(Math.min(100, percentage), 0);
    }

    get isValid() { return !this.isExpired; }

    get isExpired() { return this.exp <= epochTime(); }

    get remainingTTL() {
      if (!this.exp) {
        return this.expiration;
      }
      return this.exp - epochTime();
    }
  }

  class BaseModel extends hasFormat(provider, 'base', Class) {}

  return BaseModel;
}
