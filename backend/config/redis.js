const Redis = require('ioredis');
const { REDIS_URL } = require('./env');
const logger = require('../shared/logger');

const redis = new Redis(REDIS_URL, {
  maxRetriesPerRequest: 3,
  enableReadyCheck: true,
  lazyConnect: false,
});

redis.on('connect', () => logger.info('Redis connected'));
redis.on('error', (err) => logger.error('Redis error', { error: err.message }));
redis.on('reconnecting', () => logger.warn('Redis reconnecting'));

module.exports = redis;
