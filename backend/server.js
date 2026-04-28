const app = require('./app');
const { connect: connectDb } = require('./config/db');
const env = require('./config/env');
const logger = require('./shared/logger');

const start = async () => {
  await connectDb();
  app.listen(env.PORT, () => {
    logger.info(`Secure Vault API running on port ${env.PORT} [${env.NODE_ENV}]`);
  });
};

process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception', { error: err.message, stack: err.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled Rejection', { reason });
  process.exit(1);
});

start();
