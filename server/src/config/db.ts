import pkg from 'pg';
import { logger } from '../lib/logger.js';
import { DATABASE_URL } from './env.js';

const { Pool } = pkg;

if (!DATABASE_URL) {
  logger.error("DATABASE_URL is missing");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, 
  },
});

export const testDB = async () => {
  try {
    const res = await pool.query('SELECT version()');
    logger.info(`DB connected: ${res.rows[0].version}`);
  } catch (err) {
    logger.error('DB Connection Error', err);
  }
};

export default pool;