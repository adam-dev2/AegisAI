import { logger } from '../lib/logger.js';
import { DATABASE_URL } from './env.js';

if(!DATABASE_URL) {
    logger.error(`Can't read DB url`)
}

