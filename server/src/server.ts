import app from "./app.js";
import 'dotenv/config'
import { PORT } from "./config/env.js";
import { logger } from "./lib/logger.js";
import { testDB } from "./config/db.js";

testDB();

app.listen(PORT,() => {
    logger.info(`Server is running on port ${PORT}`)
})  