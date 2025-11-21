import redisClient from "#configs/redis.js";
import app from "./app";
import { connectDB } from "./configs/db";
import { env } from "./configs/env";
import { logger } from "./utils/logger";

connectDB()
  .then(() => {
    redisClient
      .connect()
      .then(() => {
        logger.info("✅ Redis Connection Success");
        app.listen(env.PORT, () => {
          logger.info(`✅ Server is running on http://localhost:${env.PORT}`);
        });
      })
      .catch((error) => {
        logger.error("❌ Redis Connection Failed:", error);
        process.exit(1);
      });
  })
  .catch((error) => {
    logger.error("❌ MongoDB Connection Failed:", error);
    process.exit(1);
  });
