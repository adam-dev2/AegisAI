import winston from "winston";

const { combine, timestamp, printf, colorize, errors } = winston.format;

const logFormat = printf(({ level, message, timestamp, stack }) => {
  return stack
    ? `${timestamp} [${level}]: ${stack}`
    : `${timestamp} [${level}]: ${message}`;
});

export const logger = winston.createLogger({
  level: "info",
  format: combine(
    errors({ stack: true }),
    timestamp(),
    logFormat
  ),
  transports: [
    new winston.transports.Console({
      format: combine(colorize(), logFormat),
    }),
    new winston.transports.File({ filename: "logs/error.log", level: "error"}),
    new winston.transports.File({ filename: "logs/combined.log" }),
  ],
});