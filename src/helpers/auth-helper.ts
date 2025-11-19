import crypto from "crypto";
import argon2 from "argon2";
import {
  NEXT_OTP_DELAY,
  OTP_CODE_EXPIRY,
  OTP_CODE_LENGTH,
  OTP_MAX_ATTEMPTS,
  OTP_SPAM_LOCK_TIME,
  OTP_TYPES,
} from "#constants/auth-constants.js";
import { logger } from "#utils/logger.js";
import redisClient from "#configs/redis.js";
import { STATUS_CODES } from "#constants/status-codes.js";

export type OTP_TYPE = (typeof OTP_TYPES)[number];
export const hashPassword = async (password: string) => argon2.hash(password);

export const verifyPassword = async (
  password: string,
  hashedPassword: string
) => argon2.verify(hashedPassword, password);

export const generateOtp = (length: number, ttlMinutes: number) => {
  const code = String(
    Math.floor(Math.random() * Math.pow(10, length))
  ).padStart(length, "0");
  const hashCode = crypto
    .createHash("sha256")
    .update(String(code))
    .digest("hex");
  const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000);
  return { code, hashCode, expiresAt };
};

export const verifyOtpCode = ({
  code,
  hashCode,
}: {
  code: string;
  hashCode: string;
}) => {
  const hashedCode = crypto
    .createHash("sha256")
    .update(String(code))
    .digest("hex");
  return hashedCode === hashCode;
};

export const generateRandomToken = (id: string) => {
  const token = crypto.createHash("sha256").update(String(id)).digest("hex");

  const hashedToken = crypto
    .createHash("sha256")
    .update(String(token))
    .digest("hex");

  return { token, hashedToken };
};

export const buildRedisKey = (
  email: string,
  otpType: OTP_TYPE,
  suffix: string
) => `otp:${suffix}:${email}:${otpType}`;

export const checkOtpRestrictions = async (
  email: string,
  otpType: OTP_TYPE
) => {
  const lockKey = buildRedisKey(email, otpType, "lock");
  const spamKey = buildRedisKey(email, otpType, "spam");
  const nextAllowedKey = buildRedisKey(email, otpType, "next");

  if (await redisClient.get(lockKey)) {
    return {
      status: STATUS_CODES.TOO_MANY_REQUESTS,
      message: "Account is locked due to too many failed attempts.",
    };
  }

  if (await redisClient.get(spamKey)) {
    return {
      status: STATUS_CODES.TOO_MANY_REQUESTS,
      message: "Too many OTP requests. Please try again later.",
    };
  }

  if (await redisClient.get(nextAllowedKey)) {
    return {
      status: STATUS_CODES.TOO_MANY_REQUESTS,
      message: `Please wait ${NEXT_OTP_DELAY / 1000} seconds before requesting another OTP.`,
    };
  }

  return null;
};

export const sendOtp = async (email: string, otpType: OTP_TYPE) => {
  const otp = generateOtp(OTP_CODE_LENGTH, OTP_CODE_EXPIRY / 1000);
  logger.info(`Generated OTP:  ${otp.code}`);

  if (otpType === "email-verification") {
    const html = `<p>OTP: ${otp.code}</p>`;
    // await sendEmail(email, `OTP for email verification`, html);
  }
  if (otpType === "password-reset") {
    const html = `<p>OTP: ${otp.code}</p>`;
    // await sendEmail(email, `OTP for password reset`, html);
  }

  const otpHashCodeKey = buildRedisKey(email, otpType, "hash_code");
  const nextOtpAllowedAtKey = buildRedisKey(email, otpType, "next_allowed_at");

  await redisClient.set(otpHashCodeKey, otp.hashCode, {
    EX: OTP_CODE_EXPIRY / 1000,
    NX: true,
  });

  await redisClient.set(nextOtpAllowedAtKey, "true", {
    EX: NEXT_OTP_DELAY / 1000,
    NX: true,
  });
};

export const trackOtpRequests = async (email: string, otpType: OTP_TYPE) => {
  const countKey = buildRedisKey(email, otpType, "count");
  const lockKey = buildRedisKey(email, otpType, "lock");
  const currentCount = parseInt((await redisClient.get(countKey)) || "0", 10);

  if (currentCount >= OTP_MAX_ATTEMPTS - 1) {
    await redisClient.set(lockKey, "true", { EX: OTP_SPAM_LOCK_TIME });
    return {
      status: STATUS_CODES.TOO_MANY_REQUESTS,
      message: `Too many OTP requests for ${otpType}. Try again later.`,
    };
  }

  await redisClient
    .multi()
    .incr(countKey)
    .expire(countKey, OTP_SPAM_LOCK_TIME)
    .exec();
  return null;
};

export const verifyRedisOtp = async (
  email: string,
  otpType: OTP_TYPE,
  otpCode: string
) => {
  const otpHashCodeKey = buildRedisKey(email, otpType, "hash_code");
  const failedAttemptKey = buildRedisKey(email, otpType, "failed_attempts");
  const lockKey = buildRedisKey(email, otpType, "lock");
  const countKey = buildRedisKey(email, otpType, "count");

  const storeHashOtp = await redisClient.get(otpHashCodeKey);

  if (!storeHashOtp) {
    return {
      status: STATUS_CODES.BAD_REQUEST,
      message: "Invalid or expired OTP.",
      success: false,
    };
  }

  const otpHashCode = crypto
    .createHash("sha256")
    .update(String(otpCode))
    .digest("hex");

  // ✅ If OTP matches
  if (otpHashCode === storeHashOtp) {
    // Clean up Redis keys
    await redisClient.del(otpHashCodeKey);
    await redisClient.del(failedAttemptKey);
    await redisClient.del(countKey);

    return {
      status: STATUS_CODES.OK,
      message: "OTP verified successfully.",
      success: true,
    };
  }

  const failedAttempts = parseInt(
    (await redisClient.get(failedAttemptKey)) || "0",
    10
  );

  if (failedAttempts + 1 >= OTP_MAX_ATTEMPTS - 1) {
    await redisClient.set(lockKey, "true", {
      EX: OTP_SPAM_LOCK_TIME,
    });
    await redisClient.del(otpHashCodeKey);
    await redisClient.del(failedAttemptKey);

    return {
      status: STATUS_CODES.TOO_MANY_REQUESTS,
      message: `Too many failed OTP attempts for ${otpType}. Try again later.`,
      success: false,
    };
  }

  await redisClient.incr(failedAttemptKey);

  return {
    status: STATUS_CODES.BAD_REQUEST,
    message: "Invalid OTP. Please try again.",
    success: false,
  };
};
