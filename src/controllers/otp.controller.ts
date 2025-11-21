import { ApiResponse } from "#utils/api-response.js";
import { NextFunction, Request, Response } from "express";

import { AsyncHandler } from "#utils/async-handler.js";
import { RequestOtpSchema, VerifyOtpSchema } from "#validators/auth.js";
import z from "zod";
import { User } from "#models/user.model.js";
import { RESET_PASSWORD_TOKEN_EXPIRY } from "#constants/auth-constants.js";
import {
  checkOtpRestrictions,
  generateRandomToken,
  sendOtp,
  trackOtpRequests,
  verifyRedisOtp,
} from "#helpers/auth-helper.js";
import {
  generateAccessToken,
  generateRefreshToken,
} from "#helpers/jwt-helper.js";
import { AuthenticatedRequest } from "../types/user";
import { COOKIE_OPTIONS, setAuthCookies } from "#helpers/cookie-helper.js";

//? SEND OTP
export const requestOtp = AsyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { success, data, error } = RequestOtpSchema.safeParse(req.body);

    if (!success) {
      return ApiResponse.BadRequest(
        res,
        "Invalid data received",
        z.flattenError(error).fieldErrors
      );
    }

    const { email, otpType } = data;
    if (!email || !otpType) {
      return ApiResponse.BadRequest(res, "Email and otpType are required");
    }

    const user = await User.findOne({ email });
    if (!user) {
      return ApiResponse.NotFound(res, "User not found");
    }

    if (user.lockUntil && new Date(user.lockUntil) > new Date()) {
      return ApiResponse.BadRequest(
        res,
        `Your account has been locked. Please try again after ${Math.ceil(
          (user.lockUntil.getTime() - Date.now()) / (1000 * 60)
        )} minutes.`
      );
    }

    const restriction = await checkOtpRestrictions(email, otpType);
    if (restriction)
      return ApiResponse.Error(res, restriction.message, restriction.status);

    const tracking = await trackOtpRequests(email, otpType);
    if (tracking)
      return ApiResponse.Error(res, tracking.message, tracking.status);

    await sendOtp(email, otpType);

    return ApiResponse.Success(res, "OTP sent successfully");
  }
);

//? VERIFY OTP
export const verifyOtp = AsyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const { success, data, error } = VerifyOtpSchema.safeParse(req.body);

    if (!success) {
      return ApiResponse.BadRequest(
        res,
        "Invalid data received",
        z.flattenError(error).fieldErrors
      );
    }

    const { email, otpCode, otpType } = data;
    if (!email || !otpCode) {
      return ApiResponse.BadRequest(res, "Email and otpCode are required");
    }

    const user = await User.findOne({ email });
    if (!user) {
      return ApiResponse.NotFound(res, "User not found");
    }

    if (user.lockUntil && new Date(user.lockUntil) > new Date()) {
      return ApiResponse.BadRequest(
        res,
        `Your account has been locked. Please try again after ${Math.ceil(
          (user.lockUntil.getTime() - Date.now()) / (1000 * 60)
        )} minutes.`
      );
    }

    const tracking = await trackOtpRequests(email, otpType);
    if (tracking)
      return ApiResponse.Error(res, tracking.message, tracking.status);

    const verification = await verifyRedisOtp(email, otpType, otpCode);
    if (!verification.success)
      return ApiResponse.Error(res, verification.message, verification.status);

    if (otpType === "email-verification") {
      if (!user.isEmailVerified) {
        user.isEmailVerified = true;
        await user.save();
      }

      const payload = {
        _id: user._id.toString(),
      };
      const accessToken = generateAccessToken(payload);
      const refreshToken = generateRefreshToken(user._id.toString());
      setAuthCookies(res, accessToken, refreshToken);

      await User.updateOne(
        { _id: user._id },
        { $set: { lastLogin: new Date(), failedLoginAttempts: 0 } }
      );

      await User.updateOne({ _id: user._id }, { $unset: { lockUntil: 1 } });

      return ApiResponse.Success(
        res,
        "OTP verified and user logged in successfully"
      );
    }

    if (otpType === "password-reset") {
      const { hashedToken: hashedResetPasswordToken } = generateRandomToken(
        user._id.toString()
      );
      const resetPasswordExpiry = new Date(
        Date.now() + RESET_PASSWORD_TOKEN_EXPIRY
      );

      if (
        req.cookies?.hashedResetPasswordToken ||
        req.cookies?.resetPasswordExpiry
      ) {
        res.clearCookie("hashedResetPasswordToken");
        res.clearCookie("resetPasswordExpiry");
      }

      res.cookie(
        "hashedResetPasswordToken",
        hashedResetPasswordToken,
        COOKIE_OPTIONS
      );
      res.cookie(
        "resetPasswordExpiry",
        resetPasswordExpiry.toISOString(),
        COOKIE_OPTIONS
      );

      return ApiResponse.Success(res, "OTP verified successfully");
    }

    return ApiResponse.Success(res, "OTP verified successfully");
  }
);
