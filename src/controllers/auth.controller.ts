import {
  LOCK_TIME_MS,
  LOGIN_MAX_ATTEMPTS,
  NEXT_OTP_DELAY,
  OTP_CODE_EXPIRY,
  OTP_CODE_LENGTH,
  REACTIVATION_AVAILABLE_AT,
} from "#constants/auth-constants.js";
import {
  checkOtpRestrictions,
  generateOtp,
  generateRandomToken,
  hashPassword,
  sendOtp,
  trackOtpRequests,
  verifyPassword,
} from "#helpers/auth-helper.js";
import { setAuthCookies } from "#helpers/cookie-helper.js";
import {
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
} from "#helpers/jwt-helper.js";
import cloudinary from "#lib/cloudinary.js";
import { sendEmail } from "#lib/node-mailer.js";
import { User } from "#models/user.model.js";
import { AuthenticatedRequest } from "#types/user.js";
import { ApiResponse } from "#utils/api-response.js";
import { AsyncHandler } from "#utils/async-handler.js";
import { logger } from "#utils/logger.js";
import {
  ChangePasswordSchema,
  DeleteAccountSchema,
  GoogleSigninSchema,
  ResetPasswordSchema,
  SigninSchema,
  SignupSchema,
  UpdateProfileSchema,
} from "#validators/auth.js";
import { NextFunction, Request, Response } from "express";
import z from "zod";

//? SIGNUP USER
export const signupUser = AsyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { success, data, error } = SignupSchema.safeParse(req.body);
    if (!success) {
      return ApiResponse.BadRequest(
        res,
        "Invalid data received!",
        z.flattenError(error).fieldErrors
      );
    }

    const { name, email, password } = data;
    if (!name || !email || !password) {
      return ApiResponse.BadRequest(
        res,
        "Name, email and password are required"
      );
    }

    const existingUser = await User.findOne({ email }).select("+password");

    if (existingUser) {
      return ApiResponse.Conflict(res, "User with this email already exists");
    }

    const hashedPassword = await hashPassword(password);

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
    });

    if (!newUser) {
      return ApiResponse.BadRequest(res, "Failed to register user!");
    }

    await newUser.save();

    return ApiResponse.Created(res, "User created successfully", {
      name: newUser.name,
      email: newUser.email,
      role: newUser.role,
    });
  }
);

//? SIGNIN USER
export const signinUser = AsyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { success, data, error } = SigninSchema.safeParse(req.body);

    if (!success) {
      return ApiResponse.BadRequest(
        res,
        "Invalid data received!",
        z.flattenError(error).fieldErrors
      );
    }

    const { email, password } = data;
    if (!email || !password) {
      return ApiResponse.BadRequest(res, "Email and password are required");
    }

    const user = await User.findOne({ email }).select("+password");
    if (!user) {
      return ApiResponse.BadRequest(res, "Invalid credentials!");
    }

    if (user.lockUntil && new Date(user.lockUntil) > new Date()) {
      return ApiResponse.BadRequest(
        res,
        `Your account has been locked. Please try again after ${Math.ceil(
          (user.lockUntil.getTime() - Date.now()) / (1000 * 60)
        )} minutes.`
      );
    }

    if (user?.isDeleted || user?.deletedAt) {
      return ApiResponse.BadRequest(res, "Your account has been deactivated.");
    }

    const isPasswordValid = await verifyPassword(password, user.password);

    if (!isPasswordValid) {
      let lockUntil = null;

      let newAttempts = user.failedLoginAttempts + 1;

      if (newAttempts >= LOGIN_MAX_ATTEMPTS) {
        lockUntil = new Date(Date.now() + LOCK_TIME_MS);
      }

      await User.updateOne(
        { _id: user._id },
        { $set: { failedLoginAttempts: newAttempts, lockUntil } }
      );
      return ApiResponse.BadRequest(res, "Invalid credentials!");
    }

    await User.updateOne(
      { _id: user._id },
      { $set: { failedLoginAttempts: 0, lockUntil: null } }
    );

    const otpType = "email-verification";

    const restriction = await checkOtpRestrictions(email, otpType);
    if (restriction)
      return ApiResponse.Error(res, restriction.message, restriction.status);

    const tracking = await trackOtpRequests(email, otpType);
    if (tracking)
      return ApiResponse.Error(res, tracking.message, tracking.status);

    await sendOtp(email, otpType);

    return ApiResponse.Ok(res, `OTP sent to ${email}`);
  }
);

//? GOOGLE SIGNIN
export const googleSignin = AsyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { success, data, error } = GoogleSigninSchema.safeParse(req.body);

    if (!success) {
      return ApiResponse.BadRequest(
        res,
        "Invalid data received!",
        z.flattenError(error).fieldErrors
      );
    }

    const { name, email, provider, providerId, avatar } = data;

    const user = await User.findOne({ email });

    if (user) {
      return ApiResponse.Success(res, "User signed in successfully!", {
        name: user.name,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        lastLoginAt: user.lastLoginAt,
        lockUntil: user.lockUntil,
      });
    } else {
      const newUser = new User({
        name,
        email,
        provider,
        providerId,
        avatar,
      });
      await newUser.save();
      return ApiResponse.Success(res, "User signed in successfully!", {
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
        isEmailVerified: newUser.isEmailVerified,
        lastLoginAt: newUser.lastLoginAt,
        lockUntil: newUser.lockUntil,
      });
    }
  }
);

//? GET USER PROFILE
export const getUserProfile = AsyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const userId = req.user?._id.toString();
    if (!userId) {
      return ApiResponse.NotFound(res, "User not found");
    }
    const user = await User.findById(userId);
    if (!user) {
      return ApiResponse.NotFound(res, "User not found");
    }
    if (user?.isDeleted || user?.deletedAt) {
      return ApiResponse.BadRequest(res, "Your account has been deactivated.");
    }

    if (user.lockUntil && new Date(user.lockUntil) > new Date()) {
      return ApiResponse.BadRequest(
        res,
        `Your account has been locked. Please try again after ${Math.ceil(
          (user.lockUntil.getTime() - Date.now()) / (1000 * 60)
        )} minutes.`
      );
    }

    return ApiResponse.Success(res, "User profile fetched successfully!", {
      name: user.name,
      email: user.email,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      lastLoginAt: user.lastLoginAt,
      lockUntil: user.lockUntil,
    });
  }
);

//? REFRESH TOKENS
export const refreshToken = AsyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const accessToken = req.cookies?.accessToken;
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
      return ApiResponse.Unauthorized(res, "Unauthorized, Please login first.");
    }

    const userId = verifyRefreshToken(refreshToken).userId;

    if (!userId) {
      return ApiResponse.Unauthorized(res, "Unauthorized, Please login first.");
    }

    if (accessToken) {
      const decoded = verifyAccessToken(accessToken);
      if (decoded._id !== userId) {
        return ApiResponse.Unauthorized(
          res,
          "Unauthorized, Please login first."
        );
      }
    }

    const newAccessToken = generateAccessToken({ _id: userId });
    const newRefreshToken = generateRefreshToken(userId);
    setAuthCookies(res, newAccessToken, newRefreshToken);
    return ApiResponse.Success(res, "Tokens refreshed successfully!");
  }
);

//? RESET PASSWORD
export const resetPassword = AsyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const { success, data, error } = ResetPasswordSchema.safeParse(req.body);

    if (!success) {
      return ApiResponse.BadRequest(
        res,
        "Invalid data received",
        z.flattenError(error).fieldErrors
      );
    }

    const { newPassword, email } = data;

    const hashedResetPasswordToken = req.cookies?.hashedResetPasswordToken;
    const resetPasswordExpiry = req.cookies?.resetPasswordExpiry;

    if (!hashedResetPasswordToken) {
      return ApiResponse.BadRequest(res, "Reset password token not found");
    }

    if (!resetPasswordExpiry || new Date(resetPasswordExpiry) < new Date()) {
      return ApiResponse.BadRequest(
        res,
        "Reset password token expired. Please try again."
      );
    }

    const user = await User.findOne({ email }).select("+password");

    if (!user) {
      return ApiResponse.NotFound(res, "User not found");
    }

    if (user?.isDeleted || user?.deletedAt) {
      return ApiResponse.BadRequest(res, "Your account has been deactivated.");
    }

    if (user.lockUntil && new Date(user.lockUntil) > new Date()) {
      return ApiResponse.BadRequest(
        res,
        `Your account has been locked. Please try again after ${Math.ceil(
          (user.lockUntil.getTime() - Date.now()) / (1000 * 60)
        )} minutes.`
      );
    }

    if (!user.isEmailVerified) {
      return ApiResponse.BadRequest(res, "Email not verified");
    }

    const { hashedToken } = generateRandomToken(user._id.toString());

    if (hashedResetPasswordToken !== hashedToken) {
      return ApiResponse.BadRequest(res, "Invalid reset password token");
    }

    const oldPassword = user.password;

    const isOldPassword = await verifyPassword(
      newPassword,
      oldPassword as string
    );

    if (isOldPassword) {
      return ApiResponse.BadRequest(res, "New password cannot be same as old");
    }

    const hashedNewPassword = await hashPassword(newPassword);

    user.password = hashedNewPassword;
    await user.save();

    res.clearCookie("hashedResetPasswordToken");
    res.clearCookie("resetPasswordExpiry");
    return ApiResponse.Ok(res, "Password reset successfully!");
  }
);

//? CHANGE PASSWORD
export const changePassword = AsyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const { success, data, error } = ChangePasswordSchema.safeParse(req.body);

    if (!success) {
      return ApiResponse.BadRequest(
        res,
        "Invalid data received",
        z.flattenError(error).fieldErrors
      );
    }

    const { oldPassword, newPassword } = data;

    if (!oldPassword || !newPassword) {
      return ApiResponse.BadRequest(
        res,
        "Old password and new password are required"
      );
    }
    const user = await User.findById(req?.user?._id).select("+password");

    if (!user) {
      return ApiResponse.NotFound(res, "User not found");
    }

    if (user?.isDeleted || user?.deletedAt) {
      return ApiResponse.BadRequest(res, "Your account has been deactivated.");
    }

    if (user.lockUntil && new Date(user.lockUntil) > new Date()) {
      return ApiResponse.BadRequest(
        res,
        `Your account has been locked. Please try again after ${Math.ceil(
          (user.lockUntil.getTime() - Date.now()) / (1000 * 60)
        )} minutes.`
      );
    }

    if (user?.isEmailVerified === false) {
      return ApiResponse.BadRequest(res, "Please verify your email first");
    }

    const isOldPassword = await verifyPassword(newPassword, user.password);

    if (isOldPassword) {
      return ApiResponse.BadRequest(res, "New password cannot be same as old");
    }

    const hashedNewPassword = await hashPassword(newPassword);

    user.password = hashedNewPassword;
    await user.save();
    return ApiResponse.Ok(res, "Password changed successfully!");
  }
);

//? LOGOUT
export const logout = AsyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const user = await User.findById(req?.user?._id);

    if (!user) {
      return ApiResponse.NotFound(res, "User not found");
    }

    if (user?.isDeleted || user?.deletedAt) {
      return ApiResponse.BadRequest(res, "Your account has been deactivated.");
    }

    if (user.lockUntil && new Date(user.lockUntil) > new Date()) {
      return ApiResponse.BadRequest(
        res,
        `Your account has been locked. Please try again after ${Math.ceil(
          (user.lockUntil.getTime() - Date.now()) / (1000 * 60)
        )} minutes.`
      );
    }

    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    return ApiResponse.Success(res, "User logged out successfully!");
  }
);

//? UPDATE PROFILE
export const updateProfile = AsyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const { success, data, error } = UpdateProfileSchema.safeParse(req.body);

    if (!success) {
      return ApiResponse.BadRequest(
        res,
        "Invalid data received",
        z.flattenError(error).fieldErrors
      );
    }

    const { name, role } = data;

    const user = await User.findById(req?.user?._id);

    if (!user) {
      return ApiResponse.NotFound(res, "User not found");
    }

    if (user?.isDeleted || user?.deletedAt) {
      return ApiResponse.BadRequest(res, "Your account has been deactivated.");
    }

    if (user.lockUntil && new Date(user.lockUntil) > new Date()) {
      return ApiResponse.BadRequest(
        res,
        `Your account has been locked. Please try again after ${Math.ceil(
          (user.lockUntil.getTime() - Date.now()) / (1000 * 60)
        )} minutes.`
      );
    }

    if (user?.isEmailVerified === false) {
      return ApiResponse.BadRequest(res, "Please verify your email first");
    }

    if (req?.file && user?.avatar?.public_id) {
      await cloudinary.uploader.destroy(user?.avatar?.public_id);
    }

    if (req?.file && user?.avatar) {
      user.avatar = {
        public_id: req.file
          ? req.file.filename
          : (user?.avatar?.public_id as string),
        url: req.file ? req.file.path : (user.avatar.url as string),
        size: req.file ? req.file.size : (user.avatar.size as number),
      };
    }

    if (name) {
      user.name = name;
    }

    if (role) {
      user.role = role;
    }

    await user.save();

    return ApiResponse.Success(res, "Profile updated successfully!");
  }
);

//? DELETE/DEACTIVATE ACCOUNT
export const deleteAccount = AsyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const { success, data, error } = DeleteAccountSchema.safeParse(req.body);

    if (!success) {
      return ApiResponse.BadRequest(
        res,
        "Invalid data received",
        z.flattenError(error).fieldErrors
      );
    }

    const { userId, type, password } = data;

    if (!userId || !type) {
      return ApiResponse.BadRequest(res, "Your user id and type are required");
    }

    if (!password) {
      return ApiResponse.BadRequest(res, "Your current password is required");
    }

    if (userId !== req?.user?._id) {
      return ApiResponse.BadRequest(
        res,
        "You are not authorized to delete this account."
      );
    }

    const user = await User.findById(req?.user?._id).select("+password");
    if (!user) {
      return ApiResponse.NotFound(res, "User not found");
    }

    if (user?.isDeleted || user?.deletedAt) {
      return ApiResponse.BadRequest(
        res,
        "Your account has already been deactivated."
      );
    }

    if (user.lockUntil && new Date(user.lockUntil) > new Date()) {
      return ApiResponse.BadRequest(
        res,
        `Your account has been locked. Please try again after ${Math.ceil(
          (user.lockUntil.getTime() - Date.now()) / (1000 * 60)
        )} minutes.`
      );
    }

    if (user?.isEmailVerified === false) {
      return ApiResponse.BadRequest(res, "Please verify your email first");
    }

    const isPasswordValid = await verifyPassword(password, user.password);
    if (!isPasswordValid) {
      return ApiResponse.BadRequest(res, "Invalid password");
    }

    if (type === "soft") {
      user.isDeleted = true;
      user.deletedAt = new Date();
      user.reActivateAvailableAt = new Date(
        Date.now() + REACTIVATION_AVAILABLE_AT
      );
      await user.save();
    } else if (type === "hard") {
      if (user?.avatar?.public_id) {
        await cloudinary.uploader.destroy(user?.avatar?.public_id);
      }

      const result = await User.findByIdAndDelete(req?.user?._id);
      console.log({ result });
      if (!result) {
        return ApiResponse.NotFound(res, "User not found");
      }
      await user.save();
    }

    return ApiResponse.Success(
      res,
      `Account ${type === "soft" ? "deactivated" : "deleted"} successfully!`
    );
  }
);

//? REACTIVATE ACCOUNT
export const reactivateAccount = AsyncHandler(
  async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const user = await User.findById(req?.user?._id);
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

    if (user?.isEmailVerified === false) {
      return ApiResponse.BadRequest(res, "Please verify your email first");
    }

    if (!user?.isDeleted || !user?.deletedAt) {
      return ApiResponse.BadRequest(res, "Your account is already active.");
    }

    if (
      user?.reActivateAvailableAt &&
      new Date(user?.reActivateAvailableAt) > new Date()
    ) {
      return ApiResponse.BadRequest(
        res,
        `You can reactivate your account after ${Math.ceil(
          (user?.reActivateAvailableAt.getTime() - Date.now()) /
            (1000 * 60 * 60 * 24)
        )} days.`
      );
    }

    if (user?.isDeleted || user?.deletedAt) {
      user.isDeleted = false;
      await user.save();
      await User.findOneAndUpdate(
        { _id: req?.user?._id },
        { $unset: { reActivateAvailableAt: "", deletedAt: "" } }
      );
      return ApiResponse.Success(res, "Account reactivated successfully!");
    }

    return ApiResponse.BadRequest(res, "Your account is already active.");
  }
);
