import {
  changePassword,
  deleteAccount,
  getUserProfile,
  googleSignin,
  logout,
  reactivateAccount,
  refreshToken,
  resetPassword,
  signinUser,
  signupUser,
  updateProfile,
} from "#controllers/auth.controller.js";
import { requestOtp, verifyOtp } from "#controllers/otp.controller.js";
import {
  changePasswordLimiter,
  deleteAccountLimiter,
  otpRequestLimiter,
  otpVerificationLimiter,
  resetPasswordLimiter,
  signinLimiter,
  signupLimiter,
} from "#lib/rate-limiter.js";
import upload from "#middlewares/upload-file.js";
import { isAuthenticated } from "#middlewares/verify-authentication.js";
import { Router } from "express";

const router = Router();

router.get("/profile", isAuthenticated, getUserProfile);

router.post("/signup", signupLimiter, signupUser);
router.post("/signin", signinLimiter, signinUser);

router.post("/request-otp", otpRequestLimiter, requestOtp);
router.post("/verify-otp", otpVerificationLimiter, verifyOtp);

router.post(
  "/reset-password",
  isAuthenticated,
  resetPasswordLimiter,
  resetPassword
);
router.post(
  "/change-password",
  isAuthenticated,
  changePasswordLimiter,
  changePassword
);

router.patch(
  "/update-profile",
  upload.single("avatar"),
  isAuthenticated,
  updateProfile
);

router.post("/google-signin", googleSignin);

router.post("/refresh-token", refreshToken);
router.post("/logout", isAuthenticated, logout);

router.delete(
  "/delete-account",
  isAuthenticated,
  deleteAccountLimiter,
  deleteAccount
);
router.put("/reactivate-account", isAuthenticated, reactivateAccount);

export default router;
