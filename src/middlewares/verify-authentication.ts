import { NextFunction, Request, Response } from "express";
import {
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
} from "#helpers/jwt-helper.js";
import { UserRequest } from "#types/user.js";
import { ApiResponse } from "#utils/api-response.js";
import { User } from "#models/user.model.js";
import { setAuthCookies } from "#helpers/cookie-helper.js";
import { logger } from "#utils/logger.js";

export async function isAuthenticated(
  req: UserRequest,
  res: Response,
  next: NextFunction
) {
  const accessToken = req.cookies?.accessToken;
  const refreshToken = req.cookies?.refreshToken;

  try {
    if (accessToken) {
      const decoded = verifyAccessToken(accessToken);
      req.user = decoded;
      return next();
    }
  } catch (err) {
    console.log(err);
  }

  if (!refreshToken) {
    return ApiResponse.Unauthorized(res, "Unauthorized, Please login first.");
  }

  try {
    const decodedRefresh = verifyRefreshToken(refreshToken);

    const userInDb = await User.findOne({
      _id: decodedRefresh.userId,
    });

    if (!userInDb) {
      return ApiResponse.NotFound(res, "Unauthorized, Please login first.");
    }

    const newAccessToken = generateAccessToken({
      _id: userInDb._id.toString(),
    });
    const newRefreshToken = generateRefreshToken(decodedRefresh.userId);

    setAuthCookies(res, newAccessToken, newRefreshToken);

    req.user = {
      _id: decodedRefresh.userId,
    };

    return next();
  } catch (err: any) {
    logger.error(err?.message);
    return ApiResponse.Unauthorized(res, "Unauthorized, Please login first.");
  }
}
