import { Request } from "express";
import mongoose from "mongoose";

export interface AuthenticatedRequest extends Request {
  user?: {
    _id: string | mongoose.Types.ObjectId;
  };
}

export interface UserRequest extends Request {
  user?: {
    _id?: string | mongoose.Types.ObjectId | undefined;
  };
}
