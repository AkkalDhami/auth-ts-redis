import express, { type Application } from "express";
import "dotenv/config";
import cookieParser from "cookie-parser";
import morgan from "morgan";

import { errorHandler } from "#middlewares/error-handler.js";
import { ApiResponse } from "#utils/api-response.js";

import Routes from "#routes/index.js";

const app: Application = express();

//*  Middlewares
app.use(express.json());
app.use(cookieParser());

app.use(morgan(process.env.NODE_ENV === "development" ? "dev" : "combined"));

//*  Routes
app.use("/api", Routes);

app.get("/", (req, res) => {
  return ApiResponse.Ok(res, "Welcome to the API");
});

app.use(errorHandler);

export default app;
