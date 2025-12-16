// ------------------------------------------------------------------------------------------------------------------------------
//                                                    REQUIRE AUTH MIDDLEWARE
//                                            Verifies JWT token and protects routes
// ------------------------------------------------------------------------------------------------------------------------------

import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { config } from "../config/index.js";
import { sendError } from "../utils/responseHandler.js";

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer"))
    return sendError(res, "MISSING TOKEN", 401);

  const token = auth.split(" ")[1] ?? "";
  try {
    const payload = jwt.verify(token, config.jwtSecret) as any;

    (req as any).userId = payload.id;
    next();
  } catch (err) {
    return sendError(res, "INVALID TOKEN", 401);
  }
}
