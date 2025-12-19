import type { Request, Response } from "express";
import { AuthService } from "../services/auth.service.js";
import { sendError, sendSuccess } from "../utils/responseHandler.js";

export class AuthController {
  static async register(req: Request, res: Response) {
    try {
      const { name, email, password } = req.body;

      const result = await AuthService.register({ name, email, password });
      return sendSuccess(
        res,
        result,
        "OTP sent successfully, please verify",
        200
      );
    } catch (err: any) {
      return sendError(
        res,
        err.message,
        err.status || 500,
        err.field ? { [err.field]: err.message } : undefined
      );
    }
  }

  static async verifyUser(req: Request, res: Response) {
    try {
      const { otp, token } = req.body;
      const user = await AuthService.verifyUser({
        otp,
        token,
      });

      return sendSuccess(res, user, "User verified successfully", 200);
    } catch (err: any) {
      return sendError(
        res,
        err.message,
        err.status || 500,
        err.field ? { [err.field]: err.message } : undefined
      );
    }
  }

  static async login(req: Request, res: Response) {
    try {
      const data = await AuthService.login({
        email: req.body.email,
        password: req.body.password,
        ip: req.ip,
        userAgent: req.headers["user-agent"],
        device_id: req.body.device_id,
      });
      return sendSuccess(res, data, "Login Successfull", 200);
    } catch (err: any) {
      return sendError(
        res,
        err.message,
        err.status || 500,
        err.field ? { [err.field]: err.message } : undefined
      );
    }
  }

  static async refresh(req: Request, res: Response) {
    try {
      const { refresh_token } = req.body;
      const data = await AuthService.refreshToken(refresh_token);
      return sendSuccess(res, data, "Access token refreshed");
    } catch (err: any) {
      return sendError(res, err.message, err.status || 500);
    }
  }

  static async me(req: Request, res: Response) {
    try {
      const userId = (req as any)?.userId; // from Auth Middleware
      const user = await AuthService.me(userId);

      return sendSuccess(res, user, "User fetched successfully");
    } catch (err: any) {
      return sendError(res, err.message, err.status || 500);
    }
  }

  static async forgotPassword(req: Request, res: Response) {
    try {
      const { email } = req.body;
      const result = await AuthService.forgotPassword(email);
      return sendSuccess(res, result, result.message);
    } catch (err: any) {
      return sendError(res, err.message, err.status || 500);
    }
  }

  static async resetPassword(req: Request, res: Response) {
    try {
      const { otp, token, new_password } = req.body;

      const result = await AuthService.resetPassword({
        otp,
        token,
        new_password,
      });

      return sendSuccess(res, result, result.message);
    } catch (err: any) {
      return sendError(res, err.message, err.status || 500);
    }
  }

  static async changePassword(req: Request, res: Response) {
    try {
      const userId = (req as any)?.userId; // from Auth Middleware
      const { old_password, new_password } = req.body;
      if (!old_password) {
        return sendError(res, "Old password required", 400);
      }
      if (!new_password) {
        return sendError(res, "New password required", 400);
      }

      const result = await AuthService.changePassword({
        userId: userId,
        old_password,
        new_password,
      });

      return sendSuccess(res, result, result.message);
    } catch (err: any) {
      return sendError(res, err.message, err.status || 500);
    }
  }
}
