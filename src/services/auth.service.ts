import bcrypt from "bcryptjs";
import { config } from "../config/index.js";
import { User } from "../models/User.js";
import OTPService from "../utils/otpService.js";
import { Token } from "../utils/token.js";
import { RefreshToken } from "../models/RefreshToken.js";

export class AuthService {
  static async register({
    name,
    email,
    password,
  }: {
    name: string;
    email: string;
    password: string;
  }) {
    const existingUser = await User.findOne({ email });

    // If user exists and verified = true → stop
    if (existingUser && existingUser.verified)
      throw { status: 409, message: "User already exists", field: "email" };

    // If user exists but NOT verified → resend OTP
    if (existingUser && !existingUser.verified) {
      const { token } = await OTPService.createAndSendOtp(email);
      return {
        status: 200,
        message: "OTP resent to your email",
        token,
      };
    }

    // User does NOT exist => create new pending user
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name,
      email,
      password: hashedPassword,
      verified: false,
    });

    await user.save();

    const { token } = await OTPService.createAndSendOtp(email);

    return {
      status: 201,
      message: "User created, OTP sent",
      token,
    };
  }

  static async login({
    email,
    password,
    userAgent,
    ip,
    device_id,
  }: {
    email: string;
    password: string;
    userAgent: any;
    ip: any;
    device_id: string;
  }) {
    if (!email)
      throw { status: 400, message: "Email Required", field: "email" };
    if (!device_id)
      throw { status: 400, message: "Device ID Required", field: "device_id" };

    const user = await User.findOne({ email });
    if (!user) throw { status: 401, message: "Invalid credentials" };
    if (!user.verified) {
      throw { status: 403, message: "Please verify your account first" };
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) throw { status: 401, message: "Invalid credentials" };
    const userId = user._id.toString();
    const accessToken = Token.signAccess(userId);
    const refreshToken = Token.generateRefresh();
    const { expiresAt, refreshTokenHash } = Token.hashRefresh(refreshToken);
    await RefreshToken.create({
      user: user._id,
      tokenHash: refreshTokenHash,
      expiresAt,
      ip: ip,
      userAgent,
      deviceId: device_id,
    });
    return {
      accessToken,
      refreshToken,
      refresh_expires_at: expiresAt,
      user: { id: user._id, name: user.name, email: user.email },
    };
  }

  static async me(userId: string) {
    const user = await User.findById(userId).select("-password");

    if (!user) throw { status: 404, message: "User not found" };

    return user;
  }

  static async forgotPassword(email: string) {
    if (!email) throw { status: 400, message: "Email is required" };
    const user = await User.findOne({ email });
    if (!user) throw { status: 404, message: "User not found" };
    if (!user.verified) throw { status: 400, message: "User is not verified" };
    const { token } = await OTPService.createAndSendOtp(email);

    return {
      status: 200,
      message: "OTP sent to your email",
      token,
    };
  }

  static async refreshToken(refresh_token: string) {
    try {
      if (!refresh_token) {
        throw { status: 401, message: "Refresh token required" };
      }

      // 1️⃣ Hash incoming token
      const { refreshTokenHash } = Token.hashRefresh(refresh_token);

      // 2️⃣ Find stored refresh token
      const storedToken = await RefreshToken.findOne({
        tokenHash: refreshTokenHash,
        revoked: false,
        expiresAt: { $gt: new Date() },
      });
      if (!storedToken) {
        // 🚨 Possible token reuse / revoked / expired
        throw { status: 401, message: "Invalid refresh token" };
      }
      // 3️⃣ Rotate token (revoke old)
      storedToken.revoked = true;
      await storedToken.save();

      // 4️⃣ Create new refresh token
      const {
        refreshToken,
        refreshTokenHash: new_refresh_token_hash,
        expiresAt,
      } = Token.signRefresh();

      await RefreshToken.create({
        user: storedToken.user,
        tokenHash: new_refresh_token_hash,
        expiresAt,
        ...(storedToken.deviceId && { deviceId: storedToken.deviceId }),
        ...(storedToken.ip && { ip: storedToken.ip }),
        ...(storedToken.userAgent && { userAgent: storedToken.userAgent }),
      });

      // Generate new tokens
      const access_token = Token.signAccess(storedToken.user.toString());

      //  fetch the user info from DB
      const user = await User.findById(storedToken.user.toString()).select(
        "-password"
      );

      return {
        access_token,
        refresh_token: refreshToken,
        refresh_expires_at: expiresAt,
        user,
      };
    } catch (err: any) {
      if (err?.status) throw err;
      throw { status: 500, message: "Refresh token processing failed" };
    }
  }

  static async verifyUser({ otp, token }: { otp: string; token: string }) {
    try {
      const decoded = Token.verify(token, config.jwtSecret) as {
        email: string;
        otp: string;
      };

      const email = decoded.email; // extract email from token

      if (!email) throw { status: 400, message: "Invalid token" };

      if (decoded.otp != otp) throw { status: 400, message: "Invalid OTP" };

      // Find user
      const user = await User.findOne({ email });
      if (!user) throw { status: 404, message: "User not found" };

      // Already verified
      if (user.verified)
        throw { status: 400, message: "User already verified" };

      // Update user as verified
      user.verified = true;
      await user.save();

      return {
        status: 200,
        message: "OTP verified successfully",
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
        },
      };
    } catch (err: any) {
      if (err.name === "TokenExpiredError")
        throw { status: 400, message: "OTP expired" };

      throw { status: 400, message: "Invalid OTP or token" };
    }
  }

  static async resetPassword({
    otp,
    token,
    new_password,
  }: {
    otp: string;
    token: string;
    new_password: string;
  }) {
    try {
      const decoded = Token.verify(token, config.jwtSecret) as {
        email: string;
        otp: string;
      };

      if (decoded.otp !== otp) throw { status: 400, message: "Invalid OTP" };

      const user = await User.findOne({ email: decoded.email });
      if (!user) throw { status: 404, message: "User not found" };

      const hashed = await bcrypt.hash(new_password, 10);
      user.password = hashed;

      await user.save();

      return {
        status: 200,
        message: "Password reset successful",
      };
    } catch (err: any) {
      if (err.name === "TokenExpiredError")
        throw { status: 400, message: "OTP expired" };

      throw { status: 400, message: "Invalid token or OTP" };
    }
  }

  static async changePassword({
    userId,
    old_password,
    new_password,
  }: {
    userId: string;
    old_password: string;
    new_password: string;
  }) {
    const user = await User.findById(userId);
    if (!user) throw { status: 404, message: "User not found" };

    const isMatch = await bcrypt.compare(old_password, user.password);
    if (!isMatch) throw { status: 400, message: "Old password is incorrect" };
    if (old_password === new_password)
      throw { status: 400, message: "New password cannot be same as old" };
    const hashed = await bcrypt.hash(new_password, 10);
    user.password = hashed;

    await user.save();

    return {
      status: 200,
      message: "Password updated successfully",
    };
  }
}
