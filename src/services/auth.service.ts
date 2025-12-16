import bcrypt from "bcryptjs";
import { config } from "../config/index.js";
import { User } from "../models/User.js";
import OTPService from "../utils/otpService.js";
import { Token } from "../utils/token.js";

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

  static async login({ email, password }: { email: string; password: string }) {
    const user = await User.findOne({ email });
    if (!user) throw { status: 401, message: "Invalid credentials" };

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) throw { status: 401, message: "Invalid credentials" };
    const userId = user._id.toString();
    const accessToken = Token.signAccess(userId);
    const refreshToken = Token.signRefresh(userId);

    return {
      accessToken,
      refreshToken,
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
      // Verify the refresh token
      const payload: any = Token.verify(refresh_token, config.jwtRefreshSecret);

      // Generate new tokens
      const access_token = Token.signAccess(payload?.id);
      const new_refresh_token = Token.signRefresh(payload?.id);

      // Optionally fetch the user info from DB
      const user = await User.findById(payload?.id).select("-password");

      return {
        access_token,
        refresh_token: new_refresh_token,
        user,
      };
    } catch (err) {
      throw { status: 401, message: "Invalid refresh token" };
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
