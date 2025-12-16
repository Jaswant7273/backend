import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import { config } from "../config/index.js";
import { Token } from "./token.js";

export default class OTPService {
  // Generate 6-digit OTP
  static generateOtp(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  // Create JWT token with OTP
  static generateOtpToken(email: string, otp: string): string {
    return Token.signOTP({ email, otp });
    return jwt.sign({ email, otp }, config.jwtSecret, {
      expiresIn: "10m",
    });
  }

  // Send OTP email
  static async sendOtpEmail(email: string, otp: string): Promise<void> {
    const transporter = nodemailer.createTransport({
      host: config.smtp.host,
      port: config.smtp.port,
      secure: false,
      auth: {
        user: config.smtp.user,
        pass: config.smtp.pass,
      },
    });

    await transporter.sendMail({
      from: `"Jaswant" <${config.smtp.user}>`,
      to: email,
      subject: "Your OTP Code",
      text: `Your OTP code is: ${otp}`,
    });
  }

  // Complete flow: generate, sign, send
  static async createAndSendOtp(
    email: string
  ): Promise<{ otp: string; token: string }> {
    const otp = this.generateOtp();
    const token = this.generateOtpToken(email, otp);

    await this.sendOtpEmail(email, otp);

    return { otp, token };
  }
}
