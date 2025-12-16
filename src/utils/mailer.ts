import nodemailer from "nodemailer";
import { config } from "../config/index.js";

let transporter = nodemailer.createTransport({
  host: config.smtp.host,
  port: config.smtp.port,
  auth: {
    user: config.smtp.user,
    pass: config.smtp.pass,
  },
});

// For development you can use Ethereal or just console.log the mail.
export async function sendResetEmail(to: string, token: string) {
  const resetUrl = `${
    process.env.FRONTEND_URL || "http://localhost:3000"
  }/reset-password?token=${token}`;
  const mail = {
    from: '"My App" <no-reply@myapp.test>',
    to,
    subject: "Password reset",
    text: `Use this link to reset your password: ${resetUrl}`,
    html: `<p>Use this link to reset your password:</p><p><a href="${resetUrl}">${resetUrl}</a></p>`,
  };
  // in dev: if transporter fails, just log
  try {
    const info = await transporter.sendMail(mail);
    console.log("Reset email sent:", info.messageId);
  } catch (err) {
    console.warn(
      "Mailer failed (check config). Falling back to console.log. Error:",
      err
    );
    console.log("Reset link (fallback):", resetUrl);
  }
}
