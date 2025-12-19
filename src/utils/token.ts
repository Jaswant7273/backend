// import jwt from "jsonwebtoken";
// import crypto from "crypto";
// import { config } from "../config/index.js";
// import { Utils } from "./index.js";

// export const Token = {
//   signAccess(id: string) {
//     return jwt.sign({ id }, config.jwtSecret, {
//       expiresIn: config.jwtExpiresIn,
//     });
//   },

//   // signRefresh(id: string) {
//   //   return jwt.sign({ id }, config.jwtRefreshSecret, {
//   //     expiresIn: config.jwtRefreshExpiresIn,
//   //   });
//   // },

//   // 🔥 Refresh Token (OPAQUE, NOT JWT)
//   generateRefresh() {
//     return crypto.randomBytes(40).toString("hex");
//   },

//   // 🔐 Hash refresh token before storing in DB
//   hashRefresh(token: string) {
//     const ttlMs = Utils.parseDuration(config.jwtRefreshExpiresIn);
//     const expiresAt = new Date(Date.now() + ttlMs);
//     const refreshTokenHash = crypto
//       .createHash("sha256")
//       .update(token)
//       .digest("hex");
//     return {
//       refreshTokenHash,
//       expiresAt,
//     };
//   },

//   verify(token: string, secret: string) {
//     return jwt.verify(token, secret);
//   },

//   signOTP(payload: any) {
//     return jwt.sign(payload, config.jwtSecret, {
//       expiresIn: config.otpExpiresIn,
//     });
//   },
// };

import jwt from "jsonwebtoken";
import crypto from "crypto";
import { config } from "../config/index.js";
import { Utils } from "./index.js";

export const Token = {
  /* ---------------- ACCESS ---------------- */
  signAccess(id: string) {
    return jwt.sign({ id }, config.jwtSecret, {
      expiresIn: config.jwtExpiresIn,
    });
  },

  /* ---------------- REFRESH (OPAQUE) ---------------- */
  generateRefresh() {
    return crypto.randomBytes(40).toString("hex");
  },

  hashRefresh(token: string) {
    const refreshTokenHash = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    const ttlMs = Utils.parseDuration(config.jwtRefreshExpiresIn);
    const expiresAt = new Date(Date.now() + ttlMs);

    return {
      refreshTokenHash,
      expiresAt,
    };
  },

  /* ---------------- COMBINED HELPER ---------------- */
  signRefresh() {
    const refreshToken = this.generateRefresh();
    const { refreshTokenHash, expiresAt } = this.hashRefresh(refreshToken);

    return {
      refreshToken,
      refreshTokenHash,
      expiresAt,
    };
  },

  /* ---------------- VERIFY ---------------- */
  verify(token: string, secret: string) {
    return jwt.verify(token, secret);
  },

  /* ---------------- OTP ---------------- */
  signOTP(payload: any) {
    return jwt.sign(payload, config.jwtSecret, {
      expiresIn: config.otpExpiresIn,
    });
  },
};
