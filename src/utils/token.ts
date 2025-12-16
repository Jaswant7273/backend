import jwt from "jsonwebtoken";
import { config } from "../config/index.js";

export const Token = {
  signAccess(id: string) {
    return jwt.sign({ id }, config.jwtSecret, {
      expiresIn: config.jwtExpiresIn,
    });
  },

  signRefresh(id: string) {
    return jwt.sign({ id }, config.jwtRefreshSecret, {
      expiresIn: config.jwtRefreshExpiresIn,
    });
  },

  verify(token: string, secret: string) {
    return jwt.verify(token, secret);
  },

  signOTP(payload: any) {
    return jwt.sign(payload, config.jwtSecret, {
      expiresIn: "10m",
    });
  },
};
