// ------------------------------------------------------------------------------------------------------------------------------
//                                                      APPLICATION CONFIGURATION
//     THIS FILE LOADS ALL IMPORTANT ENVIRONMENT VARIABLES USED BY THE BACKEND (PORT, DATABASE, JWT, ETC.)
//     MAKE SURE TO UPDATE THESE VALUES IN YOUR `.env` FILE BEFORE RUNNING IN PRODUCTION
// ------------------------------------------------------------------------------------------------------------------------------
type IConfig = {
  port: string | number;
  mongoUri: string;
  jwtSecret: string;
  jwtExpiresIn: string | number | any;
  jwtRefreshSecret: string;
  jwtRefreshExpiresIn: string | number | any;
  smtp: {
    host: string | any;
    port: number;
    user: string | any;
    pass: string | any;
  };
};
export const config: IConfig = {
  // ----------------------------------------------------------------------------------------------------------
  // PORT NUMBER ON WHICH THE SERVER WILL LISTEN
  // Reads PORT from environment variables. Example: PORT=5000
  // ----------------------------------------------------------------------------------------------------------
  port: process.env.PORT ?? 8000,

  // ----------------------------------------------------------------------------------------------------------
  // MONGO DATABASE CONNECTION STRING
  // MUST BE PROVIDED IN PRODUCTION (MONGO_URI=...)
  // If missing, app will warn at startup
  // ----------------------------------------------------------------------------------------------------------
  mongoUri: process.env.MONGO_URI || "",

  // ----------------------------------------------------------------------------------------------------------
  // JWT SECRET KEY USED FOR SIGNING TOKENS
  // WARNING: NEVER USE THE DEFAULT IN PRODUCTION. ALWAYS SET A STRONG SECRET IN .env
  // ----------------------------------------------------------------------------------------------------------
  jwtSecret: process.env.JWT_SECRET || "replace_this_in_prod",

  // ----------------------------------------------------------------------------------------------------------
  // TOKEN EXPIRY TIME (EXAMPLES: "1h", "30m", "7d")
  // Determines how long the user's login session remains valid
  // ----------------------------------------------------------------------------------------------------------
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || "1m",

  // ----------------------------------------------------------------------------------------------------------
  // JWT SECRET KEY USED FOR SIGNING TOKENS
  // WARNING: NEVER USE THE DEFAULT IN PRODUCTION. ALWAYS SET A STRONG SECRET IN .env
  // ----------------------------------------------------------------------------------------------------------
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || "replace_this_in_prod",

  // ----------------------------------------------------------------------------------------------------------
  // TOKEN EXPIRY TIME (EXAMPLES: "1h", "30m", "7d")
  // Determines how long the user's login session remains valid
  // ----------------------------------------------------------------------------------------------------------
  jwtRefreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || "7d",

  // SMTP for mail
  smtp: {
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
};

// ------------------------------------------------------------------------------------------------------------------------------
//                                             VALIDATION FOR REQUIRED CONFIG VALUES
//   THIS CHECK ENSURES THAT CRITICAL ENV VARIABLES ARE NOT MISSING WHEN RUNNING THE APP
// ------------------------------------------------------------------------------------------------------------------------------

if (!config.mongoUri) {
  console.warn(
    "[config] MONGO_URI IS EMPTY — MAKE SURE TO SET THE ENVIRONMENT VARIABLE BEFORE RUNNING IN PRODUCTION."
  );
}
