// ------------------------------------------------------------------------------------------------------------------------------
//                                                    RESPONSE HANDLER
//                                            Standardize API success & error responses
// ------------------------------------------------------------------------------------------------------------------------------

import type { Response } from "express";

/**
 * Send a standardized success response
 */
export const sendSuccess = (
  res: Response,
  data: any,
  message = "SUCCESS",
  status = 200
) => {
  return res.status(status).json({
    status: "success",
    message,
    data,
  });
};

/**
 * Send a standardized error response
 */
export const sendError = (
  res: Response,
  message = "ERROR",
  status = 400,
  errors?: any
) => {
  return res.status(status).json({
    status: "error",
    message,
    errors: errors || null,
  });
};
