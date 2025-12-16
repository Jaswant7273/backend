import { Router } from "express";
import { AuthController } from "../controllers/auth.controller.js";
import { requireAuth } from "../middleware/auth.middleware.js";

const router = Router();

router.post("/register", AuthController.register);
router.post("/verify-user", AuthController.verifyUser);
router.post("/login", AuthController.login);
router.post("/refresh", AuthController.refresh);
router.post("/forgot-password", AuthController.forgotPassword);
router.post("/reset-password", AuthController.resetPassword);
router.get("/me", requireAuth, AuthController.me);
router.post("/change-password", requireAuth, AuthController.changePassword);

export default router;
