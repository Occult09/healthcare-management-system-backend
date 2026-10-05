import { Router } from "express";
import { authController } from "./auth.controller";
import { auth } from "../../middleware/checkAuth";
import { Role } from "../../../../generated/prisma/enums";

const router = Router()

router.post("/register", authController.registerPatient);
router.post("/login", authController.loginUser);
router.get("/me", auth(Role.ADMIN, Role.DOCTOR, Role.PATIENT, Role.SUPER_ADMIN), authController.getMe);

export const authRoutes = router;