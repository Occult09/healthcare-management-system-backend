import cookieParser from "cookie-parser";
import express, { type Application, type Request, type Response } from "express";
import cors from "cors";
import config from "./config";
import { authRoutes } from "./app/module/auth/auth.routes";

const app: Application = express();

app.use(
	cors({
		origin: config.backend_url,
		credentials: true,
	}),
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use("/api/v1/auth", authRoutes);

app.get("/", (req: Request, res: Response) => {
	res.send("Hello World!");
});

export default app;
