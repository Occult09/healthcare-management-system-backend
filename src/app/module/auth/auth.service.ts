import bcrypt from "bcryptjs";
import { prisma } from "../../../lib/prisma";
import type {
	IGoogleLoginPayload,
	ILoginUserPayload,
	IRegisterPatientPayload,
	IRequestUser,
} from "./auth.interface";
import { AuthProvider, Role, UserStatus } from "../../../../generated/prisma/enums";
import { jwtUtils } from "../../utils/jwt";
import config from "../../../config";
import type { JwtPayload, SignOptions } from "jsonwebtoken";
import { OAuth2Client, TokenPayload } from "google-auth-library";
import { googleClient } from "../../../lib/googleAuth";

const registerPatient = async (payload: IRegisterPatientPayload) => {
	const { name, password } = payload;
	const email = payload.email.trim().toLowerCase();

	const isUserExists = await prisma.user.findUnique({
		where: {
			email,
		},
	});

	if (isUserExists) {
		throw new Error("User with this email already exists");
	}

	const hashedPassword = await bcrypt.hash(password, 8);

	const createdUser = await prisma.user.create({
		data: {
			name,
			email,
			password: hashedPassword,
			role: Role.PATIENT,
			status: UserStatus.ACTIVE,
			emailVerified: false,
			patient: {
				create: {
					name,
					email,
				},
			},
		},
		omit: {
			password: true,
		},
		include: {
			patient: true,
		},
	});

	const { ...user } = createdUser;
	const { ...patient } = createdUser;
	const jwtPayload = {
		userId: user.id,
		name: user.name,
		email: user.email,
		role: user.role,
	};

	const accessToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_access_secret as string,
		config.jwt_access_expires_in as SignOptions,
	);

	const refreshToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_refresh_secret as string,
		config.jwt_refresh_expires_in as SignOptions,
	);

	return {
		user,
		accessToken,
		refreshToken,
	};
};

const loginUser = async (payload: ILoginUserPayload) => {
	const { password } = payload;
	const email = payload.email.trim().toLowerCase();

	const user = await prisma.user.findUnique({
		where: {
			email,
		},
	});

	if (!user) {
		throw new Error("User does not exist!");
	}

	if (user.status === UserStatus.BLOCKED) {
		throw new Error("User in blocked");
	}

	if (user.isDeleted || user.status === UserStatus.DELETED) {
		throw new Error("User is deleted");
	}

	const isPasswordMatched = await bcrypt.compare(password, user.password as string);

	if (!isPasswordMatched) {
		throw new Error("Invalid credentials");
	}

	const jwtPayload = {
		userId: user.id,
		name: user.name,
		email: user.email,
		role: user.role,
	};

	const accessToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_access_secret as string,
		config.jwt_access_expires_in as SignOptions,
	);

	const refreshToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_refresh_secret as string,
		config.jwt_refresh_expires_in as SignOptions,
	);

	return {
		accessToken,
		refreshToken,
	};
};

const getMe = async (payload: IRequestUser) => {
	const user = await prisma.user.findUnique({
		where: {
			id: payload.userId,
		},
		include: {
			patient: true,
		},
		omit: {
			password: true,
		},
	});

	if (!user) {
		throw new Error("User not found!");
	}

	return user;
};

const refreshToken = async (token: string) => {
	const verifiedRefreshToken = await jwtUtils.verifyToken(
		token,
		config.jwt_refresh_secret as string,
	);

	if (!verifiedRefreshToken.success || !verifiedRefreshToken.data) {
		throw new Error(
			config.node_env === "development"
				? verifiedRefreshToken.error
				: "Invalid refresh token",
		);
	}

	const data = verifiedRefreshToken.data as JwtPayload;

	const user = await prisma.user.findUnique({
		where: {
			id: data.userId,
		},
	});

	if (!user || user.isDeleted || user.status !== UserStatus.ACTIVE) {
		throw new Error("User is inactive or not found");
	}

	const jwtPayload = {
		userId: user.id,
		name: user.name,
		email: user.name,
		role: user.role,
	};

	const accessToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_access_secret as string,
		config.jwt_access_expires_in as SignOptions,
	);

	const refreshToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_refresh_secret as string,
		config.jwt_refresh_expires_in as SignOptions,
	);

	return {
		accessToken,
		refreshToken,
	};
};

const googleLogin = async (payload: IGoogleLoginPayload) => {
	let googleIdTokenPayload: TokenPayload | null | undefined = null;
	try {
		const ticket = await googleClient.verifyIdToken({
			idToken: payload.idToken,
			audience: config.google_client_id
		})

		googleIdTokenPayload = ticket.getPayload();


	} catch (error) {
		console.log("Google ID Token Verification Failed!", error);
		throw new Error("Invalid or Expired Google Id Token");
	}

	if (!googleIdTokenPayload) {
		throw new Error("Invalid or Expired Google Id Token")
	}

	if (!googleIdTokenPayload.email) {
		throw new Error("Google Email Not Found")
	}

	if (!googleIdTokenPayload.name) {
		throw new Error("User Name Not Found")
	}

	const isPatientExistsWithGoogleAuth = await prisma.user.findUnique({
		where: {
			email: googleIdTokenPayload.email,
			role: Role.PATIENT,
			googleId: googleIdTokenPayload.sub
		}
	})

	let user = isPatientExistsWithGoogleAuth;

	if (!user) {
		user = await prisma.user.create({
			data: {
				name: googleIdTokenPayload.name,
				email: googleIdTokenPayload.email,
				role: Role.PATIENT,
				googleId: googleIdTokenPayload.sub,
				authProvider: AuthProvider.GOOGLE,
				patient: {
					create: {
						name: googleIdTokenPayload.name,
						email: googleIdTokenPayload.email
					}
				}
			}
		})
	}

	const jwtPayload = {
		userId: user?.id,
		name: user?.name,
		email: user?.email,
		role: user?.role
	}

	const accessToken = jwtUtils.createToken(jwtPayload, config.jwt_access_secret as string, config.jwt_access_expires_in as SignOptions);

	const refreshToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_refresh_secret as string,
		config.jwt_refresh_expires_in as SignOptions,
	);

	return {
		accessToken,
		refreshToken
	};
}

export const authService = {
	registerPatient,
	loginUser,
	getMe,
	refreshToken,
	googleLogin
};
