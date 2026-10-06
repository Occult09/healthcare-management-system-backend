import bcrypt from "bcryptjs";
import { prisma } from "../../../lib/prisma";
import { ILoginUserPayload, IRegisterPatientPayload, IRequestUser } from "./auth.interface"
import { Role, UserStatus } from "../../../../generated/prisma/enums";
import { jwtUtils } from "../../utils/jwt";
import config from "../../../config";
import { JwtPayload, SignOptions } from "jsonwebtoken";

const registerPatient = async (payload: IRegisterPatientPayload) => {
    const { name, password } = payload;
    const email = payload.email.trim().toLowerCase()

    const isUserExists = await prisma.user.findUnique({
        where: {
            email
        }
    })

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
                    email
                },
            }
        },
        omit: {
            password: true
        },
        include: {
            patient: true
        }
    });

    const { ...user } = createdUser;
    const { ...patient } = createdUser;
    const jwtPayload = {
        userId: user.id,
        name: user.name,
        email: user.email,
        role: user.role
    }

    const accessToken = jwtUtils.createToken(jwtPayload, config.jwt_access_secret as string, config.jwt_access_expires_in as SignOptions);

    const refreshToken = jwtUtils.createToken(jwtPayload, config.jwt_refresh_secret as string, config.jwt_refresh_expires_in as SignOptions);

    return {
        user,
        accessToken,
        refreshToken
    }
}

const loginUser = async (payload: ILoginUserPayload) => {
    const { password } = payload;
    const email = payload.email.trim().toLowerCase();

    const user = await prisma.user.findUnique({
        where: {
            email
        }
    })

    if (!user) {
        throw new Error("User does not exist!")
    }

    if (user.status === UserStatus.BLOCKED) {
        throw new Error("User in blocked")
    }

    if (user.isDeleted || user.status === UserStatus.DELETED) {
        throw new Error("User is deleted")
    }

    const isPasswordMatched = await bcrypt.compare(password, user.password);

    if (!isPasswordMatched) {
        throw new Error("Invalid credentials")
    }

    const jwtPayload = {
        userId: user.id,
        name: user.name,
        email: user.email,
        role: user.role
    }

    const accessToken = jwtUtils.createToken(jwtPayload, config.jwt_access_secret as string, config.jwt_access_expires_in as SignOptions);

    const refreshToken = jwtUtils.createToken(jwtPayload, config.jwt_refresh_secret as string, config.jwt_refresh_expires_in as SignOptions);

    return {
        accessToken,
        refreshToken
    }
}

const getMe = async (payload: IRequestUser) => {
    const user = await prisma.user.findUnique({
        where: {
            id: payload.userId
        },
        include: {
            patient: true
        },
        omit: {
            password: true
        }
    })

    if (!user) {
        throw new Error("User not found!")
    }

    return user;
}

const refreshToken = async (token: string) => {
    const verifiedRefreshToken = await jwtUtils.verifyToken(token, config.jwt_refresh_secret as string);

    if (!verifiedRefreshToken.success || !verifiedRefreshToken.data) {
        throw new Error(config.node_env === 'development' ? verifiedRefreshToken.error : "Invalid refresh token")
    }

    const data = verifiedRefreshToken.data as JwtPayload

    const user = await prisma.user.findUnique({
        where: {
            id: data.userId
        }
    })

    if (!user || user.isDeleted || user.status !== UserStatus.ACTIVE) {
        throw new Error("User is inactive or not found")
    }

    const jwtPayload = {
        userId: user.id,
        name: user.name,
        email: user.name,
        role: user.role
    }

    const accessToken = jwtUtils.createToken(jwtPayload, config.jwt_access_secret as string, config.jwt_access_expires_in as SignOptions)

    const refreshToken = jwtUtils.createToken(jwtPayload, config.jwt_refresh_secret as string, config.jwt_refresh_expires_in as SignOptions);

    return {
        accessToken,
        refreshToken
    }
}

export const authService = {
    registerPatient,
    loginUser,
    getMe,
    refreshToken
}