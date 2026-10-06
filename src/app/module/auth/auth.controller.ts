import { NextFunction, Request, Response } from "express"
import { catchAsync } from "../../utils/catchAsync"
import { authService } from "./auth.service";
import { sendResponse } from "../../utils/sendResponse";
import httpStatus from "http-status";

const registerPatient = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const payload = req.body;
    const result = await authService.registerPatient(payload);
    const { accessToken, refreshToken } = result;

    res.cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 24
    });

    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 24 * 7
    });

    sendResponse(res, {
        success: true,
        statusCode: httpStatus.OK,
        message: "User created successfully!",
        data: {
            result
        }
    })
});

const loginUser = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const payload = req.body;
    const result = await authService.loginUser(payload);

    const { accessToken, refreshToken } = result;

    res.cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 24
    });

    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 24 * 7
    });

    sendResponse(res, {
        success: true,
        statusCode: httpStatus.OK,
        message: "User logged in succesfully!",
        data: {
            accessToken,
            refreshToken
        }
    })
})

const getMe = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const user = req.user;

    if (!user) {
        throw new Error("User information is missing in the request");
    }

    const result = await authService.getMe(user)

    sendResponse(res, {
        success: true,
        statusCode: httpStatus.OK,
        message: "User profile fetched succesfully!",
        data: {
            result
        }
    })
});

const refreshToken = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    if (!req.cookies.refreshToken) {
        throw new Error("Refresh token is missing")
    }

    const result = await authService.refreshToken(req.cookies.refreshToken)

    const { accessToken, refreshToken } = result;

    res.cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 24
    })

    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 24 * 7
    })

    sendResponse(res, {
        success: true,
        statusCode: httpStatus.OK,
        message: "New tokens generated successfully",
        data: {
            accessToken,
            refreshToken
        }
    })
})



export const authController = {
    registerPatient,
    loginUser,
    getMe,
    refreshToken
}