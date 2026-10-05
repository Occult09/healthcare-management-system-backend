import { Role } from "../../../../generated/prisma/enums"

export interface IRegisterPatientPayload {
    name: string
    email: string
    password: string
}

export interface ILoginUserPayload {
    email: string
    password: string
}

export interface IRequestUser {
    userId: string
    name: string
    email: string
    role: Role
}