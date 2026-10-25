import type { NextFunction, Request, Response } from "express";
export type AppRole = "ADMIN" | "ARTIST" | "BUYER" | "DELIVERY_MAN";
export type AuthenticatedUser = {
    id: string;
    fullName: string;
    username: string;
    email: string;
    role: AppRole;
};
declare global {
    namespace Express {
        interface Request {
            authUser?: AuthenticatedUser;
        }
    }
}
export declare function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void>;
export declare function requireRole(...allowedRoles: AppRole[]): (req: Request, res: Response, next: NextFunction) => void;
export declare function requireRegisteredArtist(req: Request, res: Response, next: NextFunction): Promise<void>;
//# sourceMappingURL=auth.d.ts.map