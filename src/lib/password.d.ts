export declare function hashPassword(password: string): Promise<{
    passwordHash: string;
    passwordSalt: string;
}>;
export declare function verifyPassword(password: string, passwordHash: string): Promise<boolean>;
//# sourceMappingURL=password.d.ts.map