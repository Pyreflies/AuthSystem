import * as crypto from 'crypto';

export const jwtConstants = {
    secret:crypto.randomBytes(32).toString('hex'),
    expiresIn:'1d'
}