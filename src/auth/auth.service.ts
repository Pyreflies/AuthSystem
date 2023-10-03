import {
    HttpException,
    HttpStatus,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { User } from './auth.schema';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { jwtConstants } from 'src/jwt.constants';
import * as crypto from 'crypto';

@Injectable()
export class AuthService {
    constructor(
        private jwtService: JwtService,
        @InjectModel(User.name) private userModel: Model<User>,
    ) { }

    async login(
        credentials: any,
    ): Promise<{ access_token, refresh_token, token_type, expiresIn, responseTime }> {
        const user = await this.validateUser(credentials);

        if (!user) {
            throw new UnauthorizedException('Invalid credentials');
        }
        const access_payload = {
            _id: user._id,
            username: user.username,
            email: user.email,
        };
        const refresh_payload = {
            _id: user._id,
            username: user.username,
            expiresIn: '1d'
        };
        // const _access = this.jwtService.sign(access_payload);
        // const _refresh = this.jwtService.sign(refresh_payload);
        const _access = this.generateAccessToken(access_payload);
        const _refresh = this.generateRefreshToken(refresh_payload);
        const now = Date.now();
        const sectionId = crypto.randomBytes(32).toString('hex');

        return { access_token: _access, refresh_token: _refresh, token_type: "Bearer", expiresIn: jwtConstants.expiresIn, responseTime: Date.now() - now };
    }
    async validateUser(credentials: any): Promise<User | null>  {
        // Implement your user validation logic, e.g., check against a user database
        // Return the user if the credentials are valid, otherwise return null
        // Replace 'User' with your actual user schema and user model

        const user = await this.userModel
            .findOne({ username: credentials.username })
            .exec();
        if (user && user.password === credentials.password) {
            return user;
        }
        return null;
    }

    async validateUserRefresh(credentials: any): Promise<User | null>  {
        // Implement your user validation logic, e.g., check against a user database
        // Return the user if the credentials are valid, otherwise return null
        // Replace 'User' with your actual user schema and user model

        const user = await this.userModel
            .findOne({ _id: credentials._id })
            .exec();
        if (user) {
            return user;
        }
        return null;
    }


    generateAccessToken(user: any): string {
        const payload = { _id: user._id, username: user.username, email: user.email };
        return this.jwtService.sign(payload);
    }

    generateRefreshToken(user :any): string {
        const payload = { _id: user._id ,expiresIn: user.expiresIn  };
        return this.jwtService.sign(payload); // Refresh token expiration time (e.g., 7 days)
    }

    async validateToken(token: any): Promise<User> {
        try {
            return await this.jwtService.verify(token.refresh_token);
        } catch (err) {
            // Handle invalid token error or token expiration
            throw new HttpException(err, HttpStatus.NON_AUTHORITATIVE_INFORMATION);
        }
    }
}
