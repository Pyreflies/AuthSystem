import { HttpException, HttpStatus, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { User } from './auth.schema';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { jwtConstants } from 'src/jwt.constants';
import * as crypto from 'crypto';

@Injectable()
export class AuthService {
    constructor(
        private  jwtService: JwtService,
        @InjectModel(User.name)private userModel: Model<User>,
    ) {}
    
    async login(credentials: any): Promise<{ access_token: string; responseTime: number }> {
        const user = await this.validateUser(credentials);
    
        if (!user) {
          throw new UnauthorizedException('Invalid credentials');
        }
    
        const now = Date.now();
        const sectionId = crypto.randomBytes(32).toString('hex');
        const token = this.jwtService.sign({ sectionId ,sub: user.id, username: user.username, email: user.email ,secret: jwtConstants.secret,expiresIn: jwtConstants.expiresIn});
    
        return { access_token: token, responseTime: Date.now() - now };
    }
    
    async validateUser(credentials: any): Promise<User | null> {
        // Implement your user validation logic, e.g., check against a user database
        // Return the user if the credentials are valid, otherwise return null
        // Replace 'User' with your actual user schema and user model
        
        const user = await this.userModel.findOne({ username: credentials.username }).exec();
        if (user && user.password === credentials.password) {
          return user;
        }
        return null;
      }

    async generateToken(payload: any): Promise<string> {
      return this.jwtService.sign(payload);
    }
  
    async validateToken(token: string): Promise<any> {
      try {
        return this.jwtService.verify(token);
      } catch (err) {
        // Handle invalid token error or token expiration
        throw new HttpException(err, HttpStatus.NON_AUTHORITATIVE_INFORMATION);
      }
    }

}
