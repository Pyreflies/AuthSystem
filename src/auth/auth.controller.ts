import { Controller, Post, Body, HttpStatus, UnauthorizedException, Get, HttpException, Param, Res, Header } from '@nestjs/common';
import { ApiOperation, ApiBody, ApiResponse, ApiTags, ApiParam, ApiExtraModels } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { User } from './auth.schema';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';


@ApiTags('AuthenticationService') 
@Controller('auth')
export class AuthController {
    constructor(
        @InjectModel(User.name) private userModel: Model<User>,
        private readonly authService: AuthService
    ){}
    
    @Get()
    @ApiOperation({ summary: 'Get all users' })
    async findAll(): Promise<User[]> {
        try {
            return this.userModel.find().exec();
        } catch (error) {
            throw new HttpException('Error fetching users', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Get(':id')
    @ApiOperation({ summary: 'Get a user by ID' })
    @ApiParam({ name: 'id', description: 'User ID', type: String })
    async findById(@Param('id') id: string): Promise<User> {
        try {
            const user = await this.userModel.findById(id).exec();
            if (!user) {
                throw new HttpException('User not found', HttpStatus.NOT_FOUND);
            }
            return user;
        } catch (error) {
            throw new HttpException('Error fetching user', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Post('login')
    @Header('Content-Type', 'application/json') 
    @ApiOperation({ summary: 'Login with credentials' })
    @ApiBody({ type: User })
    async login(@Body() credentials: User): Promise<any> {
        try {
            const { access_token, responseTime } = await this.authService.login(credentials);
            return { access_token, responseTime };
        } catch (error) {
            throw new UnauthorizedException('Invalid credentials');
        }
    }
}
