import { Controller, Post, Body, HttpStatus, UnauthorizedException, Get, HttpException, Param, Res, Header, UseGuards } from '@nestjs/common';
import { ApiOperation, ApiBody, ApiResponse, ApiTags, ApiParam, ApiExtraModels } from '@nestjs/swagger';
// import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { User, Token } from './auth.schema';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

@ApiTags('AuthenticationService')
@Controller('auth')
export class AuthController {
    constructor(
        @InjectModel(User.name) private userModel: Model<User>,
        @InjectModel(Token.name) private tokenModel: Model<Token>,
        private readonly authService: AuthService
    ) { }

    @Get('health')
    @ApiOperation({ summary: 'health check' })
    //  @UseGuards(AuthGuard()) // Apply authentication guard (optional)
    checkHealth(): { status: string } {
        try {
            return { status: 'Authentication service is healthy' };
        }
        catch {
            throw new HttpException('Authentication service is not healthy', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
    
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
            throw new HttpException('Error fetching users', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Post('login')
    @Header('Content-Type', 'application/json')
    @ApiOperation({ summary: 'Login with credentials' })
    @ApiBody({ type: User })
    async login(@Body() credentials: User): Promise<any> {
        try {
            const { access_token, refresh_token, token_type, expiresIn, responseTime } = await this.authService.login(credentials);
            return { access_token, refresh_token, token_type, expiresIn, responseTime };
        } catch (error) {
            throw new UnauthorizedException('Invalid credentials');
        }
    }

    @Post('refresh')
    @Header('Content-Type', 'application/json')
    @ApiOperation({ summary: 'Refresh token' })
    @ApiBody({ type: Token })
    async refresh(@Body() credentials: Token): Promise<any> {
        try {
            // Verify and decode the refresh token
            const decoded = this.authService.validateToken(credentials);
            const user: User = await this.authService.validateUserRefresh(decoded);
            if (user) {
                // If the refresh token is valid, generate a new access token
                const accessToken = this.authService.generateAccessToken(user);
                return { access_token: accessToken };
            }
        } catch (error) {
            // Handle invalid or expired refresh token
            // ...
            throw new HttpException('Error fetching users', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
