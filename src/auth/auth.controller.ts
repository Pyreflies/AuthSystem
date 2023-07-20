import { Controller, Get, Post, Body, Param, Put, Delete ,Patch, HttpException, HttpStatus} from '@nestjs/common';
import { User } from './auth.schema';
import { ApiParam, ApiTags } from '@nestjs/swagger';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';

@ApiTags('AuthenticationService') 
@Controller('auth')
export class AuthController {
    constructor(
        @InjectModel(User.name) private userModel: Model<User>,
    ){}
    
    @Get()
    findAll(): Promise<User[]>{
        try {
            return this.userModel.find().exec();
        } catch (error) {
            throw new HttpException('Error fetching users', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Get(':id')
    @ApiParam({ name: 'id', description: 'User ID', type: String }) 
    async findById(@Param('id') id: string): Promise<User>{
        try {
            return this.userModel.findById(id).exec();
        } catch (error) {
            throw new HttpException('Error fetching users', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
