import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { User, AuthSchema,Token,TokenSchema  } from './auth.schema';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule} from '@nestjs/jwt';
import { jwtConstants } from 'src/jwt.constants';

@Module({
  imports:[
    MongooseModule.forFeature([{ name: User.name, schema: AuthSchema },{ name: Token.name, schema: TokenSchema }]),
    JwtModule.register({
      secret: jwtConstants.secret,
      signOptions: { expiresIn: jwtConstants.expiresIn },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService]
})
export class AuthModule {}
