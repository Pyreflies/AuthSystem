import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { jwtConstants } from './jwt.constants';

@Module({
  imports: [
    MongooseModule.forRoot('mongodb://localhost:27017/Database'),
    JwtModule.register({
      secret:jwtConstants.secret,
      signOptions:{expiresIn:jwtConstants.expiresIn},
    }),
    AuthModule
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
