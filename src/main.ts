import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { HttpExceptionFilter } from './services/http-exception.filter';
import { ResponseInterceptor } from './services/response.interceptor';

async function bootstrap() {
  const app = await NestFactory.create(AppModule,{cors: true});
  app.useGlobalFilters(new HttpExceptionFilter());
  app.useGlobalInterceptors(new ResponseInterceptor());
  app.enableCors();

  const options = new DocumentBuilder()
  .setTitle('Authorization-API')
  .setDescription('Description of Authorrization API')
  .setVersion('1.0')
  .build();

  const document = SwaggerModule.createDocument(app, options);
  SwaggerModule.setup('api', app, document);
  
  await app.listen(3000);
}
bootstrap();
