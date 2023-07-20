import { Injectable, NestInterceptor, ExecutionContext, CallHandler, HttpStatus } from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

@Injectable()
export class ResponseInterceptor<T> implements NestInterceptor<T, any> {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      map((data) => {
        const response = context.switchToHttp().getResponse();
        const status = response.statusCode;
        const message = HttpStatus[status];
        const timestamp = new Date().toISOString();
        // Customize the response data object with status and message properties
        return { status, message,timestamp, data };
      }),
    );
  }
}
