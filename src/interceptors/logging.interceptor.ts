import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  logger = new Logger(LoggingInterceptor.name);
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    // NOTICE: GLOBAL INTERCEPTOR
    this.logger.warn('===TRIGGER GLOBAL INTERCEPTOR (PRE)===');

    const now = Date.now();
    return next.handle().pipe(
      tap(() => {
        // NOTICE: GLOBAL INTERCEPTOR
        this.logger.warn('===TRIGGER GLOBAL INTERCEPTOR (POST)===');
        this.logger.log(`After... ${Date.now() - now}ms`);
      }),
    );
  }
}
