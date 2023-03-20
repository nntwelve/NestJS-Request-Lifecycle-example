import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  RequestTimeoutException,
  Logger,
} from '@nestjs/common';
import { Observable, throwError, TimeoutError } from 'rxjs';
import { catchError, tap, timeout } from 'rxjs/operators';

@Injectable()
export class TimeoutInterceptor implements NestInterceptor {
  logger = new Logger(TimeoutInterceptor.name);
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    // NOTICE: CONTROLLER INTERCEPTOR
    this.logger.warn('===TRIGGER CONTROLLER INTERCEPTOR (PRE)===');
    return next.handle().pipe(
      tap(() => {
        // NOTICE: CONTROLLER INTERCEPTOR
        this.logger.warn('===TRIGGER CONTROLLER INTERCEPTOR (POST)===');
      }),
      timeout(5000),
      catchError((err) => {
        if (err instanceof TimeoutError) {
          return throwError(() => new RequestTimeoutException());
        }
        return throwError(() => err);
      }),
    );
  }
}
