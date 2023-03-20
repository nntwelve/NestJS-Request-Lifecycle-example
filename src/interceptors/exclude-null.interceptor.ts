import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map, tap } from 'rxjs/operators';

@Injectable()
export class ExcludeNullInterceptor implements NestInterceptor {
  logger = new Logger(ExcludeNullInterceptor.name);
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    // NOTICE: ROUTE INTERCEPTOR
    this.logger.warn('===TRIGGER ROUTE INTERCEPTOR (PRE)===');
    return next.handle().pipe(
      map((value) => (value === null ? '' : value)),
      tap(() =>
        // NOTICE: ROUTE INTERCEPTOR
        this.logger.warn('===TRIGGER ROUTE INTERCEPTOR (POST)==='),
      ),
    );
  }
}
