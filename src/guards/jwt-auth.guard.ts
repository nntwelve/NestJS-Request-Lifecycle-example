import {
  Injectable,
  CanActivate,
  ExecutionContext,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';

@Injectable()
export class JwtAuthorizationGuard implements CanActivate {
  logger = new Logger(JwtAuthorizationGuard.name);
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    // NOTICE: CONTROLLER GUARD
    this.logger.log('===TRIGGER CONTROLLER GUARD===');
    return true;
  }
}
