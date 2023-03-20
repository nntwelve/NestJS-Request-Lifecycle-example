import {
  Injectable,
  CanActivate,
  ExecutionContext,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';

@Injectable()
export class RolesGuard implements CanActivate {
  logger = new Logger(RolesGuard.name);
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    // NOTICE: GLOBAL GUARD
    this.logger.log('===TRIGGER GLOBAL GUARD===');
    return true;
  }
}
