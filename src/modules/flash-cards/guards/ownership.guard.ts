import {
  Injectable,
  CanActivate,
  ExecutionContext,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';

@Injectable()
export class OwnershipGuard implements CanActivate {
  logger = new Logger(OwnershipGuard.name);
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    // NOTICE: ROUTE GUARD
    this.logger.log('===TRIGGER ROUTE GUARD===');
    return true;
  }
}
