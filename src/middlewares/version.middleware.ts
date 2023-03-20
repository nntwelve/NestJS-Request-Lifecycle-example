import {
  BadRequestException,
  Injectable,
  Logger,
  NestMiddleware,
} from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

@Injectable()
export class VersionMiddleware implements NestMiddleware {
  logger = new Logger(VersionMiddleware.name);
  use(req: Request, res: Response, next: NextFunction) {
    // NOTICE: MODULE BOUND MIDDLEWARE
    this.logger.debug('===TRIGGER MODULE BOUND MIDDLEWARE===');
    const appVersion = req.headers['x-app-version'];
    if (!appVersion || appVersion !== '2.0.0')
      throw new BadRequestException('Invalid App Version');
    next();
  }
}
