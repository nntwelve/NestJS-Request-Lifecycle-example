import { Injectable, Logger, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

@Injectable()
export class FlashCardMiddleware implements NestMiddleware {
  logger = new Logger(FlashCardMiddleware.name);
  use(req: Request, res: Response, next: NextFunction) {
    // NOTICE: MODULE BOUND MIDDLEWARE
    this.logger.debug('===TRIGGER MODULE BOUND MIDDLEWARE===');
    next();
  }
}
