import {
  ArgumentMetadata,
  BadRequestException,
  Injectable,
  Logger,
  PipeTransform,
} from '@nestjs/common';
import { isObjectIdOrHexString } from 'mongoose';

@Injectable()
export class ParseMongoIdPipe implements PipeTransform<string> {
  logger = new Logger(ParseMongoIdPipe.name);
  transform(value: string, metadata: ArgumentMetadata): string {
    // NOTICE: ROUTE PIPE
    this.logger.debug('===TRIGGER ROUTE PARAMS PIPE===');
    if (!isObjectIdOrHexString(value)) {
      throw new BadRequestException('Invalid ID');
    }
    return value;
  }
}
