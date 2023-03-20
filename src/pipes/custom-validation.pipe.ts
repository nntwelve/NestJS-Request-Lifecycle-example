import {
  PipeTransform,
  Injectable,
  ArgumentMetadata,
  Logger,
  ValidationPipe,
} from '@nestjs/common';

@Injectable()
export class CustomValidationPipe extends ValidationPipe {
  logger: Logger;
  constructor() {
    super();
    this.logger = new Logger(CustomValidationPipe.name);
  }
  transform(value: any, metadata: ArgumentMetadata) {
    this.logger.debug('===TRIGGER GLOBAL PIPE===');
    return value;
  }
}
