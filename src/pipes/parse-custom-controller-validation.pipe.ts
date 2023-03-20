import {
  ArgumentMetadata,
  Injectable,
  Logger,
  PipeTransform,
} from '@nestjs/common';

@Injectable()
export class ParseControllerValidationPipe implements PipeTransform<string> {
  logger = new Logger(ParseControllerValidationPipe.name);
  transform(value: string, metadata: ArgumentMetadata): string {
    // NOTICE: CONTROLLER PIPE
    this.logger.verbose('===TRIGGER CONTROLLER PIPE===');
    return value;
  }
}
