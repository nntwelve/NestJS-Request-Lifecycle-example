import { IsNotEmpty } from 'class-validator';

export class CreateFlashCardDto {
  @IsNotEmpty()
  vocabulary: string;
}
