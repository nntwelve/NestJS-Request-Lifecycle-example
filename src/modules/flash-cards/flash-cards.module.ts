import { Module } from '@nestjs/common';
import { FlashCardsService } from './flash-cards.service';
import { FlashCardsController } from './flash-cards.controller';

@Module({
  controllers: [FlashCardsController],
  providers: [FlashCardsService],
})
export class FlashCardsModule {}
