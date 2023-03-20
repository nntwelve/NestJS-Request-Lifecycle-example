import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
  UseInterceptors,
  UsePipes,
  Query,
  Logger,
} from '@nestjs/common';
import { FlashCardsService } from './flash-cards.service';
import { CreateFlashCardDto } from './dto/create-flash-card.dto';
import { UpdateFlashCardDto } from './dto/update-flash-card.dto';
import { OwnershipGuard } from './guards/ownership.guard';
import { ExcludeNullInterceptor } from 'src/interceptors/exclude-null.interceptor';
import { TimeoutInterceptor } from 'src/interceptors/timeout.interceptor';
import { ParseMongoIdPipe } from 'src/pipes/parse-mongo-id.pipe';
import { JwtAuthorizationGuard } from 'src/guards/jwt-auth.guard';
import { ObjectId } from 'mongoose';
import { ParseControllerValidationPipe } from 'src/pipes/parse-custom-controller-validation.pipe';
import { ParseRouteValidationPipe } from 'src/pipes/parse-custom-route-validation.pipe';

@UseInterceptors(TimeoutInterceptor)
@UseGuards(JwtAuthorizationGuard)
@UsePipes(ParseControllerValidationPipe)
@Controller('flash-cards')
export class FlashCardsController {
  private logger: Logger;
  constructor(private readonly flashCardsService: FlashCardsService) {
    this.logger = new Logger(FlashCardsController.name);
  }

  @Post()
  create(@Body() createFlashCardDto: CreateFlashCardDto) {
    return this.flashCardsService.create(createFlashCardDto);
  }

  @Get()
  @UseGuards(OwnershipGuard)
  @UseInterceptors(ExcludeNullInterceptor)
  @UsePipes(ParseRouteValidationPipe)
  async findAll(@Query('limit') limit, @Query('offset') offset) {
    this.logger.log(`Method name: ${this.findAll.name}`);
    return await this.flashCardsService.findAll();
  }

  @Get(':id')
  @UseInterceptors(ExcludeNullInterceptor)
  findOne(@Param('id', ParseMongoIdPipe) id: ObjectId) {
    return this.flashCardsService.findOne(id);
  }

  @Patch(':id')
  @UseGuards(OwnershipGuard)
  update(
    @Param('id') id: string,
    @Body() updateFlashCardDto: UpdateFlashCardDto,
  ) {
    return this.flashCardsService.update(+id, updateFlashCardDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.flashCardsService.remove(+id);
  }
}
