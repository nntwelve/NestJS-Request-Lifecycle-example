Trong Series lần trước mình đã giới thiệu đến các bạn [Boilerplate cho dự án **NextJS**](https://viblo.asia/s/nextjs-thuc-chien-qPoL7ezN4vk) hôm nay chúng ta sẽ cùng phát triển song song Series về **NestJS** để các bạn có thể có cái nhìn tổng quan về quá trình phát triển một ứng dụng web. Series này sẽ bao gồm Boilerplate cho **NestJS** và các vấn đề cũng như cách giải quyết mà mình trải qua trong quá trình lập trình với dự án thực tế. Hy vọng có thể giúp ích cho các bạn trong quá trình học tập và làm việc với **Javascript** và các Framework của nó.

# Đặt vấn đề

**NestJS** cung cấp cho chúng ta nhiều thành phần hữu ích như **Middleware**, **Guards**, **Interceptors**, **Pipe**, **Interceptors**, **Filter**... Việc sử dụng các thành phần đó được NestJS tinh giản nên hầu như rất dễ sử dụng, vì thế đôi khi trong quá trình sử dụng chúng ta thường bỏ qua cách mà **NestJS** xử lý 1 _request_ khi đi qua các thành phần trên. Để tận dụng tối đa sức mạnh của **NestJS**, chúng ta cần hiểu rõ về các thành phần đó và cách thức mà nó xử lý các request hay thứ tự mà các thành phần đó được gọi. Bằng cách tìm hiểu các thông tin trên, chúng ta có thể tối ưu hóa ứng dụng của mình và đạt được hiệu quả cao nhất cũng như tránh các lỗi không mong muốn trong quá trình lập trình. Hãy cùng mình khám phá và hiểu về thứ tự mà **NestJS** thực thi các bước trong **lifecycle** của một _request_ để hiểu rõ hơn về framework này. Đồng thời chúng ta cũng sẽ tìm hiểu đôi nét về chức năng và cách ứng dụng các thành phần mà **NestJS** đã cung cấp.

- Cho ví dụ như bên dưới, nếu thử chạy và xem kết quả ở console, các bạn sẽ thấy log được in ra không theo thứ tự mà chúng ta đã sắp xếp trong code:

![image.png](https://images.viblo.asia/0d0abd2f-691b-4edc-b486-273e9600f9de.png)

- Kết quả ở console cho thấy **Middleware** được gọi trước, sau đó đến **Interceptors** và cuối cùng nếu có lỗi sẽ đến **Filters**

![image.png](https://images.viblo.asia/76fca7f9-b4f6-4720-835f-376b3711b0e0.png)

# Request Lifecycle

Trình tự xử lí _request_ của **NestJS** sẽ theo thứ tự như hình bên dưới, bên trong các thành phần sẽ có thứ tự xử lí riêng tùy theo phạm vi ứng dụng các thành phần đó. Ví dụ với **Middleware**, các **Middleware** ở _Global_ sẽ được xử lí trước, sau đó đến các **Middleware** được import bên trong các _Module_.

![](https://images.viblo.asia/b2bd5b57-534a-4a0d-ad16-b6fd4028d0ec.png)

Để lấy ví dụ cho Series này mình sẽ sử dụng ý tưởng về dự án _Học tiếng Anh với FlashCard_, bên trong source code sẽ có module `flash-cards` dùng để CRUD thông tin các flashcard. Mình sẽ cố gắng nghĩ ra nhiều ví dụ nhất có thể để các bạn dễ hình dung chức năng. Tuy nhiên, vì đây là bài viết tổng quan nên mình sẽ chỉ nói đôi nét về chức năng của các thành phần trong **lifecycle** kèm với ví dụ chứ không đi sâu vào chi tiết các thành phần đó để bài viết không quá dài và dễ tiếp cận, chi tiết sẽ được chúng ta tìm hiểu rõ hơn ở các bài viết sau.

Các bạn có thể tải về toàn bộ source code ở đây

# Các thành phần trong Request Lifecycle

# 1. Middleware

![image.png](https://images.viblo.asia/659e5e8e-9dee-493e-bdf3-fab0a4b867f0.png)

**Middleware** được gọi đầu tiên khi request đến server, chúng ta thường dùng để xử lý và thay đổi thông tin request trước khi truyền đến _route handler_. Đây là thành phần đầu tiên được gọi nên thông thường khi cấu hình dự án chúng ta sẽ sử dụng chúng đầu tiên.

## 1.1. Global Bound Middleware

Đúng như tên gọi, ở đây **Middleware** được đăng ký global trên toàn ứng dụng của chúng ta và sẽ được áp dụng cho tất cả các _request_ được gửi đến. Chúng ta thường thấy khi sử dụng các package như **cors**, **helmet**, **body-parser**,... với cú pháp `app.use()`.

Trong ví dụ của chúng ta, mình sẽ sử dụng **helmet** và một **custom middleware** để log ra thứ tự:

```typescript:main.ts
import { Logger } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { Request, Response } from 'express';
import helmet from 'helmet';
import { AppModule } from './app.module';

async function bootstrap() {
  const logger = new Logger(bootstrap.name);
  const app = await NestFactory.create(AppModule);
  // NOTICE: GLOBAL MIDDLEWARE
  app.use(helmet());
  app.use((req: Request, res: Response, next) => {
    logger.debug('===TRIGGER GLOBAL MIDDLEWARE===');
    next();
  });
  await app.listen(3000);
}
bootstrap();
```

Truy cập http://localhost:3000 và quay về console để xem kết quả:

![image.png](https://images.viblo.asia/ec9a7a4e-f46d-4b0a-ab9c-eacab7cad567.png)

## 1.2. Module Bound Middleware

**Middleware** của phần này được sử dụng trong một module bất kỳ để thực hiện các chức năng riêng. Như trong [series về LTI](https://viblo.asia/s/canvas-learning-management-system-PwlVmR005Z) chúng ta đã sử dụng **ltijs** như một **middleware** để xử lý các logic liên quan đến LTI.

- Lấy ví dụ trong quá trình phát triển ứng dụng, module `flash-cards` có một số yêu cầu update từ khách hàng làm thay đổi logic so với ban đầu. Tuy nhiên họ cũng không chắc những update này sẽ phù hợp với user nên muốn đưa ra version thử nghiệm để lấy ý kiến từ người dùng, nếu không ổn có thể quay về version trước đó.
- Để làm được việc đó chúng ta sẽ tạo ra **version 2.0.0** của module `flash-cards` để cho user dùng thử và yêu cầu phía FE gửi app version trong lúc call API. Phía FE cần gửi `X-App-Version` để xác định version và trả về dữ liệu chính xác với version đó, còn ở phía API chúng ta cũng phải kiểm tra xem FE có gửi `X-App-Version` gửi lên có tồn tại và thuộc version mà chúng ta support hay không. Để làm được việc đó mình sẽ tạo `VersionMiddleware`.

  ```typescript:src/middlewares/version.middleware.ts
  import { Injectable, NestMiddleware } from '@nestjs/common';
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
  ```

> Trong thực tế thì thường chúng ta sẽ cho thử nghiệm trên một tập user cụ thể trước để thu thập ý kiến của họ, sau đó nếu phản hồi tích cực mới thử nghiệm lần nữa trên toàn bộ user.

- Sau đó chúng ta thêm vào `AppModule` để apply cho `flash-cards` routes:

  ```typescript:app.module.ts
  import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
  import { AppController } from './app.controller';
  import { AppService } from './app.service';
  import { VersionMiddleware } from './middlewares/version.middleware';
  import { FlashCardsModule } from './modules/flash-cards/flash-cards.module';

  @Module({
    imports: [FlashCardsModule],
    controllers: [AppController],
    providers: [AppService],
  })
  export class AppModule implements NestModule {
    configure(consumer: MiddlewareConsumer) {
      consumer.apply(VersionMiddleware).forRoutes('flash-cards');
    }
  }
  ```

- Truy cập http://localhost:3000 và http://localhost:3000/flash-cards để xem kết quả. Trong console có thể thấy request đi theo thứ tự từ **Global middleware** đến **Module middleware**

  ![image.png](https://images.viblo.asia/90383d6b-5431-4086-9fd9-96b1e3fa71c2.png)

- Không có version hoặc version không phù hợp sẽ báo lỗi
  ![image.png](https://images.viblo.asia/1753ff3b-2446-4b4e-b7c5-d0b6ddef3b45.png)
- Đúng version:

  ![image.png](https://images.viblo.asia/492c2cd0-f764-4cf7-a6f2-aefceba80588.png)

# 2. Guards

![image.png](https://images.viblo.asia/1e194c66-753c-4c98-9367-d6de8377153c.png)

Mục đích duy nhất của **Guard** là xác định xem có cho phép request được xử lý bởi _route handler_ hay không tại _run-time_. Có thể các bạn sẽ có thắc mắc **Guard** và **Middleware** đều xử lý logic tương tự nhau, tuy nhiên về bản chất thì **Middleware** sau khi gọi hàm `next()` thì sẽ không biết _handler_ nào sẽ được gọi sau đó. Ngược lại, **Guard** nhờ vào việc có thể truy cập vào **ExcecutionContext** instance nên có thể biết được _handler_ nào tiếp theo sẽ được gọi sau khi gọi hàm `next()`. Việc sử dụng **Guard** giúp chúng ta đưa logic xử lý vào chu trình của ứng dụng một cách rõ ràng và dễ hiểu. Điều này giúp cho code của chúng ta trở nên ngắn gọn, dễ đọc và dễ bảo trì hơn, đồng thời giúp giảm thiểu các lặp lại trong code (**DRY**). Từ đó, ứng dụng có thể được phát triển và nâng cấp một cách dễ dàng và hiệu quả hơn.

> Theo mình chúng ta nên dùng **Middleware** khi cần xử lý và thay đổi các thông tin yêu cầu, còn **Guards** thì sử dụng để bảo vệ tài nguyên của ứng dụng bằng cách kiểm tra các điều kiện nhất định.

## 2.1. Global guards

Ví dụ về **Global guards** là package **@nestjs/throttler** dùng để giới hạn request gọi đến một API nhất định, nếu truy cập vượt quá giới hạn sẽ trả về lỗi _Too many requests_. Cách sử dụng theo như [docs](https://docs.nestjs.com/security/rate-limiting) như sau:

```typescript:app.module.ts
...
@Module({
  imports: [
    ThrottlerModule.forRoot({
      ttl: 60,
      limit: 10, // Giới hạn số request có thể truy cập trong thời gian ttl
    }),
    ...
  ],
})
export class AppModule {}
```

- Để sử dụng cho global thì chúng ta dùng như bên dưới:
  ![image.png](https://images.viblo.asia/5590dc0f-c8d8-41f7-b1f4-ba0c141dc764.png)

- Tuy nhiên để dễ theo dõi đường đi của request mình sẽ extends lại `ThrottlerGuard` từ package đó để log ra thông tin:

  ```typescript:src/guards/throttler.guard.ts
  import { ExecutionContext, Logger } from '@nestjs/common';
  import { ThrottlerGuard } from '@nestjs/throttler';

  export class CustomThrottlerGuard extends ThrottlerGuard {
    logger = new Logger(CustomThrottlerGuard.name);
    canActivate(context: ExecutionContext): Promise<boolean> {
      this.logger.log('===TRIGGER GLOBAL GUARD===');
      return super.canActivate(context);
    }
  }
  ```

- Nội dung hoàn chỉnh của file **app.module.ts** sau khi thêm vào:

  ```typescript:app.module.ts
  ...
  @Module({
    imports: [
      ThrottlerModule.forRoot({
        ttl: 60,
        limit: 10,
      }),
      FlashCardsModule,
    ],
    controllers: [AppController],
    providers: [
      AppService,
      {
        provide: APP_GUARD,
        useClass: CustomThrottlerGuard,
      },
    ],
  })
  export class AppModule implements NestModule {
    configure(consumer: MiddlewareConsumer) {
      consumer.apply(VersionMiddleware).forRoutes('flash-cards');
    }
  }
  ```

- Truy cập http://localhost:3000/flash-cards và xem log ở console.
  ![image.png](https://images.viblo.asia/f1591879-58d8-4507-8b0d-cca3be92dd45.png)

- Response nếu truy cập quá 10 lần trong 60s

![image.png](https://images.viblo.asia/1d115ff1-354e-48d5-b0d2-5d7e75a9b678.png)

## 2.2. Controller Guards

**Controller Guards** thường được dùng với **Jwt Authentication**, nên chúng ta cũng sẽ lấy ví dụ dùng _jwt_ để protect `flash-cards` route, chỉ những user login xong mới có thể truy cập vào. Tuy nhiên việc config _jwt_ hơi dài dòng nên chúng ta sẽ thực hiện ở các bài viết tiếp theo trong series, mình sẽ chỉ viết tượng trưng để chúng ta thấy đường đi của request thôi.

```typescript:src/guards/jwt-auth.guard.ts
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';

@Injectable()
export class JwtAuthorizationGuard implements CanActivate {
  logger = new Logger(JwtAuthorizationGuard.name);
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    // NOTICE: CONTROLLER GUARD
    this.logger.log('===TRIGGER CONTROLLER GUARD===');
    // IMPLEMENT JWT GUARD LOGIC HERE
    return true;
  }
}
```

- Sử dụng **Guard** cho `flash-cards controller`

```typescript:flash-cards.controller.ts
...
@UseGuards(JwtAuthorizationGuard)
@Controller('flash-cards')
export class FlashCardsController {
  constructor(private readonly flashCardsService: FlashCardsService) {}

  @Get()
  async findAll() {
    return await this.flashCardsService.findAll();
  }
  ...
```

- Truy cập http://localhost:3000/flash-cards và xem log ở console.

![image.png](https://images.viblo.asia/2c46a83a-172b-4a13-a7a1-a0fb33fee6ce.png)

## 2.3. Route guards

Sau khi đi qua **Global guards** và **Controller guards** sẽ đến **Route guards**, ở đây chúng ta thường dùng các guard có tính chất riêng. Ví dụ như user khi muốn sửa/xóa một `flash-card` thì cần phải là người tạo ra nó mới quyền sửa/xóa.

- Chúng ta sẽ tạo ra `OwnershipGuard` để handle trường hợp này

```typescript:src/module/flash-cards/guards/ownership.guard.ts
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
    // IMPLEMENT QUERY FLASH-CARD DATA AND CHECK OWNERSHIP
    return true;
  }
}
```

- Thêm vào cho method update trong `flash-cards controller` :

  ````javascript:flash-cards.controller.ts
  ...
    @Patch(':id')
    @UseGuards(OwnershipGuard)
    update(
      @Param('id') id: string,
      @Body() updateFlashCardDto: UpdateFlashCardDto,
    ) {
      return this.flashCardsService.update(+id, updateFlashCardDto);
    }
    ```
  ````

- Truy cập http://localhost:3000/flash-cards/1 với method PATCH để kiểm tra kết quả:

![image.png](https://images.viblo.asia/554611ac-61cc-4d88-ae6a-fb0140ca027c.png)

# 3. Interceptors

![image.png](https://images.viblo.asia/8ec92ff6-9743-4de3-a712-44d3998813b0.png)

Nói sơ qua về **Interceptors** thì nó cho phép chúng ta xử lý các _request_ và _response_ trước khi chúng được xử lý bởi _controller_ hoặc được trả về cho client. Vì thế chúng ta có thể chèn thêm custom logic vào quá trình xử lý _request/response_ của ứng dụng. **Interceptors** thường được sử dụng cho các trường hợp sau đây:

- **Logging**: Ghi lại thông tin _request_ và _response_ để giám sát và phân tích
- **Caching**: Lưu _cache_ của các _response_ để giảm thiểu việc truy vấn database hoặc service bên ngoài
- **Transformation**: Chuyển đổi _request_ hoặc _response_ để phù hợp với định dạng mong muốn
- **Error handling**: Xử lý lỗi và trả về _response_ phù hợp

Vì **Interceptors** xử lý cả request lẫn response nên sẽ có 2 phần:

- **Pre**: trước khi đến _method handler_ của _controller_
- **Post**: sau khi có response trả về từ _method handler_.

## 3.1. Global Interceptors

- Để lấy ví dụ mình sẽ tạo `LoggingInterceptor` để ghi lại thông tin user request đến API cũng như thời gian mà API phản hồi dữ liệu đến người dùng .

```typescript:src/interceptors/logging.interceptor.ts
import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  logger = new Logger(LoggingInterceptor.name);
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    // NOTICE: GLOBAL INTERCEPTOR
    this.logger.warn('===TRIGGER GLOBAL INTERCEPTOR (PRE)===');

    const now = Date.now();
    return next.handle().pipe(
      tap(() => {
        logger.log(`After... ${Date.now() - now}ms`);
        // NOTICE: GLOBAL INTERCEPTOR
        this.logger.warn('===TRIGGER GLOBAL INTERCEPTOR (POST)===');
      }),
    );
  }
}
```

- Thêm **Interceptors** vừa tạo vào **main.ts** để áp dụng cho toàn ứng dụng

  ```typescript:main.ts
  import { LoggingInterceptor } from './interceptors/logging.interceptor';
  ...
  async function bootstrap() {
    const logger = new Logger(bootstrap.name);
    const app = await NestFactory.create(AppModule);
    // Thêm vào đây
    app.useGlobalInterceptors(new LoggingInterceptor());
    // NOTICE: GLOBAL MIDDLEWARE
    app.use(helmet());
    app.use((req: Request, res: Response, next) => {
      logger.debug('===TRIGGER GLOBAL MIDDLEWARE===');
      next();
    });
    await app.listen(3000);
  }
  bootstrap();
  ```

- Thêm log ở `flash-cards controller` để kiểm tra:

  ```typescript:flash-cards.controller.ts
  ...
  @UseGuards(JwtAuthorizationGuard)
  @Controller('flash-cards')
  export class FlashCardsController {
    private logger: Logger;
    constructor(private readonly flashCardsService: FlashCardsService) {
      this.logger = new Logger(FlashCardsController.name);
    }

    @Get()
    @UseGuards(OwnershipGuard)
    async findAll() {
      this.logger.log(`Method name: ${this.findAll.name}`);
      return await this.flashCardsService.findAll();
    }
  ```

- Truy cập http://localhost:3000/flash-cards để xem kết quả:

![image.png](https://images.viblo.asia/387f2932-fdb4-48d9-8408-1188a7f52085.png)

- Nhìn vào log ở trên các bạn có thể thấy, mặc dù chúng ta để lệnh `app.useGlobalInterceptors(new LoggingInterceptor())` ở trên `app.use((req: Request, res: Response, next) => {
  logger.debug('===TRIGGER GLOBAL MIDDLEWARE===');
  next();
})` nhưng **Middleware** vẫn được gọi trước chứ không đi theo thứ tự từ trên xuống trong file code.
- **Interceptors** thì `PRE` sẽ được gọi trước sau đó đến function `findAll` trong _controller_ sau đó đến `POST` để hiển thị tổng thời gian request thực thi.

## 3.2. Controller Interceptors

- `TimeoutInterceptor` sẽ là ví dụ về **Controller Interceptors**, chúng ta có thể dùng để control response nếu request vượt quá thời gian định trước.

  ```typescript:src/interceptors/timeout.interceptor.ts
  import {
    Injectable,
    NestInterceptor,
    ExecutionContext,
    CallHandler,
    RequestTimeoutException,
    Logger,
  } from '@nestjs/common';
  import { Observable, throwError, TimeoutError } from 'rxjs';
  import { catchError, tap, timeout } from 'rxjs/operators';

  @Injectable()
  export class TimeoutInterceptor implements NestInterceptor {
    logger = new Logger(TimeoutInterceptor.name);
    intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
      // NOTICE: CONTROLLER INTERCEPTOR
      this.logger.warn('===TRIGGER CONTROLLER INTERCEPTOR (PRE)===');
      return next.handle().pipe(
        tap(() => {
          // NOTICE: CONTROLLER INTERCEPTOR
          this.logger.warn('===TRIGGER CONTROLLER INTERCEPTOR (POST)===');
        }),
        timeout(5000),
        catchError((err) => {
          if (err instanceof TimeoutError) {
            return throwError(() => new RequestTimeoutException());
          }
          return throwError(() => err);
        }),
      );
    }
  }
  ```

- Thêm vào `flash-cards controller`:

  ```typescript:flash-cards.controller.ts
  ...
  import { TimeoutInterceptor } from 'src/interceptors/timeout.interceptor';

  @UseInterceptors(TimeoutInterceptor)
  @UseGuards(JwtAuthorizationGuard)
  @Controller('flash-cards')
  export class FlashCardsController {
  ...
  }
  ```

- Truy cập http://localhost:3000/flash-cards để xem log ở conosle.

  ![image.png](https://images.viblo.asia/43c6fc62-6547-4f4f-b307-092ff2c41e52.png)

- Có thể thấy tương tự như trường hợp với **Middleware**, mặc dù chúng ta để `TimeoutInterceptor` phía trên `JwtAuthorizationGuard` nhưng nó chỉ được gọi sau khi `JwtAuthorizationGuard` xử lí xong logic của mình.
- Lưu ý: thứ tự thực thi ở _PRE_ và _POST_ của **Interceptors** sẽ ngược lại với nhau:
  - _PRE_: **Global** => **Controller** => **Route**
  - _POST_: **Route** => **Controller** => **Global**

## 3.3. Route Interceptors

- **Interceptors** thường thấy khi dùng với **Route Interceptors** là `ExcludeNull`, giúp loại bỏ các trường null khỏi response trước khi trả về cho user.

  ```typescript:src/interceptors/exclude-null.interceptor.ts
  import {
    Injectable,
    NestInterceptor,
    ExecutionContext,
    CallHandler,
    Logger,
  } from '@nestjs/common';
  import { Observable } from 'rxjs';
  import { map, tap } from 'rxjs/operators';

  @Injectable()
  export class ExcludeNullInterceptor implements NestInterceptor {
    logger = new Logger(ExcludeNullInterceptor.name);
    intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
      // NOTICE: ROUTE INTERCEPTOR
      this.logger.warn('===TRIGGER ROUTE INTERCEPTOR (PRE)===');
      return next.handle().pipe(
        map((value) => (value === null ? '' : value)),
        tap(() =>
          // NOTICE: ROUTE INTERCEPTOR
          this.logger.warn('===TRIGGER ROUTE INTERCEPTOR (POST)==='),
        ),
      );
    }
  }
  ```

- Thêm vào cho function `findAll` trong `flash-cards controller`.

  ```typescript:flash-cards.controller.ts
     ...
    @Get()
    @UseGuards(OwnershipGuard)
    @UseInterceptors(ExcludeNullInterceptor)
    async findAll() {
      this.logger.log(`Method name: ${this.findAll.name}`);
      return await this.flashCardsService.findAll();
    }
  ```

- Truy cập http://localhost:3000/flash-cards để xem kết quả. Không ngoài mong đợi, kết quả trả về theo đúng thứ tự mà chúng ta đã nói ở trên.

  ![image.png](https://images.viblo.asia/ea9ed9f2-bb37-4293-a594-6ad55ac2993e.png)

# 4. Pipes

![image.png](https://images.viblo.asia/666e4d0c-7b7a-436b-a3c2-2438f0bc0853.png)

Mục đích chính của **Pipe** là để kiểm tra, chuyển đổi và/hoặc sàng lọc dữ liệu được gửi và nhận về từ client.

Các trường hợp khi nên sử dụng **Pipe** bao gồm:

- Xác thực dữ liệu: Kiểm tra xem dữ liệu được gửi từ client có đúng định dạng và có hợp lệ hay không.
- Chuyển đổi dữ liệu: Chuyển đổi định dạng dữ liệu được gửi từ client thành dạng dữ liệu mà server có thể hiểu được, hoặc ngược lại chuyển đổi định dạng dữ liệu gửi về cho client.
- Sàng lọc dữ liệu: Lọc bỏ dữ liệu không cần thiết, nhạy cảm hoặc nguy hiểm.

## 4.1. Global Pipes

Chúng ta không còn xa lạ gì với **class-validator** khi dùng với NestJS, đó là 1 package thông dụng dùng **Global Pipes** mà chúng ta dùng trong hầu hết các trường hợp.

- Mình cũng sẽ custom lại `ValidationPipe` của **class-validator** và thêm vào log.

  ```typescript:src/pipes/custom-validation.pipe.ts
  import { PipeTransform, Injectable, ArgumentMetadata, Logger, ValidationPipe } from '@nestjs/common';

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
  ```

- Thêm vào **main.ts**

  ```typescript:main.ts
  import { CustomValidationPipe } from './pipes/custom-validation.pipe';
  ...
  async function bootstrap() {
    const logger = new Logger(bootstrap.name);
    const app = await NestFactory.create(AppModule);
   app.useGlobalPipes(new CustomValidationPipe());
   app.useGlobalInterceptors(new LoggingInterceptor());
    // NOTICE: GLOBAL MIDDLEWARE
    app.use(helmet());
    app.use((req: Request, res: Response, next) => {
      logger.debug('===TRIGGER GLOBAL MIDDLEWARE===');
      next();
    });
    await app.listen(3000);
  }
  bootstrap();
  ```

- Tuy nhiên để trigger **Pipes** chúng ta cần thêm vào params ở _route handler_.

  ```typescript:flash-cards.controller.ts
  ...
  @Get()
  @UseGuards(OwnershipGuard)
  @UseInterceptors(ExcludeNullInterceptor)
  async findAll(@Query('limit') limit) { // Có thể thay bằng @Body, @Params,...
  this.logger.log(`Method name: ${this.findAll.name}`);
  return await this.flashCardsService.findAll();
  }
  ...
  ```

- Truy cập http://localhost:3000/flash-cards xem kết quả thu được. Log của `CustomValidationPipe` sẽ nằm trong cùng, chỉ trước khi method `findAll` trong _controller_ được gọi bất kế có thứ tự như thế nào trong file _main.ts_

![image.png](https://images.viblo.asia/3a93431d-ea19-47f0-b05e-a35f6c3f35f4.png)

> Lưu ý: ứng với mỗi params được gọi sẽ là 1 lần **Pipes** được trigger, đây là phần các bạn nên chú ý. Nếu xài **Pipes** không hợp lý sẽ làm cho nó gọi lại những **Pipes** không cần thiết. Ví dụ thêm @Query('limit') vào function `findAll` thì kết quả sẽ là:
> ![image.png](https://images.viblo.asia/3257a186-7e6b-41f7-af7c-3954392d0334.png)

## 4.2. Controller Pipes

Ở **Controller Pipes** và **Route Pipes** thông thường chúng ta cũng sẽ dùng **Validation Pipe** tùy theo trường hợp vì thế 2 phần này mình sẽ tạo 2 Custom Pipe để log ra thông tin đường đi của request.

```typescript:src/pipes/parse-custom-controller-validation.pipe.ts
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
```

- Thêm vào `flash-cards controller`

```typescript:flash-cards.controller.ts
import { ParseControllerValidationPipe } from 'src/pipes/parse-custom-validation-controller.pipe';
...
@UseInterceptors(TimeoutInterceptor)
@UseGuards(JwtAuthorizationGuard)
@UsePipes(ParseControllerValidationPipe)
@Controller('flash-cards')
export class FlashCardsController {
...
}
```

- Truy cập http://localhost:3000/flash-cards để xem log
  ![](https://images.viblo.asia/7d329f8f-82bf-4d60-b3e8-2c0720970346.png)

## 4.3. Route Pipes

Tạo `ParseRouteValidationPipe` như đã nói ở trên:

```typescript:src/pipes/parse-custom-route-validation.pipe.ts
import {
  ArgumentMetadata,
  Injectable,
  Logger,
  PipeTransform,
} from '@nestjs/common';

@Injectable()
export class ParseRouteValidationPipe implements PipeTransform<string> {
  logger = new Logger(ParseRouteValidationPipe.name);
  transform(value: string, metadata: ArgumentMetadata): string {
    // NOTICE: ROUTE PIPE
    this.logger.verbose('===TRIGGER ROUTE PIPE===');
    return value;
  }
}
```

- Thêm vào `flash-cards controller`

```typescript:flash-cards.controller.ts
import { ParseRouteValidationPipe } from 'src/pipes/parse-custom-route-validation.pipe';
...
@Get()
@UseGuards(OwnershipGuard)
@UseInterceptors(ExcludeNullInterceptor)
@UsePipes(ParseRouteValidationPipe)
async findAll(@Query('limit') limit) {
    this.logger.log(`Method name: ${this.findAll.name}`);
    return await this.flashCardsService.findAll();
}
...
```

- Truy cập http://localhost:3000/flash-cards để xem log

![image.png](https://images.viblo.asia/4aee848a-c77f-40ea-a6f5-0d04986dd895.png)

## 4.4. Route Parameter Pipes

Các **Pipe** bắt đầu bằng prefix **Parse\*** là các **Pipe** mà chúng ta thường dùng cho **Route Parameter Pipes** khi transfer dữ liệu input của user trong **Query**, **Param** hoặc **Body** từ _String_ sang _Number_, _Boolean_, _UUID_...

- Series này sẽ dùng **MongoDB** nên mình tạo một `ParseMongoID` pipe để transform ID mà FE gửi lên sang **ObjectId** của **MongoDB** đồng thời cũng trả về lỗi nếu ID không hợp lệ.

  ```typescript:src/pipes/parse-mongo-id.pipe.ts
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
      this.logger.log('===TRIGGER ROUTE PARAMS PIPE===');
      if (!isObjectIdOrHexString(value)) {
        throw new BadRequestException('Invalid ID');
      }
      return value;
    }
  }
  ```

  - Thêm vào function `findOne` trong `flash-cards controller`

  ```typescript:flash-cards.controllers.ts
  import { ParseMongoIdPipe } from 'src/pipes/parse-mongo-id.pipe';
  import { ObjectId } from 'mongoose';
  ...
  @Get(':id')
  @UseInterceptors(ExcludeNullInterceptor)
  findOne(@Param('id', ParseMongoIdPipe) id: ObjectId) {
      return this.flashCardsService.findOne(id);
  }
    ...
  ```

- Truy cập với ID không phải của **MongoDB** http://localhost:3000/flash-cards/1 để xem có gặp lỗi không.

![image.png](https://images.viblo.asia/9f08c770-b7be-4e33-97dc-eb2a50ee462d.png)

- Thử lại với ID của **MongoDB** http://localhost:3000/flash-cards/64016169f36ad5ebb84050f6 thì đã có thể truy cập được.

![image.png](https://images.viblo.asia/591c1e77-251f-4a2b-b9e4-bd91c99e0b26.png)

- Thông tin trong console:

![image.png](https://images.viblo.asia/bdd9363b-107c-42a1-9a8d-de17747aeb3e.png)

# 5. Controller

Phần này thì không còn xa lạ gì với chúng ta, _route handler_ xử lý logic chính của API được gọi tới.
![image.png](https://images.viblo.asia/1ef6a48b-e524-4026-84e1-6d451cc5a8bb.png)

# 6. Service

**Service** là nơi mà **Controller** gọi tới để xử lý yêu cầu, hoặc cũng có thể không cần gọi tới nếu bản thân **Controller** có thể tự giải quyết được. Trong trường hợp các bạn áp dụng **Repository Pattern** thì có thể có thêm 1 tầng logic từ **Service** gọi tới **Repository**.

# 7. Exception Filter

![image.png](https://images.viblo.asia/38ab0982-9345-4734-bdd9-465d5eb53b6e.png)

Khác với **NodeJS** thuần, khi gặp _exceptions_ ứng dụng sẽ bị crash,**Exception filter** được **NestJS** tạo ra để xử lý các ngoại lệ (_exceptions_) trong ứng dụng. Nó giúp chúng ta kiểm soát và định hướng các ngoại lệ xảy ra trong ứng dụng và trả về một phản hồi thích hợp cho user. Nếu các _exceptions_ không được chúng ta tự handle thì sẽ được chuyển đến cho **Exception Filter** xử lý.

- Mình sẽ sử dụng ví dụ về `HttpExceptionFilter` từ [docs của NestJS](https://docs.nestjs.com/exception-filters#exception-filters-1) để xử lý các ngoại lệ từ `HttpException class`, đồng thời logs ra `timestamp` và `path`.

```typescript:src/filters/http-exception.filter.ts
import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  logger = new Logger(HttpExceptionFilter.name);
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const status = exception.getStatus();
    // NOTICE: GLOBAL FILTER
    this.logger.debug('===TRIGGER GLOBAL FILTER===');
    response.status(status).json({
      statusCode: status,
      message: exception.message,
      timestamp: new Date().toISOString(),
      path: request.url,
    });
  }
}
```

- Tương tự với các thành phần trên, **Exception Filter** cũng có thể sử dụng ở các cấp độ: **Global**, **Controller** và **Route**. Mình sẽ cho apply `HttpExceptionFilter` trên toàn ứng dụng.

```typescript:main.ts
import { HttpExceptionFilter } from './filters/http-exception.filter';
...
async function bootstrap() {
  const logger = new Logger(bootstrap.name);
  const app = await NestFactory.create(AppModule);
  app.useGlobalFilters(new HttpExceptionFilter()); // Thêm vào đây
  app.useGlobalInterceptors(new LoggingInterceptor());
  app.useGlobalPipes(new CustomValidationPipe());
  // NOTICE: GLOBAL MIDDLEWARE
  app.use(helmet());
  app.use((req: Request, res: Response, next) => {
    logger.debug('===TRIGGER GLOBAL MIDDLEWARE===');
    next();
  });
  ...
```

- Truy cập vào http://localhost:3000/flash-cards/1 mà khi nảy chúng ta dùng **Pipe** validate **MongoID**.

![image.png](https://images.viblo.asia/fcde6452-9c2d-4ac5-b748-d379f68c4e59.png)

- Có thể thấy response đã được cập nhật thêm `timestamp` và `path`. Giờ quay lại console để xem request lifecycle. Từ logs trên hình cho ta biết khi validate ở **Route params pipe** thất bại, ngay lập tức request đến **Exception Filter** layer để response cho người dùng và kết thúc request.

![image.png](https://images.viblo.asia/899a5768-003b-43e3-bb26-816397b6f091.png)

# Kết luận

Trong bài viết này, chúng ta đã tìm hiểu về **Request Lifecycle** trong **NestJS**. Chúng ta đã bàn về các khái niệm cơ bản như **Middleware**, **Guards**, **Interceptors**, **Pipes**, và **Exception Filters**. Chúng ta cũng đã thảo luận về việc sử dụng các thành phần này trong ứng dụng của chúng ta để giải quyết các vấn đề khác nhau.

Chúng ta đã bàn về vai trò của **Middleware** và **Guards** trong việc kiểm soát và bảo vệ các tài nguyên trong hệ thống, như cảnh báo truy cập trái phép hay kiểm soát quyền truy cập của người dùng. **Interceptors** và **Pipes** được sử dụng để xử lý dữ liệu và định dạng dữ liệu trước khi nó được gửi đi hoặc sau khi nó được nhận về. **Exception Filters** giúp chúng ta xử lý các ngoại lệ xảy ra trong quá trình xử lý request.

Tóm lại, **NestJS** cung cấp một cơ chế mạnh mẽ và linh hoạt để xử lý **Request Lifecycle** của ứng dụng của bạn. Việc sử dụng các thành phần **Middleware**, **Guards**, **Interceptors**, **Pipes**, và **Exception Filters** có thể giúp bạn tạo ra một ứng dụng an toàn, bảo mật và dễ bảo trì hơn.
