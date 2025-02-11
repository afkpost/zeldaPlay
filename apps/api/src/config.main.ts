import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as compression from 'compression';
import * as store from 'connect-redis';
import * as rateLimiter from 'express-rate-limit';
import * as session from 'express-session';
import * as helmet from 'helmet';
import * as morgan from 'morgan';
import * as passport from 'passport';
import * as redis from 'redis';
import { ConfigService } from './app/config/config.service';
import { LoggerService } from './app/logger/logger.service';

const RedisStore = store(session);

export function configure(
  app: INestApplication,
  config: ConfigService,
  logger: LoggerService,
): void {
  app.use(
    session({
      store: new RedisStore({
        client: redis.createClient({
          url: config.getRedisUrl(),
        }),
      }),
      secret: config.getSessionSecret(),
      resave: false,
      saveUninitialized: false,
      name: 'id',
      cookie: {
        sameSite: config.isProd(),
        httpOnly: config.isProd(),
        secure: config.isProd(),
        maxAge: config.getCookieAge(),
      },
    }),
    morgan(config.getMorganString(), {
      skip: (req: any, res: any) =>
        (config.isProd() && req.statusCode < 400) ||
        req.url.includes('callback'),
      stream: {
        write: (value: string) => logger.log(value.trim(), 'Morgan'),
      },
    }),
    helmet(),
    compression(),
    new rateLimiter({
      windowMs: 10 * 60 * 1000,
      max: config.getRateLimit(),
    }),
    passport.initialize(),
    passport.session(),
  );
  app.setGlobalPrefix(config.getGlobalPrefix());
  app.useGlobalPipes(new ValidationPipe());
  logger.log('Application Configuration complete', 'ApplicationConfig');
}
