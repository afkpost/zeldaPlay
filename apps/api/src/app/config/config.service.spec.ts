import { Test, TestingModule } from '@nestjs/testing';
import * as dotenv from 'dotenv';
import { ConfigService } from './config.service';
jest.mock('fs');
jest.mock('path');

const postgresURL = 'postgres://postgres:postgres@localhost:5432/testing';
const redisURL = 'redis://redis:redis@localhost:9999/testing';

describe('ConfigService', () => {
  let service: ConfigService;

  beforeEach(() => {
    service = null as any;
  });

  describe('process.env config', () => {
    beforeAll(() => {
      process.env.NODE_ENV = 'production';
      process.env.DATABASE_URL = postgresURL;
      process.env.PORT = '3333';
      process.env.JWT_SECRET = 'itsasecret';
      process.env.RATE_LIMIT = '4040';
      process.env.SESSION_SECRET = 'itsasecert';
      process.env.REDIS_URL = redisURL;
      process.env.GOOGLE_SECRET = 'google_secret';
      process.env.GOOGLE_CLIENT = 'google_client';
    });
    beforeEach(async () => {
      const module: TestingModule = await Test.createTestingModule({
        providers: [
          {
            provide: ConfigService,
            useFactory: () => new ConfigService({ useProcess: true }),
          },
        ],
      }).compile();

      service = module.get<ConfigService>(ConfigService);
    });
    it('should get the NODE_ENV', () => {
      expect(service.getNodeEnv()).toBe('production');
    });
    it('should return true for isProd', () => {
      expect(service.isProd()).toBe(true);
    });
    it('should return 4040 for RATE_LIMIT', () => {
      expect(service.getRateLimit()).toBe(4040);
    });
    it('should get the Database url', () => {
      expect(service.getDatabaseUrl()).toBe(postgresURL);
    });
    it('should get the morgan string', () => {
      morganTest('combined', service);
    });
    it('should get the cookie age', () => {
      expect(service.getCookieAge()).toBe(86400 * 1000);
    });
  });

  describe('.env config', () => {
    jest.spyOn(dotenv, 'parse').mockReturnValue({
      DATABASE_URL: postgresURL,
      NODE_ENV: 'dev',
      JWT_SECRET: 'itsasecret',
      SESSION_SECRET: 'itsasecret',
      REDIS_URL: redisURL,
      GOOGLE_CLIENT: 'google_client',
      GOOGLE_SECRET: 'google_secret',
    });
    beforeEach(async () => {
      process.env.NODE_ENV = 'dev';
      const module: TestingModule = await Test.createTestingModule({
        providers: [
          {
            provide: ConfigService,
            useFactory: () => new ConfigService({ fileName: '.env' }),
          },
        ],
      }).compile();

      service = module.get<ConfigService>(ConfigService);
    });
    it('should get PORT', () => {
      expect(service.getPort()).toBe(3333);
    });
    it('should return dev for NODE_ENV', () => {
      expect(service.getNodeEnv()).toBe('dev');
    });
    it('should return false for isProd', () => {
      expect(service.isProd()).toBe(false);
    });
    it('should return 1000 for RATE_LIMIT', () => {
      expect(service.getRateLimit()).toBe(1000);
    });
    it('should return a redis url', () => {
      expect(service.getRedisUrl()).toBe(redisURL);
    });
    it('should return the jwt secret', () => {
      expect(service.getJwtSecret()).toBe('itsasecret');
    });
    it('should return the jwt expires in', () => {
      expect(service.getJwtExpiresIn()).toBe('3600');
    });
    it('should return a session secret', () => {
      expect(service.getSessionSecret()).toBe('itsasecret');
    });
    it('should return a global prefix', () => {
      expect(service.getGlobalPrefix()).toBe('api');
    });
    it('should return a log level', () => {
      expect(service.getLogLevel()).toBe('INFO');
    });
    it('should return the google secret', () => {
      expect(service.getGoogleSecret()).toBe('google_secret');
    });
    it('should return the google client', () => {
      expect(service.getGoogleClient()).toBe('google_client');
    });
    it('should return the google callback', () => {
      expect(service.getGoogleCallback()).toBe(
        'http://localhost:3333/api/auth/google/callback',
      );
    });
    it('should get the morgan string', () => {
      morganTest('dev', service);
    });
  });

  describe('failing config', () => {
    beforeAll(() => {
      process.env.NODE_ENV = 'production';
      process.env.PORT = '4444';
      process.env.DATABASE_URL = '';
    });

    it('should fail in a try catch (no database url)', async () => {
      try {
        const module: TestingModule = await Test.createTestingModule({
          providers: [
            {
              provide: ConfigService,
              useFactory: () => new ConfigService({ useProcess: true }),
            },
          ],
        }).compile();

        service = module.get<ConfigService>(ConfigService);
      } catch (err) {
        expect(err).toBeTruthy();
        expect(err.message).toBe(
          'Config validation error: "DATABASE_URL" is not allowed to be empty',
        );
      }
    });
    it('should fail in a try catch (no parameter passed)', async () => {
      try {
        const module: TestingModule = await Test.createTestingModule({
          providers: [
            { provide: ConfigService, useFactory: () => new ConfigService({}) },
          ],
        }).compile();

        service = module.get<ConfigService>(ConfigService);
      } catch (err) {
        expect(err).toBeTruthy();
        expect(err.message).toBe(
          'Missing configuration options.' +
            ' If using process.env variables, please mark useProcess as "true".' +
            ' Otherwise, please provide and env file.',
        );
      }
    });
  });
});

const morganTest = (morganString: string, service: ConfigService) => {
  const configSpy = jest.spyOn(service, 'isProd');
  expect(service.getMorganString()).toBe(morganString);
  expect(configSpy).toBeCalledTimes(1);
  expect(service.getMorganString()).toBe(morganString);
  expect(configSpy).toBeCalledTimes(1);
  configSpy.mockClear();
};
