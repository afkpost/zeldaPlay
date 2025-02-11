import { Literal, Record, Static, String, Undefined, Union } from 'runtypes';

const NodeEnv = Union(
  Literal('prod'),
  Literal('production'),
  Literal('dev'),
  Literal('development'),
  Literal('test'),
);

const LogLevel = Union(
  Literal('INFO'),
  Literal('FATAL'),
  Literal('DEBUG'),
  Literal('ERROR'),
  Literal('WARN'),
  Literal('FINE'),
  Literal('OFF'),
);

export const EnvRunType = Record({
  DATABASE_URL: String,
  JWT_SECRET: String,
  SESSION_SECRET: String,
  REDIS_URL: String,
  GOOGLE_CLIENT: String,
  GOOGLE_SECRET: String,
  GOOGLE_CALLBACK_URL: String,
  GLOBAL_PREFIX: String,
  RATE_LIMIT: String,
  NODE_ENV: NodeEnv,
  PORT: String,
  LOG_LEVEL: LogLevel,
  JWT_EXPIRES: String,
  MORGAN_STRING: Union(Literal('dev'), Literal('combined')).Or(Undefined),
  COOKIE_AGE: String,
});

export type EnvRunType = Static<typeof EnvRunType>;

export const defaults = {
  GLOBAL_PREFIX: 'api',
  LOG_LEVEL: 'INFO',
  JWT_EXPIRES: '3600',
  PORT: '3333',
  RATE_LIMIT: '1000',
  NODE_ENV: 'development',
  GOOGLE_CALLBACK_URL: 'http://localhost:3333/api/auth/google/callback',
  COOKIE_AGE: '86400',
};
