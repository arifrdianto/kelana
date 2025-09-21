import { ServerResponse } from 'http';
import { IncomingMessage } from 'http';

import { Params } from 'nestjs-pino';

const isProduction = process.env.NODE_ENV === 'production';

const pinoConfig: Params = {
  pinoHttp: {
    autoLogging: true,
    base: isProduction ? undefined : null,
    timestamp: true,
    quietReqLogger: true,
    genReqId: (req) => req.headers['x-request-id'] || req.id,
    level: isProduction ? 'info' : 'debug',
    name: process.env.SERVICE_NAME || 'Klana',
    transport: isProduction
      ? undefined
      : {
          target: 'pino-pretty',
          options: {
            colorize: true,
            singleLine: true,
            translateTime: 'yyyy-mm-dd HH:MM:ss',
            ignore: 'pid,hostname',
          },
        },
    serializers: {
      req: (req: IncomingMessage) => ({
        id: req.id,
        method: req.method,
        url: req.url,
        headers: {
          host: req.headers.host,
          'user-agent': req.headers['user-agent'],
          'content-type': req.headers['content-type'],
        },
        remoteAddress: req.socket?.remoteAddress,
        remotePort: req.socket?.remotePort,
      }),
      res: (res: ServerResponse & { headers: Record<string, string | string[] | undefined> }) => ({
        statusCode: res.statusCode,
        headers: {
          'content-type': res.headers['content-type'],
          'content-length': res.headers['content-length'],
        },
      }),
      err: (err: Error) => ({
        type: err.constructor.name,
        message: err.message,
        stack: isProduction ? undefined : err.stack,
      }),
    },
  },
};

export { pinoConfig };
