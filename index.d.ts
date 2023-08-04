import { FastifyJWTOptions } from '@fastify/jwt'
import { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify'
import { GetJwksOptions } from 'get-jwks'
import { URL, UrlObject } from 'url'

export interface FastifyUserPluginJWTOptions extends FastifyJWTOptions {
  namespace?: string
  jwks?: boolean | GetJwksOptions
}

export interface FastifyUserPluginWebhookOptions {
  url: string | URL | UrlObject
}

export type FastifyUserPluginCreateSession = (request?: FastifyRequest, reply?: FastifyReply) => Promise<void>

export interface FastifyUserPluginAuthStrategy {
  name: string,
  createSession: FastifyUserPluginCreateSession
}

export interface FastifyUserPluginOptions {
  jwt?: FastifyUserPluginJWTOptions
  webhook?: FastifyUserPluginWebhookOptions
  authStrategies?: FastifyUserPluginAuthStrategy[]
}

declare const fastifyUser: FastifyPluginAsync<FastifyUserPluginOptions>

export default fastifyUser
