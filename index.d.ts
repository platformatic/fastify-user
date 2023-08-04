import { type FastifyJWTOptions, type VerifyPayloadType } from '@fastify/jwt'
import { type FastifyPluginCallback, type FastifyReply, type FastifyRequest } from 'fastify'
import { type GetJwksOptions } from 'get-jwks'
import { type URL, type UrlObject } from 'url'

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

declare module 'fastify' {
  interface FastifyInstance {
    addAuthStrategy: (strategy: FastifyUserPluginAuthStrategy) => void
  }
  interface FastifyRequest {
    extractUser: () => Promise<any>
    createSession: () => Promise<void>
    createJWTSession: () => Promise<VerifyPayloadType>
    createWebhookSession: () => Promise<void>
  }
}

declare const fastifyUser: FastifyPluginCallback<FastifyUserPluginOptions>

export default fastifyUser
