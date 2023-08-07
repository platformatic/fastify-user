import { type FastifyJWTOptions, type VerifyPayloadType } from '@fastify/jwt'
import { type FastifyPluginCallback, type FastifyReply, type FastifyRequest } from 'fastify'
import { type GetJwksOptions } from 'get-jwks'
import { type URL, type UrlObject } from 'url'

export interface JWTOptions extends FastifyJWTOptions {
  namespace?: string
  jwks?: boolean | GetJwksOptions
}

export interface WebhookOptions {
  url: string | URL | UrlObject
}

export type CreateSession = (request?: FastifyRequest, reply?: FastifyReply) => Promise<void>

export interface AuthStrategy {
  name: string,
  createSession: CreateSession
}

export interface FastifyUserPluginOptions {
  jwt?: JWTOptions
  webhook?: WebhookOptions
  authStrategies?: AuthStrategy[]
}

export type AddAuthStrategyDecorator = (strategy: AuthStrategy) => void
export type ExtractUserDecorator = () => Promise<any>
export type CreateSessionDecorator = () => Promise<void>
export type CreateJWTSessionDecorator = () => Promise<VerifyPayloadType>
export type CreateWebhookSessionDecorator = () => Promise<void>

declare module 'fastify' {
  interface FastifyInstance {
    addAuthStrategy: AddAuthStrategyDecorator
  }
  interface FastifyRequest {
    extractUser: ExtractUserDecorator
    createSession: CreateSessionDecorator
    createJWTSession: CreateJWTSessionDecorator
    createWebhookSession: CreateWebhookSessionDecorator
  }
}

declare const fastifyUser: FastifyPluginCallback<FastifyUserPluginOptions>

export default fastifyUser
