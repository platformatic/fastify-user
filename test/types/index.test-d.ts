import fastify, { type FastifyInstance } from 'fastify'
import { expectType } from 'tsd'
import fastifyUser, {
  type AddAuthStrategyDecorator,
  type CreateJWTSessionDecorator,
  type CreateSessionDecorator,
  type CreateWebhookSessionDecorator,
  type ExtractUserDecorator
} from '../..'

const app: FastifyInstance = fastify()
app.register(fastifyUser)
app.register(async (instance) => {
  expectType<AddAuthStrategyDecorator>(instance.addAuthStrategy)

  instance.get('/', async (request) => {
    expectType<ExtractUserDecorator>(request.extractUser)
    expectType<CreateSessionDecorator>(request.createSession)
    expectType<CreateSessionDecorator>(request.createSession)
    expectType<CreateJWTSessionDecorator>(request.createJWTSession)
    expectType<CreateWebhookSessionDecorator>(request.createWebhookSession)
  })
})

