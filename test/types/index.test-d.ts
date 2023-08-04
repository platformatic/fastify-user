import fastify, { type FastifyInstance } from 'fastify'
import { expectType } from 'tsd'
import fastifyUser, { type AddAuthStrategyDecorator } from '../..'

const app: FastifyInstance = fastify()
app.register(fastifyUser)
app.register(async (instance) => {
  expectType<AddAuthStrategyDecorator>(instance.addAuthStrategy)
})

