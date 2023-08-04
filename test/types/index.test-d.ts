import fastify, { type FastifyInstance } from 'fastify'
import { expectType } from 'tsd'
import fastifyUser, { type FastifyUserPluginAuthStrategy } from '../..'

const app: FastifyInstance = fastify()
app.register(fastifyUser)
app.register(async (instance) => {
  expectType<(strategy: FastifyUserPluginAuthStrategy) => void>(instance.addAuthStrategy)
})

