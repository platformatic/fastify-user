/// <reference path="./index.d.ts" />

import fastify from 'fastify'
import { expectType } from 'tsd'
import fastifyUser, { type FastifyUserPluginAuthStrategy } from '.'

const app = fastify()
app.register(fastifyUser)

expectType<(strategy: FastifyUserPluginAuthStrategy) => void>(app.addAuthStrategy)
