'use strict'

const fastify = require('fastify')
const { test } = require('tap')
const { Agent, setGlobalDispatcher } = require('undici')
const fastifyUser = require('..')

const { buildAuthorizer } = require('./helper')

const agent = new Agent({
  keepAliveTimeout: 10,
  keepAliveMaxTimeout: 10
})
setGlobalDispatcher(agent)

test('custom auth strategy', async ({ teardown, strictSame, equal }) => {
  const app = fastify({
    forceCloseConnections: true
  })

  app.register(fastifyUser, {
    authStrategies: [{
      name: 'myStrategy',
      createSession: async function (req) {
        req.user = { id: 42, role: 'user' }
      }
    }]
  })

  app.addHook('preHandler', async (request, reply) => {
    await request.extractUser()
  })

  app.get('/', async function (request, reply) {
    return request.user
  })

  teardown(app.close.bind(app))

  await app.ready()

  {
    const res = await app.inject({ method: 'GET', url: '/' })
    equal(res.statusCode, 200)
    strictSame(res.json(), { id: 42, role: 'user' })
  }
})

test('multiple custom strategies', async ({ teardown, strictSame, equal }) => {
  const app = fastify({
    forceCloseConnections: true
  })

  app.register(fastifyUser, {
    authStrategies: [
      {
        name: 'myStrategy1',
        createSession: function () {
          throw new Error('myStrategy1 failed')
        }
      },
      {
        name: 'myStrategy2',
        createSession: async function (req) {
          req.user = { id: 43, role: 'user' }
        }
      }
    ]
  })

  app.addHook('preHandler', async (request, reply) => {
    await request.extractUser()
  })

  app.get('/', async function (request, reply) {
    return request.user
  })

  teardown(app.close.bind(app))

  await app.ready()

  {
    const res = await app.inject({ method: 'GET', url: '/' })
    equal(res.statusCode, 200)
    strictSame(res.json(), { id: 43, role: 'user' })
  }
})

test('webhook + custom strategy', async ({ teardown, strictSame, equal }) => {
  const authorizer = await buildAuthorizer()
  teardown(() => authorizer.close())

  const app = fastify({
    forceCloseConnections: true
  })

  app.register(fastifyUser, {
    webhook: {
      url: `http://localhost:${authorizer.server.address().port}/authorize`
    },
    authStrategies: [
      {
        name: 'myStrategy1',
        createSession: function (req) {
          if (req.headers['x-custom-auth'] !== undefined) {
            req.user = { id: 42, role: 'user' }
          } else {
            throw new Error('myStrategy1 failed')
          }
        }
      }
    ]
  })

  app.addHook('preHandler', async (request, reply) => {
    await request.extractUser()
  })

  app.get('/', async function (request, reply) {
    return request.user
  })

  teardown(app.close.bind(app))
  teardown(() => authorizer.close())

  await app.ready()

  {
    const cookie = await authorizer.getCookie({
      'USER-ID-FROM-WEBHOOK': 42
    })

    const res = await app.inject({
      method: 'GET',
      url: '/',
      headers: {
        cookie
      }
    })
    equal(res.statusCode, 200)
    strictSame(res.json(), {
      'USER-ID-FROM-WEBHOOK': 42
    })
  }

  {
    const res = await app.inject({
      method: 'GET',
      url: '/',
      headers: {
        'x-custom-auth': 'true'
      }
    })
    equal(res.statusCode, 200)
    strictSame(res.json(), { id: 42, role: 'user' })
  }
})

test('add custom strategy via addCustomStrategy hook', async ({ teardown, strictSame, equal }) => {
  const app = fastify({
    forceCloseConnections: true
  })

  await app.register(fastifyUser)

  app.addAuthStrategy({
    name: 'myStrategy',
    createSession: async function (req) {
      req.user = { id: 42, role: 'user' }
    }
  })

  app.addHook('preHandler', async (request, reply) => {
    await request.extractUser()
  })

  app.get('/', async function (request, reply) {
    return request.user
  })

  teardown(app.close.bind(app))

  await app.ready()

  {
    const res = await app.inject({ method: 'GET', url: '/' })
    equal(res.statusCode, 200)
    strictSame(res.json(), { id: 42, role: 'user' })
  }
})
