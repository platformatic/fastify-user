'use strict'

const fastify = require('fastify')
const { test } = require('tap')
const { request, Agent, setGlobalDispatcher } = require('undici')
const fastifyUser = require('..')

const agent = new Agent({
  keepAliveTimeout: 10,
  keepAliveMaxTimeout: 10
})
setGlobalDispatcher(agent)

async function buildAuthorizer (opts = {}) {
  const app = fastify()
  app.register(require('@fastify/cookie'))
  app.register(require('@fastify/session'), {
    cookieName: 'sessionId',
    secret: 'a secret with minimum length of 32 characters',
    cookie: { secure: false }
  })

  app.post('/login', async (request, reply) => {
    request.session.user = request.body
    return {
      status: 'ok'
    }
  })

  app.post('/authorize', async (request, reply) => {
    if (typeof opts.onAuthorize === 'function') {
      await opts.onAuthorize(request)
    }

    const user = request.session.user
    if (!user) {
      return reply.code(401).send({ error: 'Unauthorized' })
    }
    return user
  })

  await app.listen({ port: 0 })

  return app
}

test('Webhook verify OK', async ({ pass, teardown, same, equal }) => {
  const authorizer = await buildAuthorizer()
  const app = fastify()

  app.register(fastifyUser, {
    webhook: {
      url: `http://localhost:${authorizer.server.address().port}/authorize`
    }
  })

  app.addHook('preHandler', async (request, reply) => {
    await request.extractUser()
  })

  app.get('/', async function (request, reply) {
    return request.user
  })

  app.post('/', async function (request, reply) {
    return request.user
  })

  teardown(app.close.bind(app))
  teardown(() => authorizer.close())

  await app.ready()

  async function getCookie (userId, role) {
    const res = await request(`http://localhost:${authorizer.server.address().port}/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        'USER-ID': userId
      })
    })

    res.body.resume()

    const cookie = res.headers['set-cookie'].split(';')[0]
    return cookie
  }

  const cookie = await getCookie(42, 'user')

  {
    const res = await app.inject({
      method: 'GET',
      url: '/',
      headers: {
        cookie
      }
    })
    equal(res.statusCode, 200)
    same(res.json(), {
      'USER-ID': 42
    })
  }

  {
    const res = await app.inject({
      method: 'POST',
      url: '/',
      headers: {
        cookie
      },
      body: {
        test: 'test'
      }
    })
    equal(res.statusCode, 200)
    same(res.json(), {
      'USER-ID': 42
    })
  }
})

test('Non-200 status code', async ({ end, pass, teardown, same, equal }) => {
  const authorizer = await buildAuthorizer({
    onAuthorize: async (request) => {
      if (request.headers['x-status-code']) {
        pass('authorizer called, throwing exception')
        const err = new Error('Unauthorized')
        err.statusCode = request.headers['X-STATUS-CODE']
        throw err
      }
    }
  })
  const app = fastify()

  app.register(fastifyUser, {
    webhook: {
      url: `http://localhost:${authorizer.server.address().port}/authorize`
    }
  })

  app.addHook('preHandler', async (request, reply) => {
    await request.extractUser()
  })

  app.get('/', async function (request, reply) {
    return request.user || {}
  })

  teardown(app.close.bind(app))
  teardown(() => authorizer.close())

  await app.ready()

  const res = await app.inject({
    method: 'GET',
    url: '/'
  })
  equal(res.statusCode, 200)
  same(res.json(), {})
  end()
})

test('if no webhook conf is set, no user is added', async ({ same, teardown }) => {
  const app = fastify()

  teardown(app.close.bind(app))

  app.register(fastifyUser, {})

  app.addHook('preHandler', async (request, reply) => {
    request.extractUser()
  })

  app.get('/', async function (request, reply) {
    return request.user || {}
  })

  await app.ready()

  const response = await app.inject({
    method: 'GET',
    url: '/'
  })

  same(response.statusCode, 200)
  same(response.json(), {})
})
