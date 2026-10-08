'use strict'

const fastify = require('fastify')
const { test } = require('node:test')
const assert = require('node:assert')
const { Agent, setGlobalDispatcher } = require('undici')
const fastifyUser = require('..')

const { buildAuthorizer } = require('./helper')

const agent = new Agent({
  keepAliveTimeout: 10,
  keepAliveMaxTimeout: 10
})
setGlobalDispatcher(agent)

test('Webhook verify OK', async (t) => {
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

  t.after(() => app.close())
  t.after(() => authorizer.close())

  await app.ready()

  const cookie = await authorizer.getCookie({ 'USER-ID': 42 })

  {
    const res = await app.inject({
      method: 'GET',
      url: '/',
      headers: {
        cookie
      }
    })
    assert.strictEqual(res.statusCode, 200)
    assert.deepStrictEqual(res.json(), {
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
    assert.strictEqual(res.statusCode, 200)
    assert.deepStrictEqual(res.json(), {
      'USER-ID': 42
    })
  }
})

test('Non-200 status code', async (t) => {
  const authorizer = await buildAuthorizer({
    onAuthorize: async (request) => {
      if (request.headers['x-status-code']) {
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

  t.after(() => app.close())
  t.after(() => authorizer.close())

  await app.ready()

  const res = await app.inject({
    method: 'GET',
    url: '/'
  })
  assert.strictEqual(res.statusCode, 200)
  assert.deepStrictEqual(res.json(), {})
})

test('if no webhook conf is set, no user is added', async (t) => {
  const app = fastify()

  t.after(() => app.close())

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

  assert.deepStrictEqual(response.statusCode, 200)
  assert.deepStrictEqual(response.json(), {})
})
