'use strict'

const fastify = require('fastify')
const { test } = require('node:test')
const assert = require('node:assert')
const { createSigner } = require('fast-jwt')
const fastifyUser = require('..')

const { generateKeyPair, buildJwksEndpoint } = require('./helper')

const { publicJwk, privateKey } = generateKeyPair()

test('JWT verify OK using shared secret', async (t) => {
  const payload = {
    'USER-ID': 42
  }

  const app = fastify()

  t.after(() => app.close())

  app.register(fastifyUser, {
    jwt: {
      secret: 'supersecret'
    }
  })

  app.addHook('preHandler', async (request, reply) => {
    await request.extractUser()
  })

  app.get('/', async function (request, reply) {
    return request.user
  })

  await app.ready()

  const token = await app.jwt.sign(payload)

  const response = await app.inject({
    method: 'GET',
    url: '/',
    headers: {
      Authorization: `Bearer ${token}`
    }
  })

  assert.deepStrictEqual(response.statusCode, 200)
  assert.deepStrictEqual(response.json(), {
    'USER-ID': 42
  })
})

test('JWT verify OK getting public key from jwks endpoint', async (t) => {
  const { n, e, kty } = publicJwk
  const kid = 'TEST-KID'
  const alg = 'RS256'
  const jwksEndpoint = await buildJwksEndpoint(
    {
      keys: [
        {
          alg,
          kty,
          n,
          e,
          use: 'sig',
          kid
        }
      ]
    }
  )
  const issuer = `http://localhost:${jwksEndpoint.server.address().port}`
  const header = {
    kid,
    alg,
    typ: 'JWT'
  }
  const payload = {
    'USER-ID': 42
  }

  const app = fastify()

  t.after(() => app.close())
  t.after(() => jwksEndpoint.close())

  app.register(fastifyUser, {
    jwt: {
      jwks: true
    }
  })

  app.addHook('preHandler', async (request, reply) => {
    await request.extractUser()
  })

  app.get('/', async function (request, reply) {
    return request.user
  })

  await app.ready()

  const signSync = createSigner({
    algorithm: 'RS256',
    key: privateKey,
    header,
    iss: issuer,
    kid
  })
  const token = signSync(payload)

  const response = await app.inject({
    method: 'GET',
    url: '/',
    headers: {
      Authorization: `Bearer ${token}`
    }
  })

  assert.deepStrictEqual(response.statusCode, 200)
  assert.deepStrictEqual(response.json(), {
    'USER-ID': 42
  })
})

test('jwt verify fails if getting public key from jwks endpoint fails, so no user is added', async (t) => {
  const kid = 'TEST-KID'
  const alg = 'RS256'
  // This fails
  const jwksEndpoint = await buildJwksEndpoint(
    {}, true
  )
  const issuer = `http://localhost:${jwksEndpoint.server.address().port}`
  const header = {
    kid,
    alg,
    typ: 'JWT'
  }
  const payload = {
    'USER-ID': 42
  }

  const app = fastify()

  t.after(() => app.close())
  t.after(() => jwksEndpoint.close())

  app.register(fastifyUser, {
    jwt: {
      jwks: true
    }
  })

  app.addHook('preHandler', async (request, reply) => {
    await request.extractUser()
  })

  app.get('/', async function (request, reply) {
    return request.user
  })

  await app.ready()

  const signSync = createSigner({
    algorithm: 'RS256',
    key: privateKey,
    header,
    iss: issuer,
    kid
  })
  const token = signSync(payload)

  const res = await app.inject({
    method: 'GET',
    url: '/',
    headers: {
      Authorization: `Bearer ${token}`
    }
  })

  assert.strictEqual(res.statusCode, 200)
  assert.deepStrictEqual(res.json(), null)
})

test('jwt verify fail if jwks succeed but kid is not found', async (t) => {
  const { n, e, kty } = publicJwk
  const kid = 'TEST-KID'
  const alg = 'RS256'

  const jwksEndpoint = await buildJwksEndpoint(
    {
      keys: [
        {
          alg,
          kty,
          n,
          e,
          use: 'sig',
          kid
        }
      ]
    }
  )

  const issuer = `http://localhost:${jwksEndpoint.server.address().port}`
  const header = {
    kid: 'DIFFERENT_KID',
    alg,
    typ: 'JWT'
  }
  const payload = {
    'USER-ID': 42
  }

  const app = fastify()

  app.register(fastifyUser, {
    jwt: {
      jwks: true
    }
  })

  app.addHook('preHandler', async (request, reply) => {
    await request.extractUser()
  })

  app.get('/', async function (request, reply) {
    return request.user
  })

  t.after(() => app.close())
  t.after(() => jwksEndpoint.close())

  await app.ready()

  const signSync = createSigner({
    algorithm: 'RS256',
    key: privateKey,
    header,
    iss: issuer,
    kid
  })
  const token = signSync(payload)

  const res = await app.inject({
    method: 'GET',
    url: '/',
    headers: {
      Authorization: `Bearer ${token}`
    }
  })

  assert.strictEqual(res.statusCode, 200)
  assert.deepStrictEqual(res.json(), null)
})

test('jwt verify fails if the domain is not allowed', async (t) => {
  const { n, e, kty } = publicJwk
  const kid = 'TEST-KID'
  const alg = 'RS256'

  const jwksEndpoint = await buildJwksEndpoint(
    {
      keys: [
        {
          alg,
          kty,
          n,
          e,
          use: 'sig',
          kid
        }
      ]
    }
  )

  const issuer = `http://localhost:${jwksEndpoint.server.address().port}`
  const header = {
    kid,
    alg,
    typ: 'JWT'
  }
  const payload = {
    'USER-ID': 42
  }

  const app = fastify()

  app.register(fastifyUser, {
    jwt: {
      jwks: {
        allowedDomains: ['http://myalloawedomain.com']
      }
    }
  })

  app.addHook('preHandler', async (request, reply) => {
    await request.extractUser()
  })

  app.get('/', async function (request, reply) {
    return request.user
  })

  t.after(() => app.close())
  t.after(() => jwksEndpoint.close())

  await app.ready()

  const signSync = createSigner({
    algorithm: 'RS256',
    key: privateKey,
    header,
    iss: issuer,
    kid
  })
  const token = signSync(payload)

  const res = await app.inject({
    method: 'GET',
    url: '/',
    headers: {
      Authorization: `Bearer ${token}`
    }
  })

  assert.strictEqual(res.statusCode, 200)
  assert.deepStrictEqual(res.json(), null)
})

test('jwt skips namespace in custom claims', async (t) => {
  const { n, e, kty } = publicJwk
  const kid = 'TEST-KID'
  const alg = 'RS256'
  const jwksEndpoint = await buildJwksEndpoint(
    {
      keys: [
        {
          alg,
          kty,
          n,
          e,
          use: 'sig',
          kid
        }
      ]
    }
  )
  const issuer = `http://localhost:${jwksEndpoint.server.address().port}`
  const header = {
    kid,
    alg,
    typ: 'JWT'
  }
  const namespace = 'https://test.com/'
  const payload = {
    [`${namespace}USER-ID`]: 42
  }

  const app = fastify()

  app.register(fastifyUser, {
    jwt: {
      jwks: true,
      namespace
    }
  })

  app.addHook('preHandler', async (request, reply) => {
    await request.extractUser()
  })

  app.get('/', async function (request, reply) {
    return request.user
  })

  t.after(() => app.close())
  t.after(() => jwksEndpoint.close())

  await app.ready()

  const signSync = createSigner({
    algorithm: 'RS256',
    key: privateKey,
    header,
    iss: issuer,
    kid
  })
  const token = signSync(payload)

  const response = await app.inject({
    method: 'GET',
    url: '/',
    headers: {
      Authorization: `Bearer ${token}`
    }
  })

  assert.deepStrictEqual(response.statusCode, 200)
  assert.deepStrictEqual(response.json(), {
    'USER-ID': 42
  })
})

test('if no jwt conf is set, no user is added', async (t) => {
  const app = fastify()

  t.after(() => app.close())

  app.register(fastifyUser, {})

  app.addHook('preHandler', async (request, reply) => {
    await request.extractUser()
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
