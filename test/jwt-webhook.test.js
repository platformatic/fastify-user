'use strict'

const fastify = require('fastify')
const { test } = require('tap')
const { createPublicKey, generateKeyPairSync } = require('crypto')
const { request, Agent, setGlobalDispatcher } = require('undici')
const { createSigner } = require('fast-jwt')
const fastifyUser = require('..')

const agent = new Agent({
  keepAliveTimeout: 10,
  keepAliveMaxTimeout: 10
})
setGlobalDispatcher(agent)

async function buildAuthorizer (opts = {}) {
  const app = fastify({
    forceCloseConnections: true
  })
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

// creates a RSA key pair for the test
const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
})
const jwtPublicKey = createPublicKey(publicKey).export({ format: 'jwk' })

async function buildJwksEndpoint (jwks, fail = false) {
  const app = fastify()
  app.get('/.well-known/jwks.json', async (request, reply) => {
    if (fail) {
      throw Error('JWKS ENDPOINT ERROR')
    }
    return jwks
  })
  await app.listen({ port: 0 })
  return app
}

test('JWT + cookies with WebHook', async ({ pass, teardown, same, equal }) => {
  const authorizer = await buildAuthorizer()
  teardown(() => authorizer.close())

  const { n, e, kty } = jwtPublicKey
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
  teardown(() => jwksEndpoint.close())

  const issuer = `http://localhost:${jwksEndpoint.server.address().port}`
  const header = {
    kid,
    alg,
    typ: 'JWT'
  }
  const app = fastify({
    forceCloseConnections: true
  })

  app.register(fastifyUser, {
    webhook: {
      url: `http://localhost:${authorizer.server.address().port}/authorize`
    },
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

  teardown(app.close.bind(app))
  teardown(() => authorizer.close())
  teardown(() => jwksEndpoint.close())

  await app.ready()

  async function getCookie (userId, role) {
    const res = await request(`http://localhost:${authorizer.server.address().port}/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        'USER-ID-FROM-WEBHOOK': userId
      })
    })

    res.body.resume()

    const cookie = res.headers['set-cookie'].split(';')[0]
    return cookie
  }

  // Must use webhooks to get user
  {
    const cookie = await getCookie(42, 'user')
    const res = await app.inject({
      method: 'GET',
      url: '/',
      headers: {
        cookie
      }
    })
    equal(res.statusCode, 200)
    same(res.json(), {
      'USER-ID-FROM-WEBHOOK': 42
    })
  }

  // Must use jwt to get user
  {
    const signSync = createSigner({
      algorithm: 'RS256',
      key: privateKey,
      header,
      iss: issuer,
      kid
    })
    const payload = {
      'USER-ID-FROM-JWT': 42
    }
    const token = signSync(payload)

    const res = await app.inject({
      method: 'GET',
      url: '/',
      headers: {
        Authorization: `Bearer ${token}`
      }
    })
    equal(res.statusCode, 200, 'pages status code')
    same(res.json(), {
      'USER-ID-FROM-JWT': 42
    })
  }
})

async function buildAuthorizerAPIToken (opts = {}) {
  const app = fastify({
    forceCloseConnections: true
  })

  app.post('/authorize', async (request, reply) => {
    return await opts.onAuthorize(request)
  })

  await app.listen({ port: 0 })
  return app
}

test('Authorization both with JWT and WebHook', async ({ pass, teardown, same, equal }) => {
  const authorizer = await buildAuthorizerAPIToken({
    async onAuthorize (request) {
      equal(request.headers.authorization, 'Bearer foobar')
      const payload = {
        'USER-ID': 42
      }

      return payload
    }
  })
  teardown(() => authorizer.close())

  const { n, e, kty } = jwtPublicKey
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
  teardown(() => jwksEndpoint.close())

  const issuer = `http://localhost:${jwksEndpoint.server.address().port}`
  const header = {
    kid,
    alg,
    typ: 'JWT'
  }
  const app = fastify({
    forceCloseConnections: true
  })

  app.register(fastifyUser, {
    webhook: {
      url: `http://localhost:${authorizer.server.address().port}/authorize`
    },
    jwt: {
      jwks: true
    },
    roleKey: 'X-PLATFORMATIC-ROLE',
    anonymousRole: 'anonymous'
  })

  app.addHook('preHandler', async (request, reply) => {
    await request.extractUser()
  })

  app.get('/', async function (request, reply) {
    return request.user
  })

  teardown(app.close.bind(app))
  teardown(() => authorizer.close())
  teardown(() => jwksEndpoint.close())

  await app.ready()

  {
    const res = await app.inject({
      method: 'GET',
      url: '/',
      headers: {
        Authorization: 'Bearer foobar'
      }
    })
    equal(res.statusCode, 200)
    same(res.json(), {
      'USER-ID': 42
    })
  }

  {
    const signSync = createSigner({
      algorithm: 'RS256',
      key: privateKey,
      header,
      iss: issuer,
      kid
    })
    const payload = {
      'USER-ID': 43
    }
    const token = signSync(payload)

    const res = await app.inject({
      method: 'GET',
      url: '/',
      headers: {
        Authorization: `Bearer ${token}`
      }
    })
    equal(res.statusCode, 200)
    same(res.json(), {
      'USER-ID': 43
    })
  }
})
