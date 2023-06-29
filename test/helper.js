'use strict'

const { createPublicKey, generateKeyPairSync } = require('crypto')
const { request } = require('undici')
const fastify = require('fastify')

async function buildJwksEndpoint (jwks, fail = false) {
  const app = fastify()
  app.get('/.well-known/jwks.json', async () => {
    if (fail) {
      throw Error('JWKS ENDPOINT ERROR')
    }
    return jwks
  })
  await app.listen({ port: 0 })
  return app
}

function generateKeyPair () {
  // creates a RSA key pair for the test
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
  })
  const publicJwk = createPublicKey(publicKey).export({ format: 'jwk' })
  return { publicKey, publicJwk, privateKey }
}

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

  app.decorate('getCookie', async (cookie) => {
    const res = await request(`http://localhost:${app.server.address().port}/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(cookie)
    })

    res.body.resume()

    return res.headers['set-cookie'].split(';')[0]
  })

  await app.listen({ port: 0 })

  return app
}

module.exports = {
  generateKeyPair,
  buildJwksEndpoint,
  buildAuthorizer
}
