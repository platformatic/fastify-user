const fp = require('fastify-plugin')

/**
  * Namespace applies to both JWT and headers
  * We can have JWT, webhook or both. In teh "both" case:
  * 1. JWT is checked first, if this is OK, the user is created from the JWT token
  * 2. If JWT is not OK, the user is created from the answer returned by the webhook (currently the body)
  */
async function fastifyUser (app, options, done) {
  const {
    webhook,
    jwt
  } = options

  if (jwt) {
    await app.register(require('./lib/jwt'), { jwt })
  }

  if (webhook) {
    await app.register(require('./lib/webhook'), { webhook })
  }

  if (jwt && webhook) {
    app.decorateRequest('createSession', async function () {
      try {
        // `createSession` actually exists only if jwt or webhook are enabled
        // and creates a new `request.user` object
        await this.createJWTSession()
      } catch (err) {
        this.log.trace({ err })

        await this.createWebhookSession()
      }
    })
  } else if (jwt) {
    app.decorateRequest('createSession', function () {
      return this.createJWTSession()
    })
  } else if (webhook) {
    app.decorateRequest('createSession', function () {
      return this.createWebhookSession()
    })
  }

  const extractUser = async function () {
    const request = this
    if (typeof request.createSession === 'function') {
      try {
      // `createSession` actually exists only if jwt or webhook are enabled
      // and creates a new `request.user` object
        await request.createSession()
        request.log.debug({ user: request.user }, 'logged user in')
      } catch (err) {
        request.log.error({ err })
      }
    }
    return request.user
  }

  app.decorateRequest('extractUser', extractUser)

  done()
}

module.exports = fp(fastifyUser, {
  fastify: '4.x',
  name: 'fastify-user'
})

module.exports.default = fastifyUser
module.exports.fastifyUser = fastifyUser
