'use strict'

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
    jwt,
    authStrategies
  } = options

  const strategies = []

  if (jwt) {
    await app.register(require('./lib/jwt'), { jwt })
    strategies.push({
      name: 'jwt',
      createSession: (req) => req.createJWTSession()
    })
  }

  if (webhook) {
    await app.register(require('./lib/webhook'), { webhook })
    strategies.push({
      name: 'webhook',
      createSession: (req) => req.createWebhookSession()
    })
  }

  for (const strategy of authStrategies || []) {
    strategies.push(strategy)
  }

  app.decorate('addAuthStrategy', (strategy) => {
    strategies.push(strategy)
  })

  app.decorateRequest('createSession', async function () {
    const errors = []
    for (const strategy of strategies) {
      try {
        return await strategy.createSession(this)
      } catch (error) {
        errors.push({ strategy: strategy.name, error })
        this.log.trace({ strategy: strategy.name, error })
      }
    }

    if (errors.length === 1) {
      throw new Error(errors[0].error)
    }

    const errorsMessage = errors.map(({ strategy, error }) => `${strategy}: ${error}`).join('; ')
    throw new Error(`No auth strategy succeeded. ${errorsMessage}`)
  })

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
