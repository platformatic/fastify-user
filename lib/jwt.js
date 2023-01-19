'use strict'

const jwt = require('@fastify/jwt')
const fp = require('fastify-plugin')
const buildGetJwks = require('get-jwks')

module.exports = fp(async function (app, pluginOpts) {
  const {
    jwt: opts
  } = pluginOpts

  const namespace = opts?.namespace
  // @fastify/jwt has also a `namespace` property, but it's not the same (and we don't
  // need it), so we remove it. See: https://github.com/fastify/fastify-jwt#namespace
  delete opts.namespace

  const formatUser = namespace
    ? user => {
      const userDataNoNamespace = {}
      for (const key of Object.keys(user)) {
        if (key.startsWith(namespace)) {
          userDataNoNamespace[key.slice(namespace.length)] = user[key]
        } else {
          userDataNoNamespace[key] = user[key]
        }
      }
      return userDataNoNamespace
    }
    : user => user

  if (opts.jwks) {
    const getJwks = buildGetJwks(typeof opts.jwks === 'object' ? opts.jwks : {})
    app.register(jwt, {
      formatUser,
      ...opts,
      decode: { complete: true },
      secret: function (request, token) {
        const {
          header: { kid, alg },
          payload: { iss }
        } = token
        return getJwks.getPublicKey({ kid, domain: iss, alg })
      }
    })
  } else {
    app.register(jwt, { formatUser, ...opts })
  }

  app.decorateRequest('createJWTSession', async function () {
    const ret = await this.jwtVerify()
    // iss (issuer) and iat (issued at) are claims from JWT, no need to pass them to the user
    const { iss, iat, ...user } = this.user
    this.user = user
    return ret
  })
})
