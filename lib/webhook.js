'use strict'

const fp = require('fastify-plugin')
const { request } = require('undici')
const createError = require('@fastify/error')

const notAllowed = new Set([
  'content-length',
  'host',
  'connection'
])

module.exports = fp(async function (app, pluginOpts) {
  const url = pluginOpts.webhook.url

  app.decorateRequest('createWebhookSession', async function () {
    const headers = {}
    for (const header of Object.keys(this.headers)) {
      if (!notAllowed.has(header)) {
        headers[header] = this.headers[header]
      }
    }
    const body = JSON.stringify(this.body)
    if (body) {
      headers['content-length'] = Buffer.byteLength(body)
    }
    const res = await request(url, {
      method: 'POST',
      headers: {
        ...headers,
        'accept-encoding': 'identity'
      },
      body
    })

    if (res.statusCode > 299) {
      const Unauthorized = createError('UNAUTHORIZED', 'operation not allowed', 401)
      throw new Unauthorized()
    }

    const data = await res.body.json()
    this.user = data
  })
})
