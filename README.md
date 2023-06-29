# Fastify User plugin

This plugin provides a [Fastify](https://www.fastify.io/) plugin to populate a `request.user` from 
a JWT token (custom claims) or a webhook (response body).

To use it, simply invoke the `extractUser` method on the request object, or add this hook:

```js
app.addHook('preHandler', async (request, reply) => {
  await request.extractUser()
})
```

If JWT valdation or the webhook call fails, the `request.user` is not set. 


## JWT
It's build on top of [fastify-jwt](https://github.com/fastify/fastify-jwt) plugin, so you can use all the options available there (with the exception of `namespace`, see [below](#namespace))

```js

const app = fastify()
app.register(fastifyUser, {
  jwt: {
    secret: <my-shared-secret>
  }
})

app.addHook('preHandler', async (request, reply) => {
  await request.extractUser()
})

app.get('/', async function (request, reply) {
  return request.user
})

await app.ready()
```

It's also possible to specify a JSON Web Key Set (JWKS) URI to retrieve the public keys from a remote server.

```js
{
  jwt: {
    jwks: {
      allowedDomains: [
        "https://ISSUER_DOMAIN"
      ]
    }
  }
}
```

Any option supported by the [get-jwks](https://github.com/nearform/get-jwks) library can be specified in the `jwt.jwks` object.

### namespace
The JWT namespace option is used to specify the namespace for custom claims used to populate `request.user`. For more info about this see [OIDC Specification](https://openid.net/specs/openid-connect-core-1_0.html). 
Since these namespace are URLs, we might want to remove it. If the `namespace` is specified it will be removed automatically:

```js
{
  jwt: {
    jwks: true,
    namespace: "https://test.com/" 
  }
}
```
In this case, if the token contains a claim `https://test.com/email`, the plugin will strip the namespace from the claim and populate `request.user.email` with its value.

## Webhook
The plugin can also populate `request.user` from a webhook.
When a request is received, fastify-user sends a POST to the webhook, replicating the same body and headers, except for:

- host
- connection

The webhook is expected to return a JSON object with the user information. The plugin will populate `request.user` with the response body.

Example of options:

```js
{
  webhook: {
    url: `http://my-webhook-url/authorize`
  }
}
```

## JWT and Webhook
In case both `jwt` and `webhook` options are specified, the plugin will try to populate `request.user` from the JWT token first. If the token is not valid, it will try to populate `request.user` from the webhook.


## Custom auth strategies

In case if you want to use your own auth strategy, you can pass it as an option to the plugin. All custom auth strategies should have `createSession` method, which will be called on every request. This method should set `request.user` object. All custom strategies will be executed after `jwt` and `webhook` strategies.

```js
{
  authStrategies: [{
    name: 'myAuthStrategy',
    createSession: async function (request, reply) {
      req.user = { id: 42, role: 'admin' }
    }
  }]
}
```

or you can add it via `addAuthStrategy` method:

```js
app.addAuthStrategy({
  name: 'myAuthStrategy',
  createSession: async function (request, reply) {
    req.user = { id: 42, role: 'admin' }
  }
})
```

## Run Tests

```
npm test
```



