# JWT Middleware

JWT Middleware is a middleware plugin for [Traefik](https://github.com/containous/traefik) which verifies a jwt token and adds the payload as injected header to the request

## Configuration

Start with command

```yaml
command:
  - '--experimental.plugins.jwt-middleware.modulename=github.com/numaga94/jwt-middleware'
  - '--experimental.plugins.jwt-middleware.version=v0.0.3'
```

Activate plugin in your config

```yaml
http:
  middlewares:
    jwt-middleware:
      plugin:
        jwt-middleware:
          secret: SECRET
          allowedRoles: `super,admin,staff`
          authHeader: Authorization
          headerPrefix: Bearer
```

Use as docker-compose label

```yaml
labels:
  - 'traefik.http.routers.my-service.middlewares=jwt-middleware@file'
```
