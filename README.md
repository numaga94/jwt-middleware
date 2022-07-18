# JWT Middleware

JWT Middleware is a middleware plugin for [Traefik](https://github.com/containous/traefik) which verifies a jwt token and adds the payload as injected header to the request

## Configuration

1. Add this snippet in the Traefik Static Configuration:

```yaml
experimental:
  plugins:
    jwt-middleware:
      moduleName: 'github.com/numaga94/jwt-middleware'
      version: 'v0.0.5'

command:
  - '--experimental.plugins.jwt-middleware.modulename=github.com/numaga94/jwt-middleware'
  - '--experimental.plugins.jwt-middleware.version=v0.0.5'
```

2. Configure the plugin using the Dynamic Configuration.

```yaml
http:
  middlewares:
    jwt-middleware:
      plugin:
        jwt-middleware:
          secret: SECRET
          allowedRoles: `super,admin,staff`
          pathsToBeChecked: `/static/document/, /static/file/, /static/staff/`
          authHeader: Authorization
          headerPrefix: Bearer
          encodedHeader: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ._XEngvIuxOcA-j7y_upRUbXli4DLToNf7HxH1XNmxSc

```

Use as docker-compose label

```yaml
labels:
  - 'traefik.http.routers.my-service.middlewares=jwt-middleware@file'
```
