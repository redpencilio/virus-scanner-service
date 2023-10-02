# virus-scanner-service

Microservice to perform a virus scan on uploaded files.

[![Project Status: WIP – Initial development is in progress](https://www.repostatus.org/badges/latest/wip.svg)](https://www.repostatus.org/#wip)

## Getting started

### Adding the service to your stack

Add the following snippet to your `docker-compose.yml` to include this
service in your project.

```yaml
version: '3.4'

services:
  virus-scanner:
    build: https://github.com/peternowee/virus-scanner-service.git#v0.0.1
    links:
      - database:database
```

Add rules to `dispatcher.ex` to dispatch requests to the static file
service.

E.g.
```elixir
  match "/virus-scanner/*path" do
    Proxy.forward conn, path, "http://virus-scanner/virus-scanner/"
  end
```

Run `docker-compose up` and the service should be reachable through the
dispatcher, for example at http://localhost/virus-scanner/query .

## Development

For a more detailed look in how to develop a microservice based on the
[mu-javascript-template](https://github.com/mu-semtech/mu-javascript-template),
we would recommend reading "[Developing with the
template](https://github.com/mu-semtech/mu-javascript-template#developing-with-the-template)".

### Developing in the `mu.semte.ch` stack

Paste the following snippet in your `docker-compose.override.yml`,
replacing `../virus-scanner-service/` with an absolute or relative path
pointing to your local sources:

```yaml
version: '3.4'

services:
  virus-scanner:
    ports:
      - "8893:80"
      - "9229:9229"
    environment:
      NODE_ENV: "development"
    volumes:
      - ./data/files:/share
      - ../virus-scanner-service/:/app/
```
