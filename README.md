# virus-scanner-service

Microservice to perform a virus scan on uploaded files.

This service listens for delta notifications about new files and scans
those for viruses.

[![Project Status: WIP – Initial development is in progress](https://www.repostatus.org/badges/latest/wip.svg)](https://www.repostatus.org/#wip)

## Getting started

Prerequisites:
- [file-service](https://github.com/mu-semtech/file-service)
- [mu-authorization](https://github.com/mu-semtech/mu-authorization)
- [delta-notifier](https://github.com/mu-semtech/delta-notifier)

### Adding the service to your stack

Add the following snippet to your `docker-compose.yml` to include this
service in your project.

```yaml
version: '3.4'

services:
  virus-scanner:
    build: https://github.com/peternowee/virus-scanner-service.git#v0.0.4
    links:
      - database:database
    volumes:
      - ./data/files:/share
      - type: volume
        source: virus-scanner-signatures
        target: /var/lib/clamav

volumes:
  virus-scanner-signatures:
```

Add rules to `dispatcher.ex` to dispatch requests to this service. E.g.

```elixir
  match "/virus-scanner/*path" do
    Proxy.forward conn, path, "http://virus-scanner/virus-scanner/"
  end
```

Add delta-notifier to your stack as described in the [delta-notifier
documentation](https://github.com/mu-semtech/delta-notifier#readme).
Then configure delta-notifier to send relevant deltas to virus-scanner
by adding the following snippet to `config/delta/rules.js`:

```js
export default [
  {
    match: {
      predicate: {
        type: 'uri',
        value: 'http://www.semanticdesktop.org/ontologies/2007/01/19/nie#dataSource'
      },
    },
    callback: {
      url: 'http://virus-scanner/delta',
      method: 'POST',
    },
    options: {
      resourceFormat: 'v0.0.1',
      gracePeriod: 1000,
      ignoreFromSelf: true,
    }
  },
  // Other delta listeners
]
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
      LOG_INCOMING_DELTA: "true"
    volumes:
      - ../virus-scanner-service/:/app/
```

## Configuration

### Environment variables

The following enviroment variables can be configured:

* `LOG_INCOMING_DELTA (default: "false")`: log the delta message as
  received from the delta-notifier to the console.
* The environment variables recognized by
  [mu-javascript-template](https://github.com/mu-semtech/mu-javascript-template/blob/v1.7.0/README.md#environment-variables).
