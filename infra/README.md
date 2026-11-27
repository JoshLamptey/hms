# Container workflows

## Development

Copy `.env.example` to `.env`, then start the API, PostgreSQL, Redis, Celery
worker, and Beat scheduler:

```sh
docker compose -f infra/compose/compose.dev.yml up --build
```

Run database migrations and collect static files with the `jobs` profile:

```sh
docker compose -f infra/compose/compose.dev.yml --profile jobs run --rm migrate
docker compose -f infra/compose/compose.dev.yml --profile jobs run --rm collectstatic
```

## Production

Set up `.docker.env` from `.docker.env.example` with deployment secrets, external
PostgreSQL and Redis endpoints, and an immutable `APP_IMAGE` digest. Run the
migration and static collection jobs before starting the long-running services:

```sh
docker compose --env-file .docker.env -f infra/compose/compose.prod.yml config --quiet
docker compose --env-file .docker.env -f infra/compose/compose.prod.yml --profile jobs run --rm migrate
docker compose --env-file .docker.env -f infra/compose/compose.prod.yml --profile jobs run --rm --no-deps collectstatic
docker compose --env-file .docker.env -f infra/compose/compose.prod.yml up -d --remove-orphans
```

The image runs as UID `10001`. Database, Redis, and credentials are supplied at
runtime; persistent media, static files, and Beat state use named volumes.
