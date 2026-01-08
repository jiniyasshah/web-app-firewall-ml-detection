## Quick orientation

This repository composes a small multi-service application (local dev scaffolding) consisting of:
- `gateway` (comment in `docker-compose.yml` states: Go gateway)
- `ml_scorer` (comment in `docker-compose.yml` states: Python ML scorer)
- `origin` (runs the `bkimminich/juice-shop` image as an example origin server)

At present the language-specific directories contain `.gitkeep` placeholders; the canonical orchestration is in `docker-compose.yml` which drives how services are wired.

## Big picture / architecture (what to know first)
- Services are wired using Docker Compose network names. Use the service name as the hostname inside the Docker network. Example: the gateway uses the scorer at `http://scorer:8000` (see `SCORER_URL` in `docker-compose.yml`).
- Ports exposed to the host (local dev): gateway -> 8080, scorer -> 8000, origin/Juice Shop -> 3000.
- The `ml_scorer` service mounts local `./ml_scorer/data` into the container at `/app/data` (via `volumes`) and exposes `DATASET_PATH=/app/data`.

## What to look at in the repo
- `docker-compose.yml` — single source of truth for local orchestration and environment variables.
- `certs/` — certificate material (likely TLS for gateway). Treat this as the place for any local dev certs.
- `gateway/`, `ml_scorer/`, `dashboard/` — language-specific service folders (currently skeletons). Place service code, Dockerfile, and tests here.
- `docs/` — project documentation area (review before adding docs to keep style consistent).

## Service contracts & examples (concrete, copy-pasteable)
- Gateway -> Scorer: HTTP call to the scorer service at the hostname `scorer` and port `8000`. Example env in compose:

  SCORER_URL=http://scorer:8000

- Scorer data path is provided via `DATASET_PATH=/app/data` and `./ml_scorer/data:/app/data` volume mapping.

## Local developer workflows (what actually works now)
- Start all services locally (build images from local directories):

  docker-compose up --build

  (This will build contexts at `./gateway` and `./ml_scorer` per `docker-compose.yml`. If a Dockerfile is missing, add one in the respective directory.)

- To run a single service for development, add/adjust a Dockerfile in the service folder and run `docker-compose up --build <service-name>`.

## Project-specific conventions and signals
- The repo uses Docker Compose service names for internal discovery — prefer those hostnames in code (e.g., use `scorer` not `localhost` for inter-service calls when running in compose).
- Data required by the scorer should live under `ml_scorer/data` (volume is declared in compose). Keep datasets and any generated model artifacts there during local runs.
- Presence of `.gitkeep` files in service dirs indicates skeletons — when adding code, place service sources at the top level of each folder and add a Dockerfile for compose builds.

## Integration points & external dependencies
- External runtime dependency: `bkimminich/juice-shop` is used as the sample origin server image (no local source code required).
- Runtime communication is plain HTTP between services (no service mesh, message queue, or broker is defined in the repo).

## Helpful editing rules for an AI coding agent
- When you change service runtime interface (port, path, env name), update `docker-compose.yml` and any README/docs that mention it.
- Prefer editing or adding files under `gateway/` and `ml_scorer/` for service implementations. Add `Dockerfile` and small `README.md` per service describing how to run and test it.
- If you add host-level development scripts, place them in `scripts/` at repo root and reference them from the top-level `README.md`.

## Missing pieces discovered (so you can prioritize tasks)
- There are no service implementations (only `.gitkeep`) and no tests found. Any PR that adds a service should include:
  - a Dockerfile for the service
  - a minimal smoke test (e.g., health endpoint test)
  - updated `docker-compose.yml` only if a new service is added or ports change

## Where to look for more context
- Start with `docker-compose.yml` to understand runtime wiring.
- `certs/` for TLS usage; `docs/` for project-level documentation.

If any of the above assumptions are incorrect (for example, if actual service code lives in a different branch or external repo), tell me and I will merge/adjust this file. Want me to add short example Dockerfiles and simple smoke tests for `gateway` and `ml_scorer` next?
