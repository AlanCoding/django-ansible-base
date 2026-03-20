# Running OPA Alongside test_app

## Overview

The OPA (Open Policy Agent) service runs as a sidecar container alongside the test_app, similar to how PostgreSQL is run today. During development, a `make` target starts just the OPA container so that `manage.py runserver` on the host can reach it at `localhost:<port>`.

---

## 1. OPA binary in the test_app image

OPA is a single static binary. It will be installed from the official OPA release during the Docker image build.

### Dockerfile changes

Add the following to the root `Dockerfile` (the test_app image):

```dockerfile
# Install OPA binary
ARG OPA_VERSION=1.4.2
RUN curl -L -o /usr/local/bin/opa \
    "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64_static" \
    && chmod +x /usr/local/bin/opa
```

This bakes OPA into the same image used by `test_app` and keeps the version pinned and reproducible.

---

## 2. docker-compose service

A new `opa` service will be added to `docker-compose.yml`:

```yaml
  opa:
    build:
      context: .
    container_name: dab_opa
    command: >
      /usr/local/bin/opa run --server
        --addr 0.0.0.0:8181
        --bundle /src/ansible_base/lib/opa/bundles
    volumes:
      - '.:/src:z'
    ports:
      - '8181:8181'
    healthcheck:
      test: ["CMD", "/usr/local/bin/opa", "eval", "--server", "http://localhost:8181", "true"]
      interval: 10s
      timeout: 5s
      retries: 5
```

Key points:

- Reuses the same Docker image as `test_app` (OPA binary is already installed there).
- Mounts the repo so that Rego bundles under `ansible_base/lib/opa/bundles/` are available without a rebuild.
- Exposes port `8181` (the OPA default) to the host.
- The `--bundle` flag points to the directory where DAB OPA Rego policies will live. This path will be created as part of the `dab_opa` app implementation.
- Health check confirms OPA is responsive.

### test_app dependency

The `test_app` service in `docker-compose.yml` should gain a dependency on `opa` when running the full stack:

```yaml
  test_app:
    depends_on:
      postgres:
        condition: service_healthy
      opa:
        condition: service_healthy
```

This ensures OPA is ready before the Django app starts.

---

## 3. Makefile target

A new `make opa` target mirrors the existing `make postgres` pattern:

```makefile
## Starts an OPA container in the background if one is not running
opa:
	docker start dab_opa || $(DOCKER_COMPOSE) up -d opa --quiet-pull

## Stops the OPA container started with 'make opa'
stop-opa:
	echo "Killing dab_opa container"
	$(DOCKER_COMPOSE) rm -fsv opa
```

Usage:

```bash
# Terminal 1 - start supporting services
make postgres
make opa

# Terminal 2 - run Django on the host
python manage.py runserver
```

Django connects to OPA at `http://localhost:8181` just as it connects to PostgreSQL at `localhost:55432`.

---

## 4. Django settings

A setting will tell the DAB OPA app where to find the OPA server:

```python
# test_app/settings.py (or via environment)
DAB_OPA_SERVER_URL = os.environ.get("DAB_OPA_SERVER_URL", "http://localhost:8181")
```

Inside `docker-compose.yml`, the `test_app` service overrides this to the container network name:

```yaml
  test_app:
    environment:
      DAB_OPA_SERVER_URL: http://opa:8181
```

---

## 5. Rego bundle directory

OPA policy files (`.rego`) and optional `data.json` files will live under:

```
ansible_base/lib/opa/bundles/
```

This directory is mounted into the container. OPA watches it automatically when started with `--bundle`, so policy changes during development are picked up on reload without restarting the container.

The actual Rego policy implementation is part of the `dab_opa` app work and is not covered in this document.

---

## 6. bootstrap.sh integration

The `test_app/scripts/bootstrap.sh` script should start OPA alongside PostgreSQL:

```bash
# Start OPA alongside postgres
make opa
```

This should be added after the PostgreSQL startup block and before the migration step so that OPA is available when the Django app boots.

---

## 7. CI considerations

For CI and automated tests:

- Unit tests that use the **local Django evaluator** (see APP_DESIGN.md section 11) do not need OPA running.
- Integration tests that exercise the OPA HTTP boundary will need the `opa` service. These tests should be tagged or grouped so they can be run selectively.
- The same `docker compose up opa` command works in CI as in local development.
