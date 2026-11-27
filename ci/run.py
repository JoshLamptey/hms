"""Repository-owned pull request verification commands."""

import compileall
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
INPUTS = ("base.txt", "production.txt", "development.txt", "ci.in")
LOCK = ROOT / "requirements/ci.lock"


def run(*args, capture=False):
    result = subprocess.run(
        args,
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return result.stdout if capture else None


def python(*args):
    return run(sys.executable, *args)


def input_hashes():
    return {
        name: hashlib.sha256(
            (ROOT / "requirements" / name)
            .read_text(encoding="utf-8")
            .replace("\r\n", "\n")
            .encode()
        ).hexdigest()
        for name in INPUTS
    }


def lockfile_check():
    expected = json.loads((ROOT / "requirements/ci.inputs.json").read_text())
    if input_hashes() != expected:
        raise ValueError("Dependency inputs changed; regenerate ci.lock and ci.inputs.json")
    locked = dict(re.findall(r"^([\w.-]+)==([^\s;]+)", LOCK.read_text(), re.M))
    normalize = lambda name: re.sub(r"[-_.]+", "-", name).lower()
    locked = {normalize(key): value for key, value in locked.items()}
    for name in INPUTS:
        for line in (ROOT / "requirements" / name).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-r ")):
                continue
            match = re.fullmatch(r"([\w.-]+)==([^\s]+)", line)
            if not match or locked.get(normalize(match[1])) != match[2]:
                raise ValueError(f"Unpinned or mismatched requirement in {name}: {line}")


def bootstrap():
    if sys.version_info[:3] != (3, 12, 13):
        raise ValueError("CI requires Python 3.12.13")
    lockfile_check()
    before = LOCK.read_bytes()
    python("-m", "pip", "install", "--require-hashes", "-r", str(LOCK))
    python("-m", "pip", "check")
    if LOCK.read_bytes() != before:
        raise ValueError("Bootstrap modified the dependency lockfile")


def configure():
    values = {}
    for line in (ROOT / ".env.example").read_text().splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value
    values.update(
        DJANGO_SETTINGS_MODULE="hms.settings.dev",
        APP_ENV="ci",
        DEBUG="False",
        SECRET_KEY="ci-only-secret-never-for-deployment",
        POSTGRES_ENGINE="django.db.backends.postgresql",
        POSTGRES_DB="hms_ci",
        POSTGRES_USER="postgres",
        POSTGRES_PASSWORD="postgres",
        POSTGRES_HOST="127.0.0.1",
        POSTGRES_PORT="5432",
        REDIS_HOST="redis://127.0.0.1:6379/0",
        CELERY_BROKER_URL="redis://127.0.0.1:6379/0",
        CELERY_RESULT_BACKEND="redis://127.0.0.1:6379/0",
        EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    )
    os.environ.update(values)
    sys.path.insert(0, str(ROOT))


def lint():
    if not all(
        compileall.compile_dir(str(ROOT / path), quiet=1)
        for path in ("apps", "hms", "ci")
    ):
        raise ValueError("Syntax compilation failed")
    python("manage.py", "check")
    run("git", "diff", "--check")


def schema_check():
    python("manage.py", "makemigrations", "--check", "--dry-run")


def test():
    import django
    from django.test.runner import DiscoverRunner

    django.setup()
    runner = DiscoverRunner(verbosity=2)
    labels = ["apps"]
    if runner.build_suite(labels).countTestCases() == 0:
        raise ValueError("No application tests discovered")
    if runner.run_tests(labels):
        raise ValueError("Application tests failed")


def env_check():
    import django
    from django.conf import settings

    django.setup()
    if settings.DATABASES["default"]["NAME"] != "hms_ci":
        raise ValueError("CI must use its isolated PostgreSQL fixture")
    python("manage.py", "check")
    import hms.asgi  # noqa: F401
    import hms.wsgi  # noqa: F401
    import hms.celery  # noqa: F401


def security():
    python("-m", "bandit", "-r", "apps", "hms", "-ll", "-ii")
    python("-m", "pip_audit", "--disable-pip", "--no-deps", "-r", str(LOCK))


def docker_proof():
    image = "hms:pr-proof"
    with tempfile.TemporaryDirectory(prefix="hms-ci-") as directory:
        env_path = Path(directory) / "fixture.env"
        env_path.write_text((ROOT / ".docker.env.example").read_text())
        os.environ.update(
            APP_ENV_FILE=str(env_path),
            APP_IMAGE="ghcr.io/example/hms@sha256:" + "a" * 64,
        )
        run("docker", "compose", "--env-file", str(env_path), "-f", "infra/compose/compose.prod.yml", "config", "--quiet")
        rendered = json.loads(run(
            "docker", "compose", "--env-file", str(env_path), "-f", "infra/compose/compose.prod.yml",
            "--profile", "jobs", "config", "--format", "json", capture=True,
        ))
    for role in ("web", "worker", "beat", "migrate", "collectstatic"):
        service = rendered["services"][role]
        if service.get("image") != os.environ["APP_IMAGE"] or not service.get("command"):
            raise ValueError(f"Role {role} needs the canonical image and an explicit command")
    run("docker", "build", "--file", "infra/docker/Dockerfile", "--target", "production", "--tag", image, ".")
    config = json.loads(run("docker", "image", "inspect", image, capture=True))[0]["Config"]
    uid = run("docker", "run", "--rm", "--entrypoint", "id", image, "-u", capture=True).strip()
    if uid != "10001" or not config.get("Healthcheck") or not config.get("Cmd"):
        raise ValueError("Production image must run non-root and include a health check and startup command")
    run("docker", "run", "--rm", "--entrypoint", "/bin/sh", image, "-ec", 'test -x "$1"', "startup-proof", config["Cmd"][0])
    for command, argument in (("daphne", "--help"), ("celery", "--version"), ("python", "--version")):
        run("docker", "run", "--rm", "--entrypoint", command, image, argument)
    run("docker", "run", "--rm", "--entrypoint", "/bin/sh", image, "-ec", "test -f /app/manage.py && test -f /app/apps/clients/management/commands/migrate_schemas.py")


def main():
    commands = {
        "bootstrap": bootstrap,
        "lockfile-check": lockfile_check,
        "lint": lint,
        "test": test,
        "schema-check": schema_check,
        "env-check": env_check,
        "security": security,
        "docker-proof": docker_proof,
    }
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        raise ValueError(f"Expected one of: {', '.join(commands)}")
    if sys.argv[1] not in ("bootstrap", "lockfile-check", "docker-proof"):
        configure()
    commands[sys.argv[1]]()


if __name__ == "__main__":
    try:
        main()
    except (ValueError, subprocess.CalledProcessError, KeyError) as error:
        print(f"CI failed: {error}", file=sys.stderr)
        sys.exit(1)
