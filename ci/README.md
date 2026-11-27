# CI verification interface

The PR workflow uses `sh ci/run <command>` so local and hosted checks share one
entry point. Python 3.12.13 and the hash-locked `requirements/ci.lock` are
required. The bootstrap command verifies the dependency input hashes before
installing packages into the active environment.

Commands include `bootstrap`, `lockfile-check`, `lint`, `schema-check`,
`env-check`, `security`, and `docker-proof`. Application test execution can be
added once the project has CI-safe test settings and database fixtures.
