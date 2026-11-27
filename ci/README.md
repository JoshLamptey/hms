# CI verification interface

The PR workflow uses `sh ci/run <command>` so local and hosted checks share one
entry point. Python 3.12.13 and the hash-locked `requirements/ci.lock` are
required. The bootstrap command verifies the dependency input hashes before
installing packages into the active environment.

Commands include `bootstrap`, `lockfile-check`, `lint`, `test`, `schema-check`,
`env-check`, `security`, and `docker-proof`. The PR workflow keeps application
tests disabled, matching the ERP reference workflow; run `sh ci/run test` when
the required test services are available.
