# Neticora Runnerd

Neticora Runnerd is an open-source runner-management agent being developed for
customers who want to run CI workloads on infrastructure they control.

Runnerd is designed to connect customer-managed hosts to Neticora and manage the
local lifecycle of ephemeral CI runners, while keeping execution subject to
customer-defined policy.

## Project status

Runnerd is under active development. This repository currently contains the
versioned host protocol, Go SDK, and a development Linux service/CLI foundation.
The service reports local status and remains unavailable for job admission.
An offline verification foundation checks signed update artifacts against
independently provisioned trust. Production installation and runner execution are
not yet supported.

The presence of protocol definitions does not imply support for a particular
operating system, container runtime or isolation profile.

## Feedback and contributions

Use [GitHub Issues](https://github.com/Neticora/neticora-docker-runnerd/issues)
for bug reports, feature requests and general feedback. Discuss substantial
changes with maintainers before opening a pull request.

Do not include credentials, access tokens or private infrastructure details in
public issues or pull requests.
