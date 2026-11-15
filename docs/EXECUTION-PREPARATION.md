# Read-only Standard execution preparation

After enrollment, an operator can check a proposed execution configuration while
keeping the installed connection-only service and execution admission disabled:

```bash
sudo neticora-runnerd prepare-execution /etc/neticora-runnerd/candidate.json
```

The candidate is a complete ordinary Runnerd configuration with
`execution.enabled=false`. All execution paths, repository/organization binding,
PID limit, trust provisioning time and separation from credentials, journal and
bootstrap mounts are validated before any execution opt-in. `config.Parse` keeps
its existing foundation behavior; `config.ParsePreparation` performs this strict
inactive validation.

Store the candidate, policy, capabilities and offline trust files using the same
protected ownership/permissions as the existing installation. The command runs
under the configured nonroot service UID, GID and supplementary groups, using the
existing installed-product command wrapper. It never grants Docker access.

The JSON report includes configuration/policy/capability hashes, the original
public identity and endpoint binding, and explicit checks. A missing/invalid file,
changed original boot or Docker peer, incompatible capability tuple, root policy,
wrong tenant/pool or failed offline image trust blocks validation. This command
neither pulls an image nor installs configuration or trust material.

`configurationValid` means the inspected local configuration, original identity,
peer and provisioned offline image trust passed these checks. It does not attest
physical CPU, memory, PID, storage, network, concurrency or duration enforcement.
`qualificationReady` and `admissionEnabled` remain false. A successful check does
not sign or accept qualification and does not establish platform policy.

Preparation never opens the execution journal or controller, creates bootstrap
state, contacts the platform, accepts commands, adopts/disposes resources, issues
ACKs or releases reservations. It does not reconcile or reset recovery state.

The supported `linux-github-process-v1` template is trusted process-only Docker
with soft storage limits. Its bounded workspace does not establish whole-host
hard disk containment. The current controller also lacks an independently
qualified running-job duration limit; start-authority expiration is not a job
runtime timeout. These remain blockers until implementation and a separately
authorized physical qualification campaign provide the required evidence.

Independent offline qualification, image trust, exact workflow scope, signed
resource budgets, generation agreement and authoritative controller recovery are
required before any separately approved execution activation. Fresh read-only
inventory alone cannot satisfy these requirements.
