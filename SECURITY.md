# Security

Do not file a vulnerability as an issue or a pull request.

Report a suspected vulnerability in anything in this repository privately, by either route:

- GitHub's private vulnerability reporting ("Report a vulnerability" under the Security tab), or
- email to **info@ioka.io** with "security" in the subject.

Say what you found, where, and how to reproduce it. Do not include live credentials, customer data,
or a proof of concept run against a system you do not operate. You will get an acknowledgement
within two business days, and a fix, or a recorded decision, on the affected path before any related
release. Credit is given if you ask for it.

## Supported versions

Munarium Gate has no release. Until the first tagged release, `main` is the only line and a fix
lands there. Once releases exist, security fixes go to the current minor release and to the previous
one for six months after its successor ships; an older release gets a fix only where the
vulnerability is in a contract it still speaks.

A finding in the design is welcome now, through the same private channel if it has security
consequences and as an ordinary issue otherwise. The threat model this component is built against
is in [README.md](README.md) and, for the platform as a whole, in the hub
([iokaio/munarium-platform](https://github.com/iokaio/munarium-platform)).

## What matters most here

As runtime behavior is implemented, these are the classes of finding taken most seriously and most
quickly:

- **Request substitution.** An approval, claim or grant that still applies after the canonical request, target, policy epoch or target precondition changed.
- **A policy error, a missing mandatory input, or an unverifiable approval producing permission** instead of a typed refusal. Gate fails closed.
- **A grant consumed twice**, a worker that lost its lease still dispatching, or a durable execution claim that a dispatch did not precede.
- **An unresolved target outcome that is retried blindly** rather than preserved as unresolved and investigated.
- **A connector that follows a redirect, resolves a different target, or executes a broader operation** than its manifest advertises, with the same credential.
- **A target credential visible to the agent**: in a prompt, a response, an exception, a trace, an environment variable, or a log.
- **A recording failure that does not stop dispatch.** No mandatory record, no dispatch.

## What is deliberate, and is not a defect

- **Gate does not promise exactly-once external effects.** A remote system can apply a request and lose the response. Preserving that ambiguity as an unresolved state, and refusing to repeat blindly, is the design.
- **The agent's own description of an action does not lower its consequence class**, and a hash supplied by the agent is never trusted; Gate computes the authoritative request hash after validation. A report that Gate "ignores" an agent-supplied classification or digest describes the design.
- **Decision-only mode has no production action path**, and says so. Until the durable journal, Warden's broker and Council's approval path are qualified, no target effect is enabled, however complete the evaluator looks.

When a local development profile exists, its test identity provider, test broker, disposable target
and generated sample credentials are development conveniences confined to that profile. They are
not vulnerabilities in themselves. A path by which they reach a production deployment unnoticed is.

## Findings that cross components

A contract ambiguity that lets two components disagree about authority, a canonicalization
difference between clients, or a gap between what a release advertises and what its evidence
supports is still a security finding. Report it here, or to any other Munarium repository, through
the same private channel; it is routed to the hub and the affected repositories together. Do not
open a public issue for it in the hub.

## Secrets

If you have committed a token or key, treat it as compromised: rotate it first, then report it.
