# Support

Munarium Gate is open source under the Apache License 2.0 ([LICENSE](LICENSE)). **The license
includes no support from Ioka LLC**, and nothing in this repository is a support commitment.

## Where this repository stands

Planned. A local Rust interface scaffold exists; there is no release, runnable service or published package; [README.md](README.md) says what
exists and what does not. Questions about the design are welcome. A report that the README claims
something the tree cannot do is a defect and is welcome as an issue.

## What is available to everyone

- **Questions** on this component go to GitHub Discussions on this repository. A question that spans
  components goes to the hub, [iokaio/munarium-platform](https://github.com/iokaio/munarium-platform).
- **Defects** go to GitHub Issues, with the commit or version, what you expected (cite the README,
  the hub contract or the decision record that says so) and the smallest reproduction you can
  manage. Once a conformance suite exists it is the fastest way to show a behavior that differs
  from the documented one.
- **Vulnerabilities** go to the private channel in [SECURITY.md](SECURITY.md), never an issue.
- **Compatibility** is recorded in two places once it exists: this README states the contract
  versions the component supports, and the hub's platform composition manifest records which
  component versions were tested together. A floating `main` is not a compatible composition.

Issues are read and triaged by one maintainer. There is no response-time commitment on this
repository, and a defect may be closed as "recorded, not scheduled", which is a truthful answer
rather than a dismissal.

## The support boundary in the first year

Asynchronous community assistance, reproducible issue reports, documented reference
configurations, and a limited number of scheduled design-partner sessions. Enterprise production
operation remains the adopting organization's responsibility unless a separate, sustainable
agreement explicitly says otherwise. Nothing here implies around-the-clock coverage, independent
dual-human review, or a breadth of qualified integrations the project does not possess.

## What is not

A production support relationship. Ioka may offer bounded architecture reviews, implementation
assistance, training, sponsored development and support contracts consistent with actual capacity.
A sponsor can fund a connector, an adapter or an independent review; the resulting Ioka-owned
platform implementation remains public. **There is no proprietary edition of Munarium Gate.**
Deferred is a roadmap state, not a commercial restriction. Munarium Enterprise is a separate,
proprietary distribution built on Munarium Server and Munarium Matrix; it contains no part of this
component and this component reserves nothing for it.

Commercial enquiries go to **info@ioka.io**.

## Running it yourself

When there is something to run, everything needed to operate it without Ioka will be in this
repository: the local development recipe, the operational diagnostics, the runbooks and the
conformance suite that tells you whether your deployment behaves. That is deliberate. Deferred
capabilities are listed as such in the README; a release names the profiles and capabilities its
evidence supports and no others.
