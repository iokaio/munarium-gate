## What and why

<!-- One paragraph. Link the issue, and the hub decision record if the change touches a
     cross-component contract or semantic. -->

## Behavior and review scope

<!-- Describe the observable change, its regression and an adjacent valid case.
     Above 500 added + deleted non-generated lines, split by behavior or explain
     why one review is coherent. Report excluded generated files and their checks.
     Size triggers a review decision; it is not a correctness or merge gate. -->

## Validation evidence and limitations

<!-- Name commands, results, source identity, and unavailable coverage. Explain
     what each checker proves and cannot prove; transport success alone does not
     establish semantic success. Keep automatic CI enabled. A waiver links a
     numbered known gap with the original outcome, owner, reason and revisit
     condition; it does not turn failure or missing evidence into a passed check. -->

## Checks

- [ ] Every commit is signed off (`git commit -s`; the DCO, see CONTRIBUTING.md).
- [ ] `check_license.py`, `scripts/private_material_scan.py` and `scripts/docs_linkcheck.py` are green;
      `gitleaks dir . --config .gitleaks.toml` finds nothing.
- [ ] The gates for any code this change touches pass locally (CONTRIBUTING.md, "Gates").
- [ ] New source files carry `SPDX-License-Identifier: Apache-2.0` on the first line.
- [ ] Documentation that states the changed behavior is updated in this pull request, and the
      README's status label and capability table still describe what the tree can do.

## Disclosure

Answer each; "none" is an answer.

1. **Third-party code** in this pull request (any file or fragment you did not write), with its license:
2. **Generated code** (what generated it, from what):
3. **AI-tool provenance** (which tools helped write this, and that you reviewed every line):
4. **Employer or contractual restrictions** on contributing this:

I have the right to submit every file in this pull request under the Apache License 2.0.

## Maintainer self-review

<!-- For a pull request the owner merges on their own review: the compensating control
     for a sole approver. -->

- [ ] Read the whole diff once more after CI went green, as a reviewer would.
- [ ] No credential, hostname, internal path, or private document entered the tree.
- [ ] No cross-component contract or semantic was redefined here; where one changed, the hub
      decision record exists and is linked above.
