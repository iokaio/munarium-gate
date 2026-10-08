# Munarium Gate development documentation

Start with the [repository README](../README.md) for scope and capability status.
The [public platform plan, revision 4](https://github.com/iokaio/munarium-platform/blob/main/docs/platform-plan.md) is the design baseline;
section 8 covers Gate. A plan or a compiling interface does not establish a capability.

| Document | Purpose |
|---|---|
| [Architecture](architecture.md) | Proposed modules, state ownership, dependencies, threats and open decisions |
| [Implementation plan](implementation-plan.md) | First bounded work item, delivery sequence and acceptance criteria |
| [Validation](validation.md) | Local build recipe, automatic checks and future acceptance specifications |
| [Stage 1](stage1.md) | Implemented decision-only behavior, reproducible checks and composition limits |
| [Stage 2 activation](activation-profile.md) | PostgreSQL barrier, authenticated participant evidence and remaining execution limits |

The [source](../src/lib.rs) includes experimental Stage 1 behavior. Released contracts,
qualified deployment profiles and production capabilities remain **none**.

[Stage 1 service profile](service-profile.md) documents configuration, the authenticated
boundary and separate-process evidence.
