# Transaction Simulation Evasion

> Contracts that behave differently under simulation, and how wallets and security tools can harden against them.

## Contents

<!-- toc:start -->
1. [Simulation Mechanics and Threat Model](chapters/01-simulation-mechanics-and-threat-model.md)
2. [Context Differences Attackers Key On](chapters/02-context-differences.md)
3. [Time-of-Check, Time-of-Use and State Races](chapters/03-time-of-check-time-of-use.md)
4. [Honeypots and Deceptive Contracts](chapters/04-honeypot-patterns.md)
5. [Hardening Simulators: Multi-Context Runs, Invariants and Private Submission](chapters/05-hardening-simulators.md)
6. [Simulation Security Review Checklist](chapters/06-review-checklist.md)
<!-- toc:end -->

## How to read this

Read chapters in order, or jump to what you need. Every chapter ends with exercises and further reading. See [RESOURCES.md](RESOURCES.md) and [GLOSSARY.md](GLOSSARY.md).

## Build

```bash
mdbook serve   # optional: renders SUMMARY.md as a website
```

## License

Text: CC BY-SA 4.0. Code snippets: MIT. See [LICENSE](LICENSE).
