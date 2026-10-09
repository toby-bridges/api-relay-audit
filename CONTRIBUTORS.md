# Contributors

This project keeps contributor credits explicit because useful work often
arrives as issues, forks, testing reports, and design pressure before it
arrives as a direct pull request.

## Core Credits

- [@toby-bridges](https://github.com/toby-bridges) — original author and maintainer.
- [@liuwei71320](https://github.com/liuwei71320) — author of
  [`ai-relay-audit-gui`](https://github.com/liuwei71320/ai-relay-audit-gui),
  a downstream fork that contributed the Windows long-context stability
  finding and the opt-in fast context scan idea tracked in
  [issue #14](https://github.com/toby-bridges/api-relay-audit/issues/14).
- [@shivam2931120](https://github.com/shivam2931120) — contributed the
  deterministic Step 8 tool-substitution edge fixture in
  [PR #44](https://github.com/toby-bridges/api-relay-audit/pull/44), covering
  benign formatting noise alongside a real package substitution.
- [@NewFeKim](https://github.com/NewFeKim) — contributed refusal-marker
  coverage for denial-of-existence phrasing in
  [PR #45](https://github.com/toby-bridges/api-relay-audit/pull/45) and
  additional tool-rewrite edge fixtures in
  [PR #46](https://github.com/toby-bridges/api-relay-audit/pull/46).
- [@ythx-101](https://github.com/ythx-101) — proposed JSON output in
  [PR #2](https://github.com/toby-bridges/api-relay-audit/pull/2). The focused
  JSON report implementation independently adapts that idea from the fork's
  [fixed source revision](https://github.com/ythx-101/api-relay-audit/tree/495e910be9bc14bef15d651a02f4fd7d5d57159c),
  preserving the current six-dimension rating rather than deriving risk from
  flag colors. The source snapshot uses MIT; no fork code was copied.

## Attribution Policy

When a downstream fork or issue materially changes this project, credit the
person in this file and mention the issue or PR that carried the idea. If code
is copied rather than independently reimplemented, preserve the relevant
license notice as well.

GitHub's repository sidebar is commit-linked. When a material contribution
arrives through an issue or downstream fork instead of a pull request,
maintainers may land a small attribution commit on the contributor's behalf
using their GitHub noreply address, with the issue link preserved here.
