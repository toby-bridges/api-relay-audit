# Acceptance and closure matrix

The npm candidate's own Windows acceptance belongs to this repository's distribution workflow. The tests below are the additional host-repair gates. None is marked passed merely because local adapter tests pass.

| Gate | Setup / fault | Required evidence | Current state |
| --- | --- | --- | --- |
| Classifier baseline | Two pinned upstream classifiers plus three sanitized fixtures | All six observed outputs match; desired count remains 1/6 | Verified locally by replay; see baseline JSON |
| Correct attribution | Issue 99/103 fixtures; real build-policy and real lifecycle-failure controls | Network, missing Git, policy denial and actual build failure remain distinct | Upstream repair not implemented |
| Original issue 101 reproduction | Windows build 10.0.26200, Node 24.13.1, DSH 0.1.2-alpha.3, Hub 1.4.3, pnpm 11.7.0; isolated `web` profile and cache | Exact binaries/SHAs, entry point, sanitized environment identity and stage events; reproduce or record non-reproduction | Pending; no equivalent Windows run in this evidence package |
| pnpm remains alive after `Done` | Controlled hanging owned worker using same launcher | Package-manager exit absent; bounded cancellation; no success or next conflicting writer | Pending host integration test |
| DSH post-pnpm work remains pending | Pause reconciliation/commit under an isolated lock | Package-manager exit 0 plus pending DSH stage; deadline remains timeout | Pending host integration test |
| Direct child exit versus pipe close | Short-lived Node parent with inherited pipe owner | `exit(0)` precedes pipe release and `close`; bounded cleanup | Synthetic local test only; does not diagnose issue 101 |
| Timeout with package files present | Inject deadline after materialization, before commit | Preserve timeout; artifact state recorded separately; no success rewrite | Pending host repair test |
| Unreadable metadata/patch | Invalid package JSON or unreadable declared patch | Verification `unknown` or `incomplete`; never verified complete | Pending host repair test |
| Update / cancel / retry | Existing working profile; interrupt before and during commit | Prior version remains usable or explicit recovery; no orphan writer; retry serialized | Candidate workflow covers missing-version failure and metadata-phase cancellation with profile-byte and old-command checks; interruption during commit remains pending |
| Activation | Exact npm candidate, Windows path with spaces, isolated profile, no Git executable | Registered command executes `--help`; local simulated API connectivity succeeds; result and activation agree | Handled by candidate acceptance workflow; inspect its own result |
| Proxy failure on npm | Registry fetch returns proxy 502 | Failure remains network; no build-policy hint or false success | Pending fault-injection test |
| Legacy host fallback | Host version without machine result protocol | Honest unknown/timeout result, real exit/cleanup evidence; no claim of committed/ready state | Pending host repair test |

For the original Windows investigation, record exact executable version/hash and argument vector, normalized profile identity, package source/version/integrity, package-manager exit, DSH reconciliation/commit, child exit, pipe close and cleanup outcome. Do not collect credentials, network captures, raw request headers or complete environment dumps. Hash or replace local paths in the public bundle. Preserve raw sensitive evidence locally if the owner explicitly authorizes collecting it; do not upload it by default.

Issue 99 is not closed by a working npm install if the reporter's proxy failure remains unexplained. Issue 103 can be resolved for the npm path after proving installation with no Git and correcting misleading attribution; the Git path must still report Git absence accurately. Issue 101 requires either a reproduced component fix verified in the original combination or an explicit scoped non-reproduction with remaining uncertainty. A source-tree exit-0 screenshot, a synthetic pipe test and a timeout-to-success conversion do not close it.
