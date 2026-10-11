# Security Policy

This repository provides educational, non-production source under the [LICENSE](LICENSE). The code is provided "AS IS"; this policy does not promise production suitability, a support lifecycle or a response-time guarantee.

## Private Vulnerability Reporting

Email [rcnsessions@gmail.com](mailto:rcnsessions@gmail.com) with a subject such as `Security report: repository name`. Do not publish suspected vulnerabilities, sensitive reproduction details or exploit evidence in public issues or pull requests before coordinating with the maintainer.

Include:

- Repository name, commit identifier and relevant component or dependency version.
- A description of the affected trust boundary and potential impact.
- Minimal reproduction steps using synthetic data in an authorized local environment.
- Expected and observed behavior, with sanitized logs or screenshots.
- Whether the issue is in first-party code, an example configuration or a third-party dependency.

Never send access tokens, passwords, signing keys, real learner data or complete private configuration. Ordinary email is not an agreed secure channel for sensitive evidence; request a suitable channel before transmitting it.

## Scope and Coordination

Identify the exact revision tested. Reports against the current default branch are preferred; there is no promised long-term support for older revisions or a published response deadline. The maintainer will assess reports as available and coordinate reproduction, remediation and disclosure when appropriate.

For third-party vulnerabilities, follow the upstream project's reporting policy and identify any effect on this repository without redistributing sensitive details.

Test only systems you own or have explicit permission to test. Do not probe public deployments or other people's tenants, workloads or data. Read the implementation guide's synthetic-credential, network and cleanup warnings before running checks.

## Other Requests

Use [CONTRIBUTING.md](CONTRIBUTING.md) for non-sensitive bugs and proposed changes. Contact [rcnsessions@gmail.com](mailto:rcnsessions@gmail.com) for licensing or other permissions; a security report does not authorize prohibited use or redistribution.
