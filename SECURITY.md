# Security reporting and repository privacy

This repository is a public professional profile, not an application or data vault. Its security statements describe professional interests and linked work; each implementation needs its own review. GitHub and linked services have their own data handling. This repository does not provide zero-knowledge browsing or control GitHub's platform behavior.

## Contributions

Keep credentials, private conversations, student records, production logs, account exports, recordings, and identifying incident evidence out of commits and reports. Use synthetic examples. Review document and image metadata, comments, hidden text, and attachments before adding assets. The local images are retained; remote badges are replaced with ordinary links so the README no longer embeds third-party image resources.

`.gitignore` helps prevent accidental additions; it is not access control and does not affect already tracked files. After staging intended changes, run:

```sh
node --test scripts/repository-privacy.test.mjs
node scripts/repository-privacy.mjs
```

The dependency-free check scans tracked files for common credentials, sensitive filenames, symlinks, and remote embeds. It logs paths and rule names without matching content. It cannot detect all secrets or personal information, inspect binary contents or past commits, or verify account and hosting settings. Review binary assets manually. Passing is not a security guarantee.

CI uses a read-only token, commit-pinned checkout, and no persisted credentials, package installations, or external scanning service. Configure branch rules separately to require review and the privacy check, verifying its exact status name after its first run.

## Reporting concerns

For vulnerabilities in a linked project, use that project's documented private reporting channel. For this profile, use GitHub private vulnerability reporting from the Security tab if enabled. If unavailable, ask for a private channel without publishing exploit details or personal information.

If a secret is committed, revoke or rotate it promptly, then assess prior commits, forks, clones, caches, releases, and downloads. Deleting the current file does not invalidate the credential or recover exposed information. Never paste a live credential into a report or CI log.
