# Publishing the Action to GitHub Marketplace

Owner checklist. Nothing here has been clicked yet.

## Listing copy

- **Name** (from `action.yml`, must be unique on Marketplace): `mcpprobe MCP security scan`
- **Description** (from `action.yml`, 115 characters): Passive security scan of an MCP
  server you own: auth, transport and tool-poisoning checks, SARIF for code scanning.
- **Two-sentence description** (release notes / first paragraph of the listing):
  mcpprobe scans a Model Context Protocol server you own for missing authentication,
  transport weaknesses, tool-description poisoning and rug pulls, without calling any
  tool. Findings land in GitHub code scanning as SARIF with fixes, OWASP MCP/LLM Top 10
  tags and a CI gate on severity.
- **Primary category:** Security
- **Secondary category:** Continuous integration
- **Branding:** `icon: shield`, `color: green` (already in `action.yml`; `shield` is a
  valid Feather icon and `green` a valid badge colour).

## Why a new release is needed

The `v0.2.0` tag's `action.yml` has a 130-character description. Marketplace
validation is widely reported to reject descriptions of 125 characters or more, and
`v0.2.0` also lacks the not-an-MCP-server annotation, job summary and `result` output.
The `launch-prep` branch shortens the description (115) and adds those. Publish the
listing from a release cut after `launch-prep` is merged.

## Requirements (GitHub docs)

- Repository is **public** (`mcpprobe-dev/mcpprobe`).
- Exactly one action metadata file at the **root** (`action.yml`). Other files and
  the `.github/workflows/` folder are fine.
- `name` unique on Marketplace, not equal to a Marketplace category, user or org name.
- The account publishing has **two-factor authentication** enabled.
- The **owner of `mcpprobe-dev`** has accepted the **GitHub Marketplace Developer
  Agreement** (until then the publish checkbox is greyed out).
- No review: the listing goes live as soon as the release is published.

## Click list

1. Merge `launch-prep` into `main` (review the diff first; it changes `action.yml`,
   `mcpprobe/action.py`, the README Action snippet, tests and docs only).
2. Bump the version for a patch release: set `__version__ = "0.2.1"` in
   `mcpprobe/__init__.py`, move the `[Unreleased]` CHANGELOG entry under `[0.2.1]`,
   commit, then `git tag v0.2.1 && git push origin main v0.2.1`.
   The tag push also runs `release.yml`, which publishes `mcpprobe-scanner` 0.2.1 to
   PyPI (the release workflow requires the tag to match `__version__`).
3. Wait for CI to pass on the tag (the `docker-action` job builds the Action image).
4. On github.com open `mcpprobe-dev/mcpprobe` and click `action.yml`. A banner offers
   to publish the action: click **Draft a release**. (Or **Releases -> Draft a new
   release**, or edit an existing release.)
5. Choose the tag **v0.2.1**. Tick **Publish this Action to the GitHub Marketplace**.
6. If the box is disabled, follow the link to accept the Marketplace Developer
   Agreement (org owner), then reload.
7. Wait for the metadata check to show **Everything looks good!** Fix anything it
   flags in `action.yml` (name, description, branding) and re-tag if needed.
8. **Primary Category:** Security. **Another Category:** Continuous integration.
9. **Release title:** `v0.2.1`. **Description:** the two-sentence description
   above, then the CHANGELOG entry and the copy-paste snippet from
   `docs/github-action.md` with `@v0.2.1`.
10. Click **Publish release** and confirm with 2FA.
11. Open the Marketplace page from the release, check the README renders and the
    badge shows the green shield.
12. Update the snippets in `README.md` and `docs/github-action.md` from `@v0.3.0` to
    `@v0.2.1`, and optionally add a moving major tag (`v0`) for users who want
    patch updates: `git tag -f v0 v0.2.1 && git push -f origin v0`.

## README sections the listing relies on

The Marketplace page renders the repository README. It already has: what the scanner
checks, the ownership rule, exit codes, a "SARIF and GitHub code scanning" section
with the workflow, and the licence. The Action inputs/outputs table is in
`docs/github-action.md`, linked from the README.

## Unverified

- Name uniqueness on Marketplace was not checked (no access from the build
  environment). The metadata check in step 7 will say if it clashes.
- The 125-character description limit comes from reports by other action authors, not
  from GitHub's docs page.
