# "State of MCP server security" report: how to run it

`mcpprobe registry-report` (also `python -m mcpprobe.registry`) builds an anonymised
report on the remote MCP servers listed in the official MCP Registry. It has five stages,
plus two for refreshing results after a scanner update. Each stage reads and writes one
working directory, and each can be resumed:

| Stage | Network | Writes |
|---|---|---|
| `fetch` | registry API only, 1 request/s | `registry/page-*.json`, `fetch-state.json`, `entries.jsonl` |
| `scan` | the listed remote hosts (survey profile, below) | `targets.jsonl`, `selection.json`, `static.jsonl`, `scan.jsonl` |
| `calibrate` | none (local fixtures on 127.0.0.1; needs a repository checkout) | `calibration.json` |
| `aggregate` | none | `aggregates.json`, `PRIVATE-disclosure-queue.json`, `disclosure-summary.json` |
| `recheck` | selected hosts only (survey profile, same rules) | `recheck.jsonl` (`recheck-<time>.jsonl` for earlier passes) |
| `reaggregate` | none | `static.jsonl` (re-run offline), then what `aggregate` writes; prints before/after counts |
| `render` | none | `report/report.md`, `report/chart-*.svg` |

Every stage takes `--dry-run`, which sends nothing and writes nothing.

**The working directory is private.** It holds hostnames, URLs and registry names. Never
publish it, commit it or attach it to an issue. Only `report/` is meant to be published.
`render` refuses to write a report that contains any host, URL or registry server name
from the working directory. The exceptions are hosts passed with `--allow-host` and
fixed hosts whose operator agreed to be named.

## Rules the code enforces

These rules are in code, not in this document only. The tests in
`tests/test_registry_report.py` cover them.

- **Opt-out first.** The DNS TXT record `mcpprobe-opt-out=all` at `_mcpprobe.<host>` (or a
  parent) is checked before any packet reaches the host. Then
  `/.well-known/mcpprobe-opt-out` is checked. Both use `mcpprobe/policy.py`.
- **Survey profile only.** The checks are AUTH-01, AUTH-02, TRANS-05, TRANS-06, TRANS-09
  and META-01/03/04/05/06/07. They send only what an ordinary client sends:
  - negotiation;
  - the `*/list` methods;
  - the RFC 9728 document on the same origin.

  The forged and malformed probes are left out: Origin, version, session, JWT,
  truncated JSON, oversized and deep payloads, and the DOS-01 burst. So are the
  authorization-server fetches and the baseline writer. No tool is ever called.
- **Rate.** At most 1 request per second per rate key, and at most 8 hosts in parallel
  (`--concurrency` is capped at 8). The rate key is the host's last two DNS labels, so a
  provider with many per-server subdomains sees one client at 1 request/s.
- **Addresses.** The scanner resolves every host itself and refuses any host with a
  loopback, private, CGNAT, link-local or reserved address. The connection is pinned to
  the vetted address; TLS still verifies the hostname through SNI. IP-literal URLs,
  templated URLs (`{tenant}`) and local names are dropped before scanning.
- **Funnel arithmetic.** Every listed remote URL is either selected or counted under exactly
  one reason in `funnel.excluded` (`duplicate_host`: another URL on a host already selected;
  `duplicate_url` *(0.3.2)*: the same URL listed again by another entry or transport), so
  `remote_urls - sum(excluded) == selected_urls == unique_hosts` with one URL per host.
- **Same origin only.** A request to any host other than the target is refused.
- **Stop on refusal.** The first HTTP 429 or 403 stops all traffic to that rate key for
  the rest of the run and for resumed runs. `Retry-After` is not waited out.
- **No bodies stored.** Evidence exists only in memory during one host's scan.
  `scan.jsonl` keeps, per host: status, the outcome of each check
  (`passed` / severity / `n_a` / `blocked` / `unreachable` / `not_mcp` / `error`), request
  count, negotiated revision, negotiation style, edge label and list counts. From 0.3.1 it
  also keeps derived labels from fixed vocabularies: the META-01 rules revision
  (`meta01_rules`), the META-01 indicator kinds at medium or above (`meta01_indicators`),
  the META-03 capability classes (`capabilities`) and the checks run (`checks_run`). It
  never keeps a tool name, description or any other text from the host, so a rule change
  cannot be re-evaluated offline for remote hosts: use `recheck`.
- **Identification.** Every request carries
  `User-Agent: mcpprobe/<version> (+https://mcpprobe.tech/scanning-policy)`.

## Where to run it: a small EC2 instance with an Elastic IP

**Use EC2, not CloudShell.** CloudShell sessions end after about 20 minutes of
inactivity, have a 12-hour maximum, and egress from a shared AWS address. A scan run
takes hours and should come from one address that you publish.

**Use EC2, not a Lambda fan-out.** Lambda egress comes from changing AWS addresses. A
fixed, published address needs a VPC with a NAT gateway and an Elastic IP; the NAT
gateway alone costs more than the instance. The 15-minute limit would also force the
per-provider queue to be split across invocations, with shared state in S3 or DynamoDB.
That is more moving parts and adds nothing at 1 request/s.

The steps below use `eu-west-2` (London). Run them from your workstation or CloudShell
with an admin profile. CloudShell is fine for these one-off commands.

### 1. Infrastructure (once)

```bash
export AWS_REGION=eu-west-2
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
BUCKET=mcpprobe-survey-$ACCOUNT_ID

# Private, encrypted bucket for the working directory backup and the report
aws s3api create-bucket --bucket $BUCKET --create-bucket-configuration LocationConstraint=$AWS_REGION
aws s3api put-public-access-block --bucket $BUCKET \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-encryption --bucket $BUCKET \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# Instance role: Session Manager (no SSH, no inbound ports) plus write access to that bucket only
aws iam create-role --role-name mcpprobe-survey --assume-role-policy-document \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam attach-role-policy --role-name mcpprobe-survey \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
aws iam put-role-policy --role-name mcpprobe-survey --policy-name survey-bucket --policy-document \
  "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:PutObject\",\"s3:GetObject\",\"s3:ListBucket\"],\"Resource\":[\"arn:aws:s3:::$BUCKET\",\"arn:aws:s3:::$BUCKET/*\"]}]}"
aws iam create-instance-profile --instance-profile-name mcpprobe-survey
aws iam add-role-to-instance-profile --instance-profile-name mcpprobe-survey --role-name mcpprobe-survey
sleep 15   # instance profiles take a few seconds to propagate

# Security group with no inbound rules (egress only)
VPC_ID=$(aws ec2 describe-vpcs --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId' --output text)
SG_ID=$(aws ec2 create-security-group --group-name mcpprobe-survey \
  --description "mcpprobe survey: egress only" --vpc-id $VPC_ID --query GroupId --output text)

# The scanning IP you will publish
read ALLOC_ID SCAN_IP < <(aws ec2 allocate-address --domain vpc --query '[AllocationId,PublicIp]' --output text)
echo "Scanning IP: $SCAN_IP"

# Instance: t3.small, Amazon Linux 2023, IMDSv2 only, encrypted 8 GB disk
AMI=$(aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
  --query Parameter.Value --output text)
INSTANCE_ID=$(aws ec2 run-instances --image-id $AMI --instance-type t3.small \
  --security-group-ids $SG_ID --iam-instance-profile Name=mcpprobe-survey \
  --metadata-options HttpTokens=required \
  --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=8,VolumeType=gp3,Encrypted=true}' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=mcpprobe-survey}]' \
  --query 'Instances[0].InstanceId' --output text)
aws ec2 wait instance-running --instance-ids $INSTANCE_ID
aws ec2 associate-address --instance-id $INSTANCE_ID --allocation-id $ALLOC_ID
```

### 2. Identify the scanner before the first request

1. Create a DNS `A` record `scanner.mcpprobe.tech -> $SCAN_IP`. Then set reverse DNS so
   the address names itself:
   `aws ec2 modify-address-attribute --allocation-id $ALLOC_ID --domain-name scanner.mcpprobe.tech`.
2. Publish on `https://mcpprobe.tech/scanning-policy`:
   - the IP and reverse name;
   - the User-Agent;
   - the survey dates;
   - what is sent (the survey profile above) and that no tool is called;
   - the two opt-out mechanisms;
   - a contact address that someone reads during the run.
3. Optional: tell the registry maintainers before the run (an issue or discussion in the
   registry repository), with a link to the policy page.

### 3. Run

Push the `registry-report` branch first: the instance clones it. Then connect with
`aws ssm start-session --target $INSTANCE_ID` (CloudShell has the plugin) and run:

```bash
sudo dnf install -y git python3.11 python3.11-pip tmux jq
git clone --branch registry-report https://github.com/mcpprobe-dev/mcpprobe.git ~/mcpprobe
cd ~/mcpprobe && python3.11 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
python -m pytest -q tests/test_registry_report.py      # sanity check on this host
touch ~/exclusions.txt                                 # one host per line; *.zone for a zone
tmux new -s survey                                     # detach with Ctrl-b d; reattach: tmux attach -t survey

W=~/survey
python -m mcpprobe.registry fetch -w $W                # about 1 s per 100 entries
python -m mcpprobe.registry scan  -w $W --exclude-file ~/exclusions.txt --dry-run   # prints the plan and estimate
python -m mcpprobe.registry scan  -w $W --exclude-file ~/exclusions.txt --limit 25  # canary: check the results
jq -r .status $W/scan.jsonl | sort | uniq -c
python -m mcpprobe.registry scan  -w $W --exclude-file ~/exclusions.txt 2>&1 | tee -a $W/scan.log
```

Progress, from a second tmux window:

```bash
wc -l < ~/survey/scan.jsonl; jq -r .status ~/survey/scan.jsonl | sort | uniq -c
aws s3 sync ~/survey s3://$BUCKET/survey/ --exclude 'report/*'    # hourly backup (private bucket)
```

To stop, press Ctrl-C. Re-running the same `scan` command resumes. Hosts already in
`scan.jsonl` are skipped, and a provider that answered 429/403 stays stopped. To retry
such a provider, delete its `blocked` lines from `scan.jsonl`.

**If an operator asks you to stop:**

1. Add their host or zone to `~/exclusions.txt`.
2. Press Ctrl-C and re-run `scan`.
3. Reply with confirmation.

Excluded hosts drop out of the aggregates and the disclosure queue, even when they were
already scanned.

When the scan has finished:

```bash
python -m mcpprobe.registry calibrate -w $W      # hardened fixture must give zero findings, or it fails
python -m mcpprobe.registry aggregate -w $W
python -m mcpprobe.registry render    -w $W      # mcpprobe.tech may always be named; --allow-host only for other hosts of ours
aws s3 cp --recursive $W/report s3://$BUCKET/report/
aws s3 cp $W/PRIVATE-disclosure-queue.json s3://$BUCKET/private/
```

### After a scanner update: recheck and reaggregate

`scan.jsonl` keeps outcomes, not tool descriptions, so improved META-01 rules cannot be
applied to stored results. Two stages refresh them:

- `reaggregate` (offline) re-runs the static checks on the tool definitions stored in
  `entries.jsonl`, merges `scan.jsonl` with every recheck pass, rebuilds `aggregates.json`,
  the PRIVATE queue and `disclosure-summary.json`, and prints each metric before and after.
  META-01 rates count only hosts whose META-01 outcome came from the current rules
  (`meta01_rules`); older outcomes are reported as stale and left out.
- `recheck` re-runs survey-profile checks (default `META-01,META-03,META-05,META-07`) on
  every scanned host whose tool list was visible, or with `--from-queue` only on hosts in
  the PRIVATE queue. Every scan rule applies: opt-out first, the same User-Agent, 1
  request/s per provider, at most 8 hosts, public pinned addresses, same origin, and stop on
  429/403. A provider that refused us in the scan or in an earlier recheck is not contacted.
  Re-running resumes; `--new-pass` archives the current pass and checks every selected
  host again. `--dry-run` prints the plan and runtime estimate.

```bash
python -m mcpprobe.registry reaggregate -w $W                      # offline; queue without stale META-01
python -m mcpprobe.registry recheck     -w $W --exclude-file ~/exclusions.txt --dry-run
python -m mcpprobe.registry recheck     -w $W --exclude-file ~/exclusions.txt 2>&1 | tee -a $W/recheck.log
python -m mcpprobe.registry reaggregate -w $W
python -m mcpprobe.registry render      -w $W
# later, to refresh only the queue:
python -m mcpprobe.registry recheck     -w $W --from-queue --new-pass --exclude-file ~/exclusions.txt
```

A recheck costs about the same per host as the scan (opt-out document, negotiation, the
three list methods; budget 10 requests, 10 s per host). For ~11,750 hosts with visible tool
lists that is at least 11,750 x 10 s / 8 = about 4.1 hours, or the largest provider group
x 10 s if that is longer; `recheck --dry-run` prints the exact figure for your data.

### 4. Tear down

```bash
aws ec2 terminate-instances --instance-ids $INSTANCE_ID
aws ec2 wait instance-terminated --instance-ids $INSTANCE_ID
aws ec2 release-address --allocation-id $ALLOC_ID   # keep it instead if the published IP must stay stable
aws ec2 delete-security-group --group-id $SG_ID
```

Keep the bucket until the disclosure window has closed. After that, delete the private
working state:

```bash
aws s3 rm --recursive s3://$BUCKET/survey/ && aws s3 rm --recursive s3://$BUCKET/private/
```

## Runtime and cost

**Fetch.** One request per page of 100 entries, at 1 request/s. Several thousand
entries take under two minutes.

**Scan.** Each host costs about 10 requests at 1 per second, so about 10 s. This is
`EST_REQUESTS_PER_HOST` in `batch.py`; the fixtures measured 3 to 7 requests per host.
Eight hosts run in parallel, but a provider's hosts run one after another. The runtime is
therefore the larger of two numbers:

- hosts x 10 s / 8;
- the largest provider group x 10 s.

`scan --dry-run` prints this figure for the real target list after `fetch`.

| Unique remote hosts | Spread over many providers | If one provider hosts 300 of them |
|---|---|---|
| 500 | about 10 min | about 50 min |
| 1,000 | about 21 min | about 50 min |
| 2,000 | about 42 min | about 55 min |
| 5,000 | about 1.7 h | about 1.7 h |

**Dead hosts.** These add timeouts: up to 15 s per request, and a handful of requests
before a host is marked unreachable. Run the canary (`--limit 25`) and budget two to
three times the dry-run figure. Expect a multi-hour run, which is why CloudShell is not
suitable.

The number of remote entries in the registry was not measured: the build environment
could not reach the registry. Third-party indexes put the whole registry at several
thousand servers, and only some of them have remote endpoints.

**Cost** (us-east-1 list prices; London is about 10% higher; check current prices):

| Item | Price | One survey (allow a day) |
|---|---|---|
| t3.small on demand | about $0.021/h | about $0.50 |
| Public IPv4 / Elastic IP | $0.005/h while allocated | about $0.12 |
| 8 GB gp3 | about $0.08/GB-month | under $0.05 |
| Data transfer out | a few KB per request, under 1 GB in total | covered by the 100 GB/month free allowance |
| S3 | a few MB | under $0.01 |

The total is about $1. Keeping the Elastic IP between surveys costs about $3.60 a month.

## Responsible disclosure

`aggregate` writes `PRIVATE-disclosure-queue.json`. In the survey an open server is a
description, not a vulnerability, so AUTH-01, AUTH-02 and TRANS-05 never qualify a host on
their own. A host is queued only for:

| Priority | Criterion |
|---|---|
| P1 | secrets in tool metadata (META-05 high/critical) |
| P2 | command execution or file access on an open server (META-03 high/critical, no authentication), or a token-validation bypass (AUTH-04 high/critical, not in the survey profile) |
| P3 | tool poisoning at high (META-01 high from the current rules) |
| P4 | lethal trifecta on an open server (META-07, no authentication) |

Each entry has `priority` (the highest that applies), `priorities`, `reasons`, the
qualifying `checks` and other findings as `context`. `disclosure-summary.json` holds the
counts per priority and per reason, with no host, and may be shared. Re-running
`aggregate` keeps the fields you fill in by hand: `notified_at`, `fixed_at`, `may_name`,
`contact` and `notes`. An entry that no longer qualifies is dropped, unless one of those
fields is set; it then stays with `priority: null` until you close it.

1. **Confirm first.** Check each queued host by hand with the same passive requests, for
   example `mcpprobe <url> --only AUTH-01 --only META-01 -v`. Do not run active checks
   and do not call tools. Anything you cannot confirm passively is dropped.
2. **Find a contact**, in this order:
   - `https://<host>/.well-known/security.txt`;
   - `security@<domain>`;
   - the security policy or maintainer listed in the registry entry's repository;
   - the registry maintainers, as a last resort (for a server with no reachable owner,
     or one that looks malicious; the registry's moderation can act on those).

   `scripts/outreach_contacts.py --segment A` does the published-channel part of this
   (security.txt, the repository's SECURITY.md, the entry's website) and writes a PRIVATE
   CSV with the source and date of each contact. It guesses `security@<domain>` only with
   `--allow-rfc2142`, and marks such rows not eligible until you decide. `--dry-run
   --fixtures DIR` fetches nothing.
3. **Send a private report.** State what was observed, the date, the check ID, the fix
   text from CHECKS.md, and that the scan was passive and called no tool. Link the
   scanning policy. Do not send anything a third party could misuse in transit: keep
   tool text to the minimum needed to recognise the issue.
4. **The deadline is 90 days** from first contact, or sooner if the operator confirms a
   fix. Record `notified_at` and, once verified, `fixed_at`.
5. **Publish aggregates only.** The report never names a host whose finding is unfixed.
   A host whose finding is fixed is named only if all of the following hold:
   - its queue entry has `"may_name": true`, set after the operator agreed in writing;
   - `render --name-fixed` is used;
   - otherwise, fixed issues appear only as a count.
6. **Do not publish specifics of unfixed issues after 90 days.** This survey has no
   full-disclosure deadline. Unfixed issues stay in the aggregates only. If an issue puts
   users at risk and the operator does not respond, escalate to the registry maintainers.

## What this cannot verify

- **Live registry API shape.** The API shape was taken from the registry repository's
  `docs/reference/api/openapi.yaml` and the "Registry aggregators" documentation, both
  read on 2026-10-31: `GET /v0.1/servers` with `limit`, `cursor` and `version=latest`,
  items `{server, _meta}`, and `metadata.nextCursor`. The live service was not reachable
  from the build environment. `--api-path /v0/servers` exists for the older path, and the
  normaliser also accepts flat items, but neither was checked against the live service.
- **Tool definitions in registry metadata.** Tool definitions under the publisher-provided
  `_meta` key are an optional convention, not part of `server.json`. Expect most entries
  to be "not assessable" by the static stage.
- **Pinned connections behind CDNs.** Pinning sets the `sni_hostname` extension of
  httpx/httpcore and keeps the original `Host` header. This was checked against a local
  TLS server: the certificate is verified against the hostname, and a wrong SNI is
  rejected. It was not checked against real CDNs. Confirm on the canary run that hosts
  behind a CDN are not reported unreachable in bulk.
