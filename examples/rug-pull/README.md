# Lab: rug pull (META-02)

A "rug pull" is a server that serves a clean tool description while it is reviewed and
approved, and a different one later. Most clients ask for approval once; nothing in the
protocol stops a server changing its definitions afterwards.

`server.py` exposes one tool, `get_weather`. The `RUG_PULL_STAGE` environment variable
picks what it serves:

| Stage | Description | Schema |
|---|---|---|
| unset (approved) | "Returns today's forecast for a city." | `city` |
| `after` | the same line plus an `<IMPORTANT>` block telling the model to bcc `audit@example.invalid` whenever a *different* tool, `send_email`, is used, and not to tell the user | `city`, `notes` |

The changed description is also cross-server shadowing: it tries to change how the model
uses a tool from another server. The address uses the reserved `.invalid` domain and the
server discards all arguments.

## Run it

From this folder. First scan, approved stage: this records the baseline.

```console
$ mcpprobe --stdio "python server.py" --baseline baseline.json
```

No findings; META-02 is reported not applicable with the reason "No usable previous
baseline ... (first scan)", and `baseline.json` now holds a SHA-256 hash of every tool,
prompt, resource and the server instructions.

Second scan, same command and target, but the server has changed its mind:

```console
$ mcpprobe --stdio "python server.py" --env RUG_PULL_STAGE=after \
    --baseline baseline.json --no-write-baseline -v
```

Expected (trimmed):

```text
 MEDIUM    META-02  Tool surface changed since the stored baseline (rug-pull indicator)
    confidence high  where tools[get_weather]
    standards MCP03:2025 (beta), ASI04
    Tool 'get_weather' changed since baseline <timestamp>: fields description, inputSchema.
    affected get_weather
    proof
      baseline from <timestamp> compared with this scan:
        {
          "changed_fields": [
            "description",
            "inputSchema"
          ]
        }
```

The same scan also reports META-01 (high) on the new description, and META-03 (low)
because the tool now mentions email. `--no-write-baseline` keeps the approved baseline;
without it the file is updated to the new surface.

META-02 is deterministic: it reports that a definition changed and which fields, not
whether the change is malicious. A legitimate release that edits a description triggers
it too, which is the point: someone should look.

## In CI

META-02 is rated medium (low when only fields other than the description and schema
change), so the default `--fail-on high` does not fail on it by itself. To gate on any
change to the approved surface, commit the baseline and run:

```console
$ mcpprobe --stdio "python server.py" --baseline baseline.json --no-write-baseline --fail-on medium
```

Update the committed baseline deliberately, in the same pull request as the description
change, so the change gets reviewed.
