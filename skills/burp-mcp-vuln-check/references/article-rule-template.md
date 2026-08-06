# Article Rule Extraction Template

Use this template when a vulnerability writeup, WeChat article, PoC, or advisory is the source of truth.

## Required Fields

- Source URL:
- Vulnerability name/class:
- Affected product/framework/component:
- Version range or fingerprint:
- Required authentication/role:
- Candidate paths:
- Candidate parameters/headers/cookies/body fields:
- Content types:
- Positive indicators:
- Negative indicators:
- Safe probe payloads:
- OOB probe location:
- Evidence needed for confirmation:
- Non-goals/destructive actions to avoid:

## Probe Design

1. Find matching requests in Burp proxy history by host, path, product keyword, parameter name, file extension, or response marker.
2. Replay the unmodified request to establish a baseline.
3. Apply the article's minimal safe payload to one input.
4. Send a negative control that is syntactically similar but should not trigger the vulnerability.
5. Compare baseline, control, and probe.
6. If blind behavior is expected, use a Burp Collaborator payload and record interaction type, timestamp, and client IP/protocol metadata.

## Confirmation Threshold

Call the issue confirmed only when at least one of these is true:

- The response contains the article's documented success marker and the negative control does not.
- The OOB payload receives an interaction that correlates to the tested request.
- A bounded timing probe produces repeatable deltas across multiple baseline/control/probe cycles.
- The application exposes a non-sensitive, deterministic file/object/marker that should be unreachable and is specific to the documented bug.

Otherwise classify as likely or inconclusive and explain what is missing.


