# ZAI-82 — WARP egress integration: public summary

> **Privacy update (2026-11-20).** This document remains at its original URL for reference compatibility. Field measurement tables, actual VPS addresses, Cloudflare endpoints, site/host identifiers and packet traces have been removed from the public version. Detailed evidence remains accessible only in the restricted internal research environment, without a public link.

## Scope of the historical test

A disposable test environment was used to verify the integration sequence:

```text
authorized test client → private tunnel → policy routing → Mihomo TUN → WARP outbound → Internet
```

The test methodology distinguished discovery from actual tunnel data transfer, validated generated configuration syntax with Mihomo, and tested **fail-closed behavior** when the outbound became unavailable.

## Reusable engineering lessons

- A WARPSCOUT candidate is an observation at a given time and network, not a durable Cloudflare route or a universal endpoint recommendation.
- A successful tunnel scan alone does not prove traffic takes the intended path. Verify the selected outbound, client-plane traffic, egress trace and absence of direct fallback separately.
- Build/import of WG profiles may complete asynchronously; do not generate the final Mihomo YAML before import is finished.
- Test outage handling: the WARP tunnel or Mihomo service being unavailable must not silently route private client traffic via DIRECT.
- DNS egress, IPv6 coverage and post-restart policy-routing recovery require distinct checks and evidence classifications.

## Operational and privacy limits

This historical summary does not establish current VPS state. No live host changes are authorized by this page. Avoid publicizing a real public server IP, source/destination addresses, subscriber locations, selected WARP endpoints, exact performance results or source logs. Authorized operators should consult the internal evidence store for the dated full case without publishing its location.
