# GateBridge Example Policies

This directory contains example policies for testing GateBridge shadow evaluation.

## Files

| File | Description |
|------|-------------|
| `minimal.yaml` | Simplest valid policy (default only) |
| `oidc_groups.yaml` | OIDC group-based access control |
| `ip_restricted.yaml` | IP/CIDR-based restrictions |
| `time_based.yaml` | Business hours enforcement |
| `complex.yaml` | Multi-condition policies |

## Usage

```bash
# Test with GateBridge
gatebridge validate examples/policies/minimal.yaml
gatebridge shadow examples/policies/oidc_groups.yaml request.json
```

## Request Format

```json
{
  "subject": "alice",
  "oidc_groups": ["developers"],
  "email": "alice@example.com",
  "local_username": "alice",
  "source_ip": "10.0.0.5",
  "current_time": "14:30",
  "webauthn_id": null
}
```
