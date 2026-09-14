# Application repository guidance

## Repository structure

- `deploy/values.yaml` contains application Helm values.
- `deploy/manifests/` contains namespace-local Kubernetes manifests.
- `scripts/app-secrets-init.py` generates and stores application secrets in
  OpenBao.
- `.env.example` documents the local secret-initialization environment.
- `.env` is local-only and must never be committed.

## Secret workflow

Copy `.env.example` to `.env`, fill in the OpenBao and Cloudflare Access
credentials, then run:

```bash
set -a
source .env
set +a
python3 scripts/app-secrets-init.py
```

Replace the example generated keys in the script with the keys required by the
application. Do not commit generated credentials, tokens, or `.env` contents.

## Application ownership

Keep application deployment configuration in this repository. Platform
Terraform owns shared infrastructure and the standard application resources
(namespace, OpenBao namespace, ingress, DNS, and Cloudflare Access), while
this repository owns Helm values, application manifests, and secret
initialization.
