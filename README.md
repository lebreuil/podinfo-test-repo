# Application repository template

This repository is a template for applications deployed through the shared
Kubernetes platform and Argo CD.

## Structure

- `deploy/values.yaml` contains Helm values.
- `deploy/manifests/` contains namespace-local manifests such as
  `SecretStore` and `ExternalSecret`.
- `scripts/app-secrets-init.py` initializes application secrets in OpenBao.
- `.env.example` documents the required local environment variables.

The platform Terraform configuration owns the application namespace, OpenBao
namespace, ingress, DNS record, and Cloudflare Access application. Application
repositories own Helm values, application manifests, and secret
initialization.

## Secret initialization

```bash
cp .env.example .env
# Edit .env with the application OpenBao token and Cloudflare Access credentials.
set -a
source .env
set +a
python3 scripts/app-secrets-init.py
```

The `.env` file and generated secret values must never be committed.
