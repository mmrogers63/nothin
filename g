You are helping migrate an existing AWS CloudFront Terraform module to CloudFront SaaS Manager (multi-tenant distributions).

## Context

- Module is located at `terraform/reliance-cloudfront`
- Two AWS providers are already configured: default provider is GovCloud (Route 53 lives here), `aws.secondary` is commercial (CloudFront, ACM live here)
- The base domain is already passed in as a variable — do not hardcode any domain values
- FedRAMP compliant — no wildcard certificates, TLS 1.2 minimum, DNS validation only
- All DNS is controlled internally

## Your job

Read all files under `terraform/reliance-cloudfront` and produce a migration plan with exact changes only, using the real variable names, resource names, and module structure found in the code. Do not suggest changes to anything outside of `terraform/reliance-cloudfront`.

## The 5 changes to make

1. Remove `aws_cloudfront_distribution`
2. Add `aws_cloudfront_multitenant_distribution` (same config as the removed distribution, minus aliases and viewer cert — use cloudfront default cert at distribution level)
3. Add `aws_cloudfront_connection_group`
4. Add `aws_cloudfront_distribution_tenant` with `for_each` over the existing tenant variable
5. Move `aws_acm_certificate` from distribution level to per-tenant with `for_each` (explicit domain SAN, no wildcards — compose domain from the existing domain variable)

## Rules

- Keep `provider = aws.secondary` on all CloudFront and ACM resources
- Keep default provider (no alias) on all Route 53 records — do not change this
- `minimum_protocol_version` must be `TLSv1.2_2021` on every certificate block
- `ssl_support_method` must be `sni-only` everywhere
- `validation_method` must be `DNS` on all ACM certs
- All domain composition must reference the existing domain variable — never hardcode a domain value
- Do not change origins, WAF, IAM, S3, VPC, or any other resources
- Do not change provider configuration blocks
- Preserve all existing variable names, resource names, and module structure exactly as found
- Flag any existing config that uses features unsupported by multi-tenant distributions: dedicated IP SSL, WAF Classic v1, OAI, aliases on the distribution, Firewall Manager policies

## Output format

For each of the 5 changes produce:
- The exact file it lives in under `terraform/reliance-cloudfront`
- What is being removed (exact block from the real code)
- What replaces it (exact block using the real variable and resource names)
- Any flags or warnings specific to the existing code

Do not produce a general explanation. Only produce diffs and flags based on the actual code in `terraform/reliance-cloudfront`.
