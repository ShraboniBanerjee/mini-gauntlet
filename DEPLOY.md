# Running Mini Gauntlet in production on AWS

A design note; nothing here is deployed.

## Shape

```
Route 53 ─► CloudFront + WAF ─► ALB (HTTPS, public subnets)
                                  ├─ /api/* ─► api        (ECS Fargate) ──► SQS scan queue
                                  └─ /*     ─► dashboard  (ECS Fargate)          │
                                                                                 ▼
          RDS PostgreSQL (Multi-AZ) ◄── api, scan-worker ◄──────── scan-worker (ECS Fargate)
                                                                      │ read-only roles
                                                                      ▼
                                                    customer AWS, Azure and Google Cloud
```

Everything except the ALB runs in private subnets.

**Compute.** ECS on Fargate with the same images CI builds, pushed to ECR. Three
services: `dashboard` (nginx), `api` (FastAPI) and `scan-worker`. In production the API
doesn't run scans itself: `POST /api/scans` writes the RUNNING scan and puts a message on
SQS, and workers take it. Workers scale on queue depth, a crashed worker's message
returns to the queue after its visibility timeout, and a dead-letter queue catches scans
that keep failing. The worker limit stays per task (`SCAN_WORKERS`), so cloud API rate
limits are respected.

**Collecting inventory.** A worker replaces `inventory.json` with live API calls. It
signs in to each customer account with the read-only identities below, calls the
provider APIs (the real work behind `simulated_latency_ms`), and writes the raw responses
to S3 as a snapshot in the same shape as `inventory.json`: one object per scan, encrypted,
with a lifecycle rule. The same check registry then runs over that snapshot, so live and
offline scans share every line of check code, and any result can be replayed later from
its snapshot. Denied calls become `errors` entries, which the engine already turns into
CANNOT_SCAN findings.

**Database.** RDS for PostgreSQL, Multi-AZ, encrypted with KMS, automated backups and
point-in-time recovery. SQLite only suits a single instance; `store.py` is plain SQL and
ports with small changes (placeholders, `SERIAL`). Old findings are pruned or archived to
S3 on a schedule.

**Networking.** One VPC across two Availability Zones. Only the ALB sits in public
subnets; tasks and RDS are in private subnets. Security groups chain ALB → api/dashboard
→ RDS on 5432 only. Workers reach cloud provider APIs through a NAT gateway; VPC
endpoints keep ECR, S3, SQS, STS, Secrets Manager and CloudWatch Logs traffic off the
internet. TLS uses an ACM certificate. The dashboard shows a customer's weaknesses, so
it sits behind sign-in: ALB OIDC authentication against the company's identity provider.

**Secrets.** No keys in images, env files or the repository. Database credentials live
in Secrets Manager with automatic rotation, injected through the ECS task definition's
`secrets` (or replaced by RDS IAM authentication). Each service has its own task role
with only what it needs: the API can send to the queue, the worker can receive from it
and call `sts:AssumeRole` on customer scan roles.

**Logs and monitoring.** The `awslogs` driver sends container logs to CloudWatch Logs
(JSON, 30-day retention, longer in S3). Alarms on ALB 5xx, unhealthy targets, queue age,
dead-letter messages, the share of FAILED scans and a jump in CANNOT_SCAN findings,
which usually means a customer changed a role's permissions. CloudTrail records every
`AssumeRole` into customer accounts.

**Deploying from CI without long-lived keys.** GitHub Actions requests an OIDC token and
calls `sts:AssumeRoleWithWebIdentity`. The deploy role's trust policy only accepts
`token.actions.githubusercontent.com` with audience `sts.amazonaws.com` and subject
`repo:<org>/mini-gauntlet:environment:production`, so only the protected production
environment on the main repository can deploy. That role can push to the two ECR
repositories, register task definitions, update the three ECS services, and
`iam:PassRole` only for their task and execution roles. A deploy is: build, scan the
image, push by digest, update services, wait for them to be stable.

## Least-privilege permissions for a live scanner

Customers grant read-only access to exactly what the catalog reads, nothing broader.

**AWS**: a role in each customer account, trusting the worker's task role with an
`sts:ExternalId` unique to the customer (prevents the confused-deputy problem).

| Check | Actions |
| --- | --- |
| AWS-S3-01 | `s3:ListAllMyBuckets`, `s3:GetBucketLocation`, `s3:GetBucketPublicAccessBlock`, `s3:GetAccountPublicAccessBlock` |
| AWS-EC2-01 | `ec2:DescribeRegions`, `ec2:DescribeSecurityGroups` |
| AWS-IAM-01 | `iam:ListUsers`, `iam:GetLoginProfile`, `iam:ListMFADevices` |
| AWS-IAM-02 | `iam:ListUsers`, `iam:ListAccessKeys` |
| AWS-RDS-01 | `rds:DescribeDBInstances` |

The IAM checks could use the credential report instead, but `iam:GenerateCredentialReport`
creates a resource, so the per-user calls keep the role strictly read-only. AWS's managed
`SecurityAudit` policy covers all of this but grants far more.

**Azure**: a custom role at subscription scope, instead of the broad built-in Reader,
with `Microsoft.Resources/subscriptions/resourceGroups/read`,
`Microsoft.Storage/storageAccounts/read` (AZ-STG-01) and
`Microsoft.Network/networkSecurityGroups/read` (AZ-NSG-01, rules included). The scanner
signs in as a multi-tenant Entra application through workload identity federation, so
no client secret is stored.

**Google Cloud**: a custom role on the project with `resourcemanager.projects.get`,
`storage.buckets.list`, `storage.buckets.get` (GCP-GCS-02), `storage.buckets.getIamPolicy`
(GCP-GCS-01) and `compute.firewalls.list` (GCP-VPC-01), granted to a service account
that the worker impersonates through Workload Identity Federation with AWS as the
identity provider. No service-account key exists.
