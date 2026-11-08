# Cloud-Based Digital Forensics System: Backend

FastAPI + SQLAlchemy backend that follows Chapter 3 (requirements FR1-FR10, NFR1-NFR8).

## Run it locally

```bash
cd backend
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements-dev.txt

# Set the first admin account (otherwise a temporary password is printed on first start)
export ADMIN_PASSWORD='choose-a-strong-password'      # Windows: set ADMIN_PASSWORD=...
export SECRET_KEY='any-long-random-string'

uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/docs. This interactive page lets you try every endpoint.
Click **Authorize**, log in as `admin`, then create an investigator and a reviewer with `POST /api/users`.

Optional demo accounts for local testing only: `python -m app.seed` (investigator1 and reviewer1).

## Run the tests (your evaluation evidence)

```bash
pytest -v
```

Each test is labelled with the requirement it checks (FR/NFR), so the results table
for Chapter 4 can be taken straight from the output.

## Roles

| Role | Can do |
| --- | --- |
| admin | Manage users and roles; read the global audit log. **No access to evidence.** |
| investigator | Create cases, register, verify and retrieve evidence in **their own** cases |
| reviewer | Read-only access to all cases, evidence, custody trails and the audit log |

## Endpoints (all under /api)

| Method | Path | Purpose | Requirement |
| --- | --- | --- | --- |
| POST | /auth/login | Get a token | FR1 |
| POST/GET/PATCH | /users | Manage users (admin) | FR7 |
| POST/GET/PATCH | /cases | Create, list, update cases | FR2 |
| POST | /cases/{id}/evidence | Upload evidence; SHA-256 computed on arrival | FR3, FR4 |
| GET | /cases/{id}/evidence, /evidence/{id} | List and view evidence metadata | FR8 |
| GET | /evidence/{id}/download | Retrieve the file (logged) | FR8 |
| POST | /evidence/{id}/verify | Recalculate hash and compare | FR5 |
| GET | /evidence/{id}/custody | Chain-of-custody trail | FR6 |
| GET | /audit, /audit/verify-chain | Audit log and tamper check | FR6 |
| GET | /cases/{id}/report | Case report (JSON) | FR9 |
| GET | /search?q= | Search cases and evidence | FR10 |

## Cloud storage (S3 or MinIO)

Set `STORAGE_BACKEND=s3`, `S3_BUCKET=...` (plus `S3_REGION`, and `S3_ENDPOINT_URL` for MinIO)
and provide AWS credentials the normal way (environment variables or an IAM role).
Local disk is used by default so you can develop without a cloud account.
