# At-Rest Security Review — Rails 5.2.0.beta2

**Date:** 2026-05-10  
**Branch:** `cursor/at-rest-security-review-4275`  
**Reviewer:** Automated Security Agent

---

## Summary

| # | Severity | Location | Title |
|---|----------|----------|-------|
| 1 | HIGH | `activestorage/app/controllers/active_storage/disk_controller.rb:10-16` | Active Storage Disk Controller Content-Type Override → XSS |
| 2 | MEDIUM | `activerecord/lib/active_record/core.rb:92` + `attribute_methods.rb:182-208` | SQL Injection via `order()` with default `allow_unsafe_raw_sql = :deprecated` |
| 3 | MEDIUM | `activesupport/lib/active_support/key_generator.rb:65-69` | Application secret leaked in error message |

---

## Finding 1: Active Storage Disk Controller Content-Type Override → XSS

**Severity:** HIGH  
**Location:** `activestorage/app/controllers/active_storage/disk_controller.rb:10-16`  
**Verified:** true

### Description

The `ActiveStorage::DiskController#show` action serves file bytes with `Content-Type` and `Content-Disposition` headers taken directly from unsigned URL query parameters. Only the `encoded_key` parameter is cryptographically signed (with an expiration). The `content_type` and `disposition` parameters are passed through from `params` without verification.

```ruby
def show
  if key = decode_verified_key
    send_data disk_service.download(key),
      disposition: params[:disposition], content_type: params[:content_type]
  else
    head :not_found
  end
end
```

While `BlobsController` applies `forcibly_serve_as_binary?` protection (forcing `text/html`, `text/javascript`, `image/svg+xml` etc. to be served as `attachment`), this check only runs at **URL generation time** — not at the Disk endpoint itself. The Disk endpoint trusts query params blindly.

### Impact

An attacker who obtains or intercepts a valid Active Storage Disk URL can modify the `content_type` query parameter to `text/html` (or `image/svg+xml`), causing the browser to interpret uploaded file bytes as HTML. Since the Disk service runs on the **same origin** as the application (unlike S3/GCS which use different domains), this results in **Cross-Site Scripting (XSS)** in the application's authentication context — giving access to cookies, CSRF tokens, and full session hijack.

### Attack Path

1. Attacker uploads a file containing HTML/JavaScript payload (e.g., disguised as an image or with benign content type).
2. The application generates a valid Disk URL and redirects (via `BlobsController`). The redirect `Location` header contains the signed `encoded_key` along with `content_type` and `disposition` as query params.
3. Attacker captures the redirect URL (e.g., from browser network tab, leaked in logs/referrer, or via their own upload).
4. Attacker modifies the `content_type` query param to `text/html` while keeping the valid signed `encoded_key` intact.
5. Victim visits the modified URL. `DiskController#show` verifies only the key, then serves the file with `Content-Type: text/html`.
6. Browser renders the HTML → JavaScript executes in the application's origin → session cookies, CSRF tokens, and DOM are accessible.

**Note:** For cloud services (S3, GCS, Azure), the `response_content_type` is embedded in the presigned URL signature, so this attack does NOT apply. It is **specific to the Disk storage backend**.

### Evidence

- `activestorage/app/controllers/active_storage/disk_controller.rb:13` — `content_type: params[:content_type]` passed to `send_data`
- `activestorage/lib/active_storage/service/disk_service.rb:69-77` — Only `key` is signed; `content_type` is a plain URL param
- `activestorage/app/models/active_storage/blob.rb:191-193` — `forcibly_serve_as_binary?` only checked at blob URL generation, not at disk serving
- Contrast with `activestorage/lib/active_storage/service/s3_service.rb:63-65` — S3 presigns with `response_content_type` in signature

### Remediation

The `DiskController#show` action should either:
1. Include `content_type` and `disposition` in the signed payload (like S3 does with presigned URLs), OR
2. Look up the blob metadata from the database using the key and derive `content_type`/`disposition` from stored blob attributes (applying `forcibly_serve_as_binary?`), OR
3. At minimum, whitelist `content_type` against the blob's stored type and restrict `disposition` to `inline`/`attachment`.

```ruby
def show
  if key = decode_verified_key
    blob = ActiveStorage::Blob.find_by(key: key)
    if blob
      content_type = blob.forcibly_serve_as_binary? ? "application/octet-stream" : blob.content_type
      disposition = blob.forcibly_serve_as_binary? ? :attachment : params[:disposition]
      send_data disk_service.download(key),
        disposition: ActiveStorage::Service.content_disposition_with(type: disposition, filename: blob.filename),
        content_type: content_type
    else
      head :not_found
    end
  else
    head :not_found
  end
end
```

---

## Finding 2: SQL Injection via `order()` — Warning-Only Default

**Severity:** MEDIUM  
**Location:** `activerecord/lib/active_record/core.rb:92`, `activerecord/lib/active_record/attribute_methods.rb:182-208`  
**Verified:** true

### Description

Rails 5.2 introduces `enforce_raw_sql_whitelist` for `order`/`reorder`/`pluck` to detect non-attribute-name arguments. However, the default setting `allow_unsafe_raw_sql = :deprecated` only **logs a deprecation warning** and **still executes the query**. SQL injection via raw string arguments to `order()` remains possible in production when applications pass user input.

Additionally, several query methods (`group`, `select`, `joins` (string), `from`, `lock`, `update_all` (string), aggregate methods like `sum`/`average`) have **no whitelist check at all** and accept raw SQL strings without any sanitization.

### Impact

Applications that pass user-controlled input (e.g., sort parameters from requests) directly to `order()`, `group()`, `select()`, or similar methods are vulnerable to SQL injection. The framework's default behavior warns but does not prevent exploitation.

### Attack Path

1. Application has code like `Model.order(params[:sort])` or `Model.group(params[:group_by])`.
2. Attacker sends `sort=id; DROP TABLE users--` or `sort=(SELECT password FROM users LIMIT 1)`.
3. For `order()`: `enforce_raw_sql_whitelist` detects the non-attribute argument but only emits a deprecation warning (default `:deprecated`).
4. Query executes with attacker-controlled SQL fragment in ORDER BY clause.
5. For `group()`/`select()`/`joins()`/`from()`: No whitelist check exists at all — raw SQL passes through directly.

### Evidence

- `activerecord/lib/active_record/core.rb:92` — `mattr_accessor :allow_unsafe_raw_sql, instance_writer: false, default: :deprecated`
- `activerecord/lib/active_record/attribute_methods.rb:192-201` — Warning only, query still executes
- `activerecord/lib/active_record/relation/query_methods.rb:1034-1038` — `joins` wraps strings in `Arel.sql()` with no validation
- `activerecord/lib/active_record/relation/calculations.rb:235-242` — `aggregate_column` wraps unknown column names in `Arel.sql()`

### Remediation

- Set `ActiveRecord::Base.allow_unsafe_raw_sql = :disabled` in production to raise exceptions instead of warnings.
- Application code should never pass raw user input to query methods; use column whitelists.
- Framework should consider making `:disabled` the default in a future version.

---

## Finding 3: Application Secret Leaked in Error Message

**Severity:** MEDIUM  
**Location:** `activesupport/lib/active_support/key_generator.rb:65-69`  
**Verified:** true

### Description

The `LegacyKeyGenerator` constructor validates that the provided secret meets a minimum length requirement. If the secret is too short, it raises an `ArgumentError` that **includes the actual secret value** in the error message.

```ruby
if secret.length < SECRET_MIN_LENGTH
  raise ArgumentError, "Secret should be something secure, " \
    "like \"#{SecureRandom.hex(16)}\". The value you " \
    "provided, \"#{secret}\", is shorter than the minimum length " \
    "of #{SECRET_MIN_LENGTH} characters."
end
```

### Impact

If this error is triggered during application startup and the error is captured by an error reporting service (Sentry, Bugsnag, Honeybadger), logged to a centralized logging system, or rendered in a development/staging error page, the **actual secret value is disclosed** to anyone with access to those systems.

### Attack Path

1. Developer configures a short/weak `secret_key_base` (under 30 characters) during setup.
2. Application raises `ArgumentError` on boot containing the literal secret value.
3. Error is captured by error-reporting middleware, logged to stdout/file, or displayed in a web error page.
4. Attacker with access to logs/error reports (insider, log aggregation breach, exposed error pages) obtains the secret.
5. With the secret, attacker can forge signed cookies, decrypt encrypted cookies, and achieve session hijack or RCE (via Marshal deserialization gadgets on forged cookies).

### Evidence

- `activesupport/lib/active_support/key_generator.rb:65-69` — Secret value interpolated into error message string

### Remediation

Remove the secret value from the error message. Report only that the secret is too short:

```ruby
if secret.length < SECRET_MIN_LENGTH
  raise ArgumentError, "Secret should be something secure, " \
    "like \"#{SecureRandom.hex(16)}\". The value you " \
    "provided is shorter than the minimum length " \
    "of #{SECRET_MIN_LENGTH} characters."
end
```

---

## Notes

- **Slack posting failed:** The Cursor bot is not invited to `#topic-security`. Findings documented here instead.
- This review covers the Rails framework source code itself. Many findings require specific application-level patterns to be exploitable (e.g., passing user input to `order()`). The Active Storage Disk Controller finding (Finding 1) is exploitable in any application using the Disk storage backend with default configuration.
