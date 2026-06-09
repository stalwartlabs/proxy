#!/usr/bin/env python3
"""Build a Stalwart CLI migration plan from a Stalwart v0.15 server.

This reads principal (account) definitions from a running Stalwart v0.15
server through its management API and emits an NDJSON plan that the Stalwart
CLI can apply against a new (latest) Stalwart server to recreate those
accounts:

    stalwart-cli apply --file migration-plan.ndjson

Each line of the plan is a create operation in the form consumed by
`stalwart-cli apply`:

    {"@type":"create","object":"Domain","value":{"<ref>":{...}}}
    {"@type":"create","object":"Account","value":{"<ref>":{"@type":"User",...}}}

Accounts reference their domain through a plan-local "#<ref>" placeholder that
the CLI resolves while applying. When a domain already exists on the target
server, pass --existing-domain NAME=ID so accounts reference the real id
instead of trying to recreate the domain.

Password hashes are migrated verbatim, so users keep their existing passwords.
App passwords and one-time-password (TOTP) secrets are not migrated.

If a username is given, only that account is exported; otherwise every
individual (optionally every group with --include-groups) is exported.
"""

import argparse
import base64
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

PAGE_SIZE = 200
REQUEST_TIMEOUT = 60


class ApiError(RuntimeError):
    pass


class StalwartV015Client:
    def __init__(self, url, token=None, username=None, password=None, insecure=False):
        self.base = url.rstrip("/")
        if token:
            self.auth = "Bearer " + token
        elif username is not None:
            raw = f"{username}:{password or ''}".encode()
            self.auth = "Basic " + base64.b64encode(raw).decode()
        else:
            raise ValueError("either a token or a username must be provided")
        self.ctx = None
        if insecure:
            self.ctx = ssl.create_default_context()
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def get(self, path, params=None):
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, method="GET")
        req.add_header("Authorization", self.auth)
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=self.ctx) as resp:
                payload = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            raise ApiError(f"{exc.code} {exc.reason} for {path}: {body}") from exc
        except urllib.error.URLError as exc:
            raise ApiError(f"cannot reach {url}: {exc.reason}") from exc
        if isinstance(payload, dict) and "data" in payload:
            return payload["data"]
        return payload

    def list_principal_names(self, types):
        names = []
        for kind in types:
            page = 1
            while True:
                data = self.get(
                    "/api/principal",
                    {"page": page, "limit": PAGE_SIZE, "types": kind},
                )
                items = data.get("items") or []
                for item in items:
                    name = principal_name(item)
                    if name:
                        names.append(name)
                total = data.get("total") or 0
                if page * PAGE_SIZE >= total or not items:
                    break
                page += 1
        return names

    def fetch_principal(self, name):
        return self.get("/api/principal/" + urllib.parse.quote(name, safe=""))


def principal_name(record):
    name = record.get("name")
    if isinstance(name, dict):
        return name.get("string")
    return name


def scalar_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        if "stringList" in value:
            return value["stringList"]
        if "string" in value:
            return [value["string"]]
        return list(value.values())
    return [value]


def scalar(value):
    if isinstance(value, dict):
        for key in ("string", "integer"):
            if key in value:
                return value[key]
        return None
    return value


def domain_ref(domain):
    safe = "".join(c if c.isalnum() else "_" for c in domain)
    return "domain_" + safe


def split_address(record):
    name = principal_name(record) or ""
    emails = [e for e in scalar_list(record.get("emails")) if e]
    primary = emails[0] if emails else name
    if "@" in primary:
        local, _, domain = primary.partition("@")
    elif "@" in name:
        local, _, domain = name.partition("@")
        primary = name
    else:
        local, domain = name, None
    return local, domain, primary, emails


def build_credentials(record):
    creds = {}
    index = 0
    for secret in scalar_list(record.get("secrets")):
        if not isinstance(secret, str) or not secret:
            continue
        if secret.startswith("$app$"):
            continue
        if secret.startswith("otpauth://"):
            continue
        creds[str(index)] = {"@type": "Password", "secret": secret}
        index += 1
    return creds


def build_aliases(primary, emails, domain_refs, existing):
    aliases = {}
    index = 0
    for email in emails:
        if email == primary or "@" not in email:
            continue
        local, _, domain = email.partition("@")
        ref = existing.get(domain) or ("#" + domain_ref(domain))
        aliases[str(index)] = {"name": local, "domainId": ref}
        domain_refs.add(domain)
        index += 1
    return aliases


def build_account(record, domain_value, existing):
    kind = scalar(record.get("type"))
    local, domain, primary, emails = split_address(record)
    if not domain:
        raise ApiError(
            f"principal {principal_name(record)!r} has no email domain; cannot map it"
        )
    seen_domains = {domain}
    domain_id = existing.get(domain) or ("#" + domain_ref(domain))

    account = {
        "@type": "Group" if kind == "group" else "User",
        "name": local,
        "domainId": domain_id,
    }
    description = scalar(record.get("description"))
    if description:
        account["description"] = description
    creds = build_credentials(record)
    if creds and kind != "group":
        account["credentials"] = creds
    if kind != "group":
        account["roles"] = {"@type": "User"}
        account["encryptionAtRest"] = {"@type": "Disabled"}
    aliases = build_aliases(primary, emails, seen_domains, existing)
    if aliases:
        account["aliases"] = aliases

    for dom in seen_domains:
        if dom not in existing:
            domain_value.setdefault(domain_ref(dom), {"name": dom})
    return account


def main():
    parser = argparse.ArgumentParser(
        description="Build a Stalwart CLI migration plan from a Stalwart v0.15 server.",
    )
    parser.add_argument("username", nargs="?", help="export only this account (default: all)")
    parser.add_argument("--url", required=True, help="base URL of the v0.15 server")
    parser.add_argument("--token", help="admin bearer token")
    parser.add_argument("--user", help="admin username (HTTP basic auth)")
    parser.add_argument("--password", help="admin password (HTTP basic auth)")
    parser.add_argument("--insecure", action="store_true", help="skip TLS verification")
    parser.add_argument("--include-groups", action="store_true", help="also export groups")
    parser.add_argument(
        "--existing-domain",
        action="append",
        default=[],
        metavar="NAME=ID",
        help="reference an existing target domain by id instead of creating it",
    )
    parser.add_argument(
        "--output",
        help="write the plan to this file (default: stdout)",
    )
    args = parser.parse_args()

    if not args.token and args.user is None:
        parser.error("provide --token or --user/--password")

    existing = {}
    for entry in args.existing_domain:
        if "=" not in entry:
            parser.error(f"--existing-domain expects NAME=ID, got {entry!r}")
        name, _, value = entry.partition("=")
        existing[name.strip()] = value.strip()

    client = StalwartV015Client(
        args.url,
        token=args.token,
        username=args.user,
        password=args.password,
        insecure=args.insecure,
    )

    if args.username:
        names = [args.username]
    else:
        types = ["individual"]
        if args.include_groups:
            types.append("group")
        names = client.list_principal_names(types)

    if not names:
        sys.stderr.write("no accounts to export\n")
        return 1

    domain_value = {}
    account_value = {}
    for name in names:
        record = client.fetch_principal(name)
        account = build_account(record, domain_value, existing)
        account_value["acct_" + str(scalar(record.get("id")) or name)] = account

    ops = []
    if domain_value:
        ops.append({"@type": "create", "object": "Domain", "value": domain_value})
    ops.append({"@type": "create", "object": "Account", "value": account_value})

    out = open(args.output, "w") if args.output else sys.stdout
    try:
        for op in ops:
            out.write(json.dumps(op) + "\n")
    finally:
        if args.output:
            out.close()

    sys.stderr.write(
        f"exported {len(account_value)} account(s), {len(domain_value)} domain(s)\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
