#!/usr/bin/env python3

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

REQUEST_TIMEOUT = 60
DEFAULT_PAGE_SIZE = 500
MASKED = "****"
USING = ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"]
COPIED_FIELDS = ("description", "quotas", "locale", "timeZone")


class ApiError(RuntimeError):
    pass


class StalwartV016Client:
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
        self.api_url = None
        self.page_size = DEFAULT_PAGE_SIZE

    def request(self, url, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
        req.add_header("Authorization", self.auth)
        req.add_header("Accept", "application/json")
        if data:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=self.ctx) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise ApiError(f"{exc.code} {exc.reason} for {url}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise ApiError(f"cannot reach {url}: {exc.reason}") from exc

    def connect(self):
        session = self.request(self.base + "/.well-known/jmap")
        api_url = session.get("apiUrl")
        if not api_url:
            raise ApiError("the JMAP session does not advertise an apiUrl")
        self.api_url = self.base + (urllib.parse.urlsplit(api_url).path or "/jmap")
        core = (session.get("capabilities") or {}).get("urn:ietf:params:jmap:core") or {}
        max_get = core.get("maxObjectsInGet")
        if isinstance(max_get, int) and max_get > 0:
            self.page_size = min(DEFAULT_PAGE_SIZE, max_get)

    def call(self, method, args):
        resp = self.request(self.api_url, {"using": USING, "methodCalls": [[method, args, "c0"]]})
        responses = resp.get("methodResponses") or []
        if len(responses) != 1:
            raise ApiError(f"{method}: unexpected response {resp}")
        name, result, _ = responses[0]
        if name == "error":
            raise ApiError(f"{method}: {result.get('type')}: {result.get('description', '')}")
        return result

    def query_ids(self, obj):
        ids = []
        args = {"limit": self.page_size}
        while True:
            batch = self.call(f"x:{obj}/query", args).get("ids") or []
            ids.extend(batch)
            if len(batch) < self.page_size:
                return ids
            args = {"limit": self.page_size, "anchor": batch[-1], "anchorOffset": 1}

    def get_all(self, obj):
        objects = []
        ids = self.query_ids(obj)
        for start in range(0, len(ids), self.page_size):
            result = self.call(f"x:{obj}/get", {"ids": ids[start : start + self.page_size]})
            objects.extend(result.get("list") or [])
        return objects


def entries(value):
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value[k] for k in sorted(value, key=lambda k: int(k) if k.isdigit() else k)]
    return []


def as_list_map(items):
    return {str(i): item for i, item in enumerate(items)}


def domain_ref(domain):
    return "domain_" + "".join(c if c.isalnum() else "_" for c in domain)


class PlanBuilder:
    def __init__(self, domains, existing, warn):
        self.domains = domains
        self.existing = existing
        self.warn = warn

    def domain_target(self, domain_id, address, used):
        name = self.domains.get(domain_id)
        if name is None:
            raise ApiError(f"{address}: references unknown domain id {domain_id}")
        used.add(name)
        return self.existing.get(name) or ("#" + domain_ref(name))

    def credentials(self, account, address):
        creds = []
        skipped = 0
        for cred in entries(account.get("credentials")):
            if cred.get("@type") != "Password":
                skipped += 1
                continue
            secret = cred.get("secret")
            if not secret or secret == MASKED:
                raise ApiError(
                    f"{address}: the source returned a masked password; restart it with "
                    "STALWART_INCLUDE_SECRETS=1 in its environment"
                )
            out = {"@type": "Password", "secret": secret}
            otp = cred.get("otpAuth")
            if otp and otp != MASKED:
                out["otpUrl"] = otp
            for key in ("expiresAt", "allowedIps"):
                if cred.get(key):
                    out[key] = cred[key]
            creds.append(out)
        if skipped:
            self.warn(f"{address}: {skipped} app password(s) or API key(s) not migrated")
        return creds

    def account(self, account, address, used):
        kind = account.get("@type")
        out = {
            "@type": kind,
            "name": account["name"],
            "domainId": self.domain_target(account["domainId"], address, used),
        }
        for key in COPIED_FIELDS:
            if account.get(key) not in (None, {}, []):
                out[key] = account[key]

        if kind == "User":
            creds = self.credentials(account, address)
            if creds:
                out["credentials"] = as_list_map(creds)
            else:
                self.warn(f"{address}: no password credential, the account is created without one")

        roles = account.get("roles") or {}
        if roles.get("@type") == "Custom":
            fallback = "User" if kind == "User" else "Default"
            self.warn(f"{address}: custom roles not migrated, assigned the {fallback} roles")
            out["roles"] = {"@type": fallback}
        elif roles:
            out["roles"] = roles

        permissions = account.get("permissions") or {}
        if permissions.get("@type") in ("Merge", "Replace"):
            self.warn(f"{address}: account-level permissions copied, check them on the target")
            out["permissions"] = permissions

        if kind == "User":
            encryption = account.get("encryptionAtRest") or {}
            if encryption.get("@type") not in (None, "Disabled"):
                self.warn(f"{address}: encryption at rest not migrated, the public key must be added again")
            out["encryptionAtRest"] = {"@type": "Disabled"}

        if account.get("memberGroupIds"):
            self.warn(f"{address}: group memberships not migrated")
        if account.get("externalId"):
            self.warn(f"{address}: external directory identifier not migrated")
        if account.get("memberTenantId"):
            self.warn(f"{address}: tenant membership not migrated")

        aliases = []
        for alias in entries(account.get("aliases")):
            entry = {
                "name": alias["name"],
                "domainId": self.domain_target(alias["domainId"], address, used),
                "enable": alias.get("enabled", True),
            }
            if alias.get("description"):
                entry["description"] = alias["description"]
            aliases.append(entry)
        if aliases:
            out["aliases"] = as_list_map(aliases)
        return out


def plan_lines(accounts, builder):
    used = set()
    value = {}
    for address, account in accounts:
        value["acct_" + str(account["id"])] = builder.account(account, address, used)
    ops = []
    missing = sorted(d for d in used if d not in builder.existing)
    if missing:
        ops.append(
            {
                "@type": "upsert",
                "object": "Domain",
                "matchOn": ["name"],
                "value": {domain_ref(d): {"name": d} for d in missing},
            }
        )
    ops.append({"@type": "create", "object": "Account", "value": value})
    return [json.dumps(op) for op in ops]


def write_lines(path, lines):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as out:
        for line in lines:
            out.write(line + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Build Stalwart CLI plans that recreate the accounts of a Stalwart "
        "v0.16.27 server, with their password hashes, on a Stalwart v1 server.",
    )
    parser.add_argument("addresses", nargs="*", help="export only these accounts (default: all)")
    parser.add_argument("--url", required=True, help="base URL of the v0.16 server")
    parser.add_argument("--token", help="admin bearer token")
    parser.add_argument("--user", help="admin username (HTTP basic auth)")
    parser.add_argument("--password", help="admin password (default: $SOURCE_ADMIN_PASSWORD)")
    parser.add_argument("--insecure", action="store_true", help="skip TLS verification")
    parser.add_argument("--include-groups", action="store_true", help="also export groups")
    parser.add_argument(
        "--existing-domain",
        action="append",
        default=[],
        metavar="NAME=ID",
        help="reference a target domain by id instead of matching it by name",
    )
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--output", help="write one plan to this file (default: stdout)")
    target.add_argument("--output-dir", help="write one plan per account into this directory")
    args = parser.parse_args()

    if not args.token and args.user is None:
        parser.error("provide --token or --user")
    password = args.password if args.password is not None else os.environ.get("SOURCE_ADMIN_PASSWORD")

    existing = {}
    for entry in args.existing_domain:
        name, sep, value = entry.partition("=")
        if not sep:
            parser.error(f"--existing-domain expects NAME=ID, got {entry!r}")
        existing[name.strip().lower()] = value.strip()

    client = StalwartV016Client(
        args.url, token=args.token, username=args.user, password=password, insecure=args.insecure
    )
    client.connect()

    domains = {d["id"]: d["name"].lower() for d in client.get_all("Domain")}
    kinds = {"User", "Group"} if args.include_groups else {"User"}
    accounts = {}
    for account in client.get_all("Account"):
        if account.get("@type") not in kinds:
            continue
        domain = domains.get(account.get("domainId"))
        if domain:
            accounts[f"{account['name']}@{domain}".lower()] = account

    if args.addresses:
        wanted = [a.lower() for a in args.addresses]
        unknown = [a for a in wanted if a not in accounts]
        if unknown:
            sys.stderr.write("unknown account(s): " + ", ".join(unknown) + "\n")
            return 1
        selected = [(a, accounts[a]) for a in wanted]
    else:
        selected = sorted(accounts.items())

    if not selected:
        sys.stderr.write("no accounts to export\n")
        return 1

    warnings = []
    builder = PlanBuilder(domains, existing, warnings.append)

    if args.output_dir:
        os.makedirs(args.output_dir, mode=0o700, exist_ok=True)
        for address, account in selected:
            write_lines(
                os.path.join(args.output_dir, address + ".ndjson"),
                plan_lines([(address, account)], builder),
            )
    else:
        lines = plan_lines(selected, builder)
        if args.output:
            write_lines(args.output, lines)
        else:
            for line in lines:
                sys.stdout.write(line + "\n")

    for warning in warnings:
        sys.stderr.write("warning: " + warning + "\n")
    sys.stderr.write(f"exported {len(selected)} account(s)\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ApiError as exc:
        sys.stderr.write(f"error: {exc}\n")
        sys.exit(1)
