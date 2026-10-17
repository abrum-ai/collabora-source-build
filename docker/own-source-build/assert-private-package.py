#!/usr/bin/env python3
"""Validate fresh authenticated GHCR metadata before an internal staging push.

This is an access boundary, not a license/source-completeness approval.
The workflow fetches metadata through the authenticated GitHub GET endpoint.
Only 404 returns code 3 for a license/metadata-only seed; it never admits a
runtime. Other errors and unverified privacy fail without a bootstrap fallback.
"""
import argparse
import json
import os
import re
import urllib.error
import urllib.request


class PackageUnobserved(Exception):
    """404 permits only a license/metadata seed, never a runtime push."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_package(repository, owner_type, token, opener=None):
    if (not isinstance(repository, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository)
            or any(part in ['.', '..'] for part in repository.split('/'))):
        raise ValueError('Explicit repository required.')
    if owner_type not in ['Organization', 'User'] or not token:
        raise ValueError('Actual owner type and scoped action credential required.')
    owner, name = repository.lower().split('/')
    collection = 'orgs' if owner_type == 'Organization' else 'users'
    req = urllib.request.Request('https://api.github.com/'+collection+'/'+owner+'/packages/container/'+name,
        headers={'Authorization':'Bearer '+token, 'Accept':'application/vnd.github+json',
                 'X-GitHub-Api-Version':'2026-03-10'})
    if opener is None:
        opener = urllib.request.build_opener(NoRedirect()).open
    try:
        with opener(req, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise PackageUnobserved() from None
        raise


def validate(metadata, repository, expected_id=None):
    if (not isinstance(repository, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository)
            or any(part in ['.', '..'] for part in repository.split('/'))):
        raise ValueError('Expected an explicit GitHub owner/repository.')
    owner, name = repository.lower().split('/')
    if not isinstance(metadata, dict):
        raise ValueError('Package metadata must be an object.')
    ident = metadata.get('id')
    if type(ident) is not int or ident <= 0:
        raise ValueError('Existing package identity is required.')
    if metadata.get('visibility') != 'private' or metadata.get('package_type') != 'container':
        raise ValueError('Only a private container package permits internal staging.')
    actual_owner = metadata.get('owner')
    linked = metadata.get('repository')
    if (not isinstance(actual_owner, dict) or not isinstance(linked, dict)
            or not isinstance(actual_owner.get('login'), str)
            or not isinstance(metadata.get('name'), str)
            or not isinstance(linked.get('full_name'), str)
            or actual_owner['login'].lower() != owner
            or metadata['name'].lower() != name
            or linked['full_name'].lower() != repository.lower()):
        raise ValueError('Package owner, name and linked repository must match the build repository.')
    if expected_id is not None and ident != expected_id:
        raise ValueError('Original private package identity changed.')
    return {'id':ident, 'visibility':'private', 'repository':repository.lower()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', required=True)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--metadata-file')
    inputs.add_argument('--fetch', action='store_true')
    parser.add_argument('--owner-type', choices=['Organization', 'User'])
    parser.add_argument('--expected-id', type=int)
    args = parser.parse_args()
    try:
        if args.fetch:
            metadata = read_package(args.repository, args.owner_type, os.environ.get('GH_TOKEN'))
        else:
            with open(args.metadata_file, encoding='utf-8') as stream:
                metadata = json.load(stream)
        result = validate(metadata, args.repository, args.expected_id)
    except PackageUnobserved:
        raise SystemExit(3)
    except (ValueError, OSError):
        raise SystemExit('PRIVATE_STAGING_REQUIRED: package access is not verified private; no runtime push is permitted.')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
