#!/usr/bin/env python3
"""
Standalone script to update GitHub repository secrets.

This script is used by the Neko-Collector.yml workflow to automatically
update the QWEN_TOKENS secret with encrypted tokens.

Usage:
    python update_secret.py <token> <owner> <repo> <secret_name> <secret_value>
"""

import base64
import sys

import requests
from nacl import encoding, public


def encrypt_secret(public_key: str, secret_value: str) -> str:
    """Encrypt a secret using the repository's public key."""
    public_key_obj = public.PublicKey(
        public_key.encode("utf-8"), encoding.Base64Encoder()
    )
    sealed_box = public.SealedBox(public_key_obj)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return base64.b64encode(encrypted).decode("utf-8")


def get_public_key(token: str, owner: str, repo: str) -> dict:
    """Get repository public key for secret encryption."""
    url = f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/public-key"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }

    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    return response.json()


def update_secret(
    token: str, owner: str, repo: str, secret_name: str, secret_value: str
) -> None:
    """Update a GitHub repository secret."""
    # Get public key
    public_key_data = get_public_key(token, owner, repo)
    public_key = public_key_data["key"]
    key_id = public_key_data["key_id"]

    # Encrypt secret
    encrypted_value = encrypt_secret(public_key, secret_value)

    # Update secret
    url = f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/{secret_name}"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    data = {
        "encrypted_value": encrypted_value,
        "key_id": key_id,
    }

    response = requests.put(url, headers=headers, json=data, timeout=30)
    response.raise_for_status()
    print(f"✅ Successfully updated secret '{secret_name}'")


def main() -> None:
    """Main function."""
    if len(sys.argv) < 6:
        print("Usage: update_secret.py <token> <owner> <repo> <secret_name> <secret_value>")
        print("")
        print("Arguments:")
        print("  token        - GitHub Personal Access Token with repo scope")
        print("  owner        - Repository owner (username or organization)")
        print("  repo         - Repository name")
        print("  secret_name  - Name of the secret to create/update")
        print("  secret_value - Value of the secret")
        sys.exit(1)

    token = sys.argv[1]
    owner = sys.argv[2]
    repo = sys.argv[3]
    secret_name = sys.argv[4]
    secret_value = sys.argv[5]

    try:
        update_secret(token, owner, repo, secret_name, secret_value)
    except requests.exceptions.HTTPError as e:
        print(f"❌ HTTP Error: {e}")
        print(f"   Response: {e.response.text if e.response else 'No response'}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error updating secret: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
