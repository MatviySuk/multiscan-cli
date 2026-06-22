#!/usr/bin/env bash
# Pull a fresh copy of OWASP Juice Shop v15.0.0 into ./juice-shop.
# Used as the evaluation target — the ground truth in evaluation/ground_truth.json
# is pinned to this exact release.
set -e

VERSION="v15.0.0"
DEST="juice-shop"

if [ -d "$DEST" ]; then
    echo "$DEST already exists. Remove it first if you want a fresh checkout."
    exit 0
fi

git clone --depth 1 --branch "$VERSION" https://github.com/juice-shop/juice-shop.git "$DEST"
echo "Juice Shop $VERSION cloned to ./$DEST"
