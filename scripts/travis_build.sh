#!/bin/sh

# Make sure the script fails fast.
set -e
set -u

# Make a list of all non-vendored packages.
PKGS=$(go list ./... | grep -v /vendor/ | grep -v /tools/ | grep -v /testhelpers/)

echo "Check that the code meets quality standards"
go fmt $PKGS
go vet $PKGS

echo "Run tests for all packages"
for P in $PKGS; do
    go test -v -p 1 -timeout=120s $P -check.vv;
done
