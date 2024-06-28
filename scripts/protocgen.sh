#!/usr/bin/env bash
set -x
set -eo pipefail

echo "Generating gogo proto code"
cd proto

buf generate --template buf.gen.gogo.yaml $file

cd ..

# move proto files to the right places
cp -r github.com/datachainlab/ibc-hd-signer/* ./
rm -rf github.com

echo 'run "go mod tidy"'

