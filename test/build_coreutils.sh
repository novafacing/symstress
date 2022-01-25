#!/bin/sh

docker build . -t symstress-coreutils-builder
docker run -d --name symstress-coreutils-builder-run symstress-coreutils-builder
docker cp symstress-coreutils-builder-run:/build/bin/coreutils ./binaries/
docker stop symstress-coreutils-builder-run