#!/usr/bin/env bash
# Description: Publish the mulval image to local
set -e

tar -zcf mulval.tar.gz ../kb ../lib ../src ../utils ../doc ../LICENSE ../Makefile
docker build -t mulval ./
wait
rm mulval.tar.gz

