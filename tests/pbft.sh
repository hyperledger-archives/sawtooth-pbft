#!/bin/bash

source .env;

if [ $# -ge 1 ]
then
  DOCKER_TEST=tests/$1.yaml
  A=("$@")
  DOCKER_ARGS="${A[@]:1}"
else
  DOCKER_TEST=tests/test_liveness.yaml
  DOCKER_ARGS="--abort-on-container-exit --exit-code-from test-pbft-engine"
fi

docker-compose -f $DOCKER_TEST up $DOCKER_ARGS
docker-compose -f $DOCKER_TEST down
