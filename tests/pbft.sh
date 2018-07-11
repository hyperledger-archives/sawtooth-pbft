#!/bin/bash

source .env;

DOCKER_TEST=tests/test_liveness.yaml

docker-compose -f $DOCKER_TEST up --abort-on-container-exit --exit-code-from test-pbft-engine
docker-compose -f $DOCKER_TEST down
