#!/bin/bash

docker-compose -f tests/pbft_client.yaml up;
docker-compose -f tests/pbft_client.yaml down
