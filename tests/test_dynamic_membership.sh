#!/bin/bash
#
# Copyright 2018 Intel Corporation
# Copyright 2018 Cargill Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

### This script tests dynamic membership by starting a PBFT network with 4
### nodes, adding a 5th node, applying a workload, checking that all 5 nodes
### reach block 10, adding a 6th node, checking that all 6 nodes reach block 20,
### removing a node, and checking that all remaining nodes reach block 30.

if [ -z "$ISOLATION_ID" ]; then export ISOLATION_ID=latest; fi

set -eux

# Clean up docker on exit, even if it failed
function cleanup {
    echo "Done testing"
    echo "Dumping logs"
    echo "-- Workload --"
    docker-compose -p ${ISOLATION_ID} -f adhoc/workload.yaml logs
    echo "-- Alpha --"
    docker-compose -p ${ISOLATION_ID}-alpha -f adhoc/node.yaml logs
    echo "-- Beta --"
    docker-compose -p ${ISOLATION_ID}-beta -f adhoc/node.yaml logs
    echo "-- Gamma --"
    docker-compose -p ${ISOLATION_ID}-gamma -f adhoc/node.yaml logs
    echo "-- Delta --"
    docker-compose -p ${ISOLATION_ID}-delta -f adhoc/node.yaml logs
    echo "-- Epsilon --"
    docker-compose -p ${ISOLATION_ID}-epsilon -f adhoc/node.yaml logs
    echo "-- Zeta --"
    docker-compose -p ${ISOLATION_ID}-zeta -f adhoc/node.yaml logs
    echo "-- Admin --"
    docker-compose -p ${ISOLATION_ID} -f adhoc/admin.yaml logs
    echo "Shutting down all containers"
    docker-compose -p ${ISOLATION_ID} -f adhoc/workload.yaml down --remove-orphans --volumes
    docker-compose -p ${ISOLATION_ID}-alpha -f adhoc/node.yaml down --remove-orphans --volumes
    docker-compose -p ${ISOLATION_ID}-beta -f adhoc/node.yaml down --remove-orphans --volumes
    docker-compose -p ${ISOLATION_ID}-gamma -f adhoc/node.yaml down --remove-orphans --volumes
    docker-compose -p ${ISOLATION_ID}-delta -f adhoc/node.yaml down --remove-orphans --volumes
    docker-compose -p ${ISOLATION_ID}-epsilon -f adhoc/node.yaml down --remove-orphans --volumes
    docker-compose -p ${ISOLATION_ID}-zeta -f adhoc/node.yaml down --remove-orphans --volumes
    docker-compose -p ${ISOLATION_ID} -f adhoc/admin.yaml down --remove-orphans --volumes
}

trap cleanup EXIT SIGTERM

echo "Ensuring sawtooth services are built"
docker-compose -p ${ISOLATION_ID} -f tests/sawtooth-services.yaml build

echo "Building PBFT engine"
# Try to create these if they don't exist
docker network create pbft_validators_${ISOLATION_ID} || true
docker network create pbft_rest_apis_${ISOLATION_ID} || true
docker volume create --name=pbft_shared_data_${ISOLATION_ID} || true
if [ ! -f ./target/debug/pbft-engine ]; then
  docker-compose -f adhoc/node.yaml run --rm pbft cargo build
fi

echo "Starting initial network"
docker-compose -p ${ISOLATION_ID} -f adhoc/admin.yaml up -d
docker-compose -p ${ISOLATION_ID}-alpha -f adhoc/node.yaml up -d
docker-compose -p ${ISOLATION_ID}-beta -f adhoc/node.yaml up -d
docker-compose -p ${ISOLATION_ID}-gamma -f adhoc/node.yaml up -d
GENESIS=1 docker-compose -p ${ISOLATION_ID}-delta -f adhoc/node.yaml up -d

ADMIN=${ISOLATION_ID}_admin_1

echo "Gathering list of initial keys and REST APIs"
INIT_KEYS=($(docker exec $ADMIN bash -c '\
  cd /shared_data/validators && paste $(ls -1) -d , | sed s/,/\ /g'))
echo "Initial keys:" ${INIT_KEYS[*]}
INIT_APIS=($(docker exec $ADMIN bash -c 'cd /shared_data/rest_apis && ls -d *'))
echo "Initial APIs:" ${INIT_APIS[*]}

echo "Waiting until network has started"
docker exec -e API=${INIT_APIS[0]} $ADMIN bash -c 'while true; do \
  BLOCK_LIST=$(sawtooth block list --url "http://$API:8008" 2>&1); \
  if [[ $BLOCK_LIST == *"BLOCK_ID"* ]]; then \
    echo "Network ready" && break; \
  else \
    echo "Still waiting..." && sleep 0.5; \
  fi; done;'

echo "Starting new node"
docker-compose -p ${ISOLATION_ID}-epsilon -f adhoc/node.yaml up -d

echo "Waiting until new node is ready"
docker exec $ADMIN bash -c 'while true; do \
  KEYS=($(cd /shared_data/validators && paste $(ls -1) -d \ )); \
  if [[ "${#KEYS[@]}" -eq 5 ]]; then \
    echo "New node ready" && break; \
  else \
    echo "Still waiting..." && sleep 0.5; \
  fi; done;'

echo "Adding new node to PBFT network"
docker exec -e API=${INIT_APIS[0]} $ADMIN bash -c '\
  NEW_PEERS=$(cd /shared_data/validators && paste $(ls -1) -d , \
    | sed s/,/\\\",\\\"/g); \
  SETTING_PEERS=($(sawtooth settings list --url "http://$API:8008" \
    --filter "sawtooth.consensus.pbft.members" --format csv | sed -n 2p | \
    sed "s/\"\",\"\"/\ /g")); \
  until [[ "${#SETTING_PEERS[@]}" -eq 5 ]]; do \
    echo "Attempting to set sawtooth.consensus.pbft.members..."; \
    # Try to update setting \
    sawset proposal create -k /shared_data/keys/settings.priv \
      --url "http://$API:8008" sawtooth.consensus.pbft.members=[\"$NEW_PEERS\"]; \
    # Wait and see if setting has been updated \
    sleep 5; \
    SETTING_PEERS=($(sawtooth settings list --url "http://$API:8008" \
      --filter "sawtooth.consensus.pbft.members" --format csv | sed -n 2p | \
      sed "s/\"\",\"\"/\ /g")); \
  done;'

NEW_KEYS=($(docker exec $ADMIN bash -c '\
  cd /shared_data/validators && paste $(ls -1) -d , | sed s/,/\ /g'))
NEW_APIS=($(docker exec $ADMIN bash -c 'cd /shared_data/rest_apis && ls -d *'))
NEW_KEY=($(comm -3 <(printf '%s\n' "${INIT_KEYS[@]}" | LC_ALL=C sort) \
  <(printf '%s\n' "${NEW_KEYS[@]}" | LC_ALL=C sort)))
NEW_API=($(comm -3 <(printf '%s\n' "${INIT_APIS[@]}" | LC_ALL=C sort) \
  <(printf '%s\n' "${NEW_APIS[@]}" | LC_ALL=C sort)))
echo "New keys:" ${NEW_KEYS[*]}
echo "New APIs:" ${NEW_APIS[*]}
echo "New node key:" $NEW_KEY
echo "New node API:" $NEW_API

echo "Waiting for new node to receive block"
docker exec -e API=$NEW_API $ADMIN bash -c 'while true; do \
  BLOCK_LIST=$(sawtooth block list --url "http://$API:8008" 2>&1); \
  if [[ $BLOCK_LIST == *"BLOCK_ID"* ]]; then \
    echo "New node has received block" && break; \
  else \
    echo "Still waiting..." && sleep 0.5; \
  fi; done;'

echo "Starting workload"
RATE=1 docker-compose -p ${ISOLATION_ID} -f adhoc/workload.yaml up -d

echo "Waiting for all nodes to reach block 10"
docker exec $ADMIN bash -c '\
  APIS=$(cd /shared_data/rest_apis && ls -d *); \
  NODES_ON_10=0; \
  until [ "$NODES_ON_10" -eq 5 ]; do \
    NODES_ON_10=0; \
    sleep 5; \
    for api in $APIS; do \
      BLOCK_LIST=$(sawtooth block list --url "http://$api:8008" \
        | cut -f 1 -d " "); \
      echo $api && echo $BLOCK_LIST;
      if [[ $BLOCK_LIST == *"10"* ]]; then \
        echo "API $api is on block 10" && ((NODES_ON_10++)); \
      else \
        echo "API $api is not yet on block 10"; \
      fi; \
    done; \
  done;'
echo "All nodes have reached block 10!"

echo "Starting 6th node"
docker-compose -p ${ISOLATION_ID}-zeta -f adhoc/node.yaml up -d

echo "Waiting until 6th node is ready"
docker exec $ADMIN bash -c 'while true; do \
  KEYS=($(cd /shared_data/validators && paste $(ls -1) -d \ )); \
  if [[ "${#KEYS[@]}" -eq 6 ]]; then \
    echo "New node ready" && break; \
  else \
    echo "Still waiting..." && sleep 0.5; \
  fi; done;'

echo "Adding 6th node to PBFT network"
docker exec -e API=${INIT_APIS[0]} $ADMIN bash -c '\
  NEW_PEERS=$(cd /shared_data/validators && paste $(ls -1) -d , \
    | sed s/,/\\\",\\\"/g); \
  SETTING_PEERS=($(sawtooth settings list --url "http://$API:8008" \
    --filter "sawtooth.consensus.pbft.members" --format csv | sed -n 2p | \
    sed "s/\"\",\"\"/\ /g")); \
  until [[ "${#SETTING_PEERS[@]}" -eq 6 ]]; do \
    echo "Attempting to set sawtooth.consensus.pbft.members..."; \
    # Try to update setting \
    sawset proposal create -k /shared_data/keys/settings.priv \
      --url "http://$API:8008" sawtooth.consensus.pbft.members=[\"$NEW_PEERS\"]; \
    # Wait and see if setting has been updated \
    sleep 5; \
    SETTING_PEERS=($(sawtooth settings list --url "http://$API:8008" \
      --filter "sawtooth.consensus.pbft.members" --format csv | sed -n 2p | \
      sed "s/\"\",\"\"/\ /g")); \
  done;'

NEWER_KEYS=($(docker exec $ADMIN bash -c '\
  cd /shared_data/validators && paste $(ls -1) -d , | sed s/,/\ /g'))
NEWER_APIS=($(docker exec $ADMIN bash -c 'cd /shared_data/rest_apis && ls -d *'))
NEWER_KEY=($(comm -3 <(printf '%s\n' "${NEW_KEYS[@]}" | LC_ALL=C sort) \
  <(printf '%s\n' "${NEWER_KEYS[@]}" | LC_ALL=C sort)))
NEWER_API=($(comm -3 <(printf '%s\n' "${NEW_APIS[@]}" | LC_ALL=C sort) \
  <(printf '%s\n' "${NEWER_APIS[@]}" | LC_ALL=C sort)))
echo "New keys:" ${NEWER_KEYS[*]}
echo "New APIs:" ${NEWER_APIS[*]}
echo "New node key:" $NEWER_KEY
echo "New node API:" $NEWER_API

echo "Waiting for all nodes to reach block 20"
docker exec $ADMIN bash -c '\
  APIS=$(cd /shared_data/rest_apis && ls -d *); \
  NODES_ON_20=0; \
  until [ "$NODES_ON_20" -eq 6 ]; do \
    NODES_ON_20=0; \
    sleep 5; \
    for api in $APIS; do \
      BLOCK_LIST=$(sawtooth block list --url "http://$api:8008" \
        | cut -f 1 -d " "); \
      echo $api && echo $BLOCK_LIST;
      if [[ $BLOCK_LIST == *"20"* ]]; then \
        echo "API $api is on block 20" && ((NODES_ON_20++)); \
      else \
        echo "API $api is not yet on block 20"; \
      fi; \
    done; \
  done;'
echo "All nodes have reached block 20!"

echo "Removing a node from the network"
docker exec -e API=${INIT_APIS[0]} $ADMIN bash -c '\
  NEW_PEERS=$(cd /shared_data/validators && paste $(ls -1 | head -5) -d , \
    | sed s/,/\\\",\\\"/g); \
  SETTING_PEERS=($(sawtooth settings list --url "http://$API:8008" \
    --filter "sawtooth.consensus.pbft.members" --format csv | sed -n 2p | \
    sed "s/\"\",\"\"/\ /g")); \
  until [[ "${#SETTING_PEERS[@]}" -eq 6 ]]; do \
    echo "Attempting to set sawtooth.consensus.pbft.members..."; \
    # Try to update setting \
    sawset proposal create -k /shared_data/keys/settings.priv \
      --url "http://$API:8008" sawtooth.consensus.pbft.members=[\"$NEW_PEERS\"]; \
    # Wait and see if setting has been updated \
    sleep 5; \
    SETTING_PEERS=($(sawtooth settings list --url "http://$API:8008" \
      --filter "sawtooth.consensus.pbft.members" --format csv | sed -n 2p | \
      sed "s/\"\",\"\"/\ /g")); \
  done;'

echo "Waiting for all remaining nodes to reach block 30"
docker exec $ADMIN bash -c '\
  APIS=$(cd /shared_data/rest_apis && ls -d *); \
  NODES_ON_30=0; \
  until [ "$NODES_ON_30" -ge 5 ]; do \
    NODES_ON_30=0; \
    sleep 5; \
    for api in $APIS; do \
      BLOCK_LIST=$(sawtooth block list --url "http://$api:8008" \
        | cut -f 1 -d " "); \
      echo $api && echo $BLOCK_LIST;
      if [[ $BLOCK_LIST == *"30"* ]]; then \
        echo "API $api is on block 30" && ((NODES_ON_30++)); \
      else \
        echo "API $api is not yet on block 30"; \
      fi; \
    done; \
  done;'
echo "All nodes have reached block 30!"
