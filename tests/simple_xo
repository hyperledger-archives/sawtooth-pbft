#!/bin/bash

for i in $(seq 9);
do
  echo "BEGINNING ROUND $i"

  xo create game$i --url http://rest-api-1:8008
  sawtooth block list --url http://rest-api-1:8008

  xo take game$i 4 --url http://rest-api-1:8008
  xo take game$i 5 --url http://rest-api-1:8008
  sawtooth block list --url http://rest-api-1:8008

  xo take game$i 1 --url http://rest-api-2:8008
  xo take game$i 2 --url http://rest-api-2:8008
  sawtooth block list --url http://rest-api-1:8008

  xo take game$i 9 --url http://rest-api-3:8008
  xo take game$i 8 --url http://rest-api-3:8008
  sawtooth block list --url http://rest-api-1:8008

  ./tests/show_nodes
done
