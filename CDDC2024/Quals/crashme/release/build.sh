#!/bin/bash

docker rm -f crashme
docker rmi -f crashme

docker build -t crashme .
