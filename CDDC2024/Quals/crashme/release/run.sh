#!/bin/bash

docker rm -f crashme
docker run -d -p 19754:19754 --name crashme --restart unless-stopped --privileged crashme