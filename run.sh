#!/bin/bash
IMAGE_NAME="riskeye"
if [[ "$(docker images -q $IMAGE_NAME 2> /dev/null)" == "" ]]; then
  echo "Docker image not found. Building..."
  docker build -t $IMAGE_NAME .
fi
docker run -p 5000:5000 $IMAGE_NAME
