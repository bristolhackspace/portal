#!/bin/bash

CONTAINER_CMD=$(which podman || which docker)

$CONTAINER_CMD tag localhost/portal:latest registry.bristolhackspace.org/portal:latest

$CONTAINER_CMD push registry.bristolhackspace.org/portal:latest
