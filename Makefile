DOCKER_USERNAME ?= localhost
APPLICATION_NAME ?= jose-api
DOCKER_IMAGE_NAME ?= $(DOCKER_USERNAME)/$(APPLICATION_NAME)
REGISTRY ?= localhost:5000
REGISTRY_IMAGE_NAME ?= $(REGISTRY)/$(APPLICATION_NAME)

build:
# Delete the existing manifest
	podman manifest rm $(DOCKER_IMAGE_NAME) || true
# Create a manifest
	podman manifest create $(DOCKER_IMAGE_NAME)
# Build multi-arch image
	podman build --platform linux/amd64,linux/arm64 --manifest $(DOCKER_IMAGE_NAME) .
# Inspect the manifest
	podman manifest inspect $(DOCKER_IMAGE_NAME)
run:
	podman compose -f ../compose.yaml down $(APPLICATION_NAME) 
	podman compose -f ../compose.yaml up $(APPLICATION_NAME) -d
tag:
	podman tag $(DOCKER_IMAGE_NAME) $(REGISTRY_IMAGE_NAME)
push:
	podman push $(REGISTRY_IMAGE_NAME)