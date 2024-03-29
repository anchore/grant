#!/usr/bin/env bash
set -uxe

PKGSDIR=$1
CTRID=$(docker create -u "$(id -u):$(id -g)" -e MAVEN_CONFIG=/tmp/.m2 -v /example-java-app -w /example-java-app maven:3.8.6-openjdk-18 mvn -Duser.home=/tmp -DskipTests package)

function cleanup() {
  docker rm "${CTRID}"
}

trap cleanup EXIT
set +e

docker cp "$(pwd)/example-java-app" "${CTRID}:/"
docker start -a "${CTRID}"
mkdir -p "$PKGSDIR"
docker cp "${CTRID}:/example-java-app/target/example-java-app-maven-0.1.0.jar" "$PKGSDIR"