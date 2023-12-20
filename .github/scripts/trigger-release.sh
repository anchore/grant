#!/usr/bin/env bash
set -eu

TOOL_DIR=.tool
GH=$TOOL_DIR/gh

bold=$(tput bold)
normal=$(tput sgr0)

if ! [ -x "$(command -v $GH)" ]; then
    echo "The GitHub CLI could not be found."
    exit 1
fi

$GH auth status

# we need all of the git state to determine the next version. Since tagging is done by
# the release pipeline it is possible to not have all of the tags from previous releases.
git fetch --tags

# populates the CHANGELOG.md and VERSION files
echo "${bold}Generating changelog...${normal}"
make changelog 2> /dev/null

NEXT_VERSION=$(cat VERSION)

if [[ "$NEXT_VERSION" == "" ||  "${NEXT_VERSION}" == "(Unreleased)" ]]; then
    echo "Could not determine the next version to release. Exiting..."
    exit 1
fi

while true; do
    read -p "${bold}Do you want to trigger a release for version '${NEXT_VERSION}'?${normal} [y/n] " yn
    case $yn in
        [Yy]* ) echo; break;;
        [Nn]* ) echo; echo "Cancelling release..."; exit;;
        * ) echo "Please answer yes or no.";;
    esac
done

echo "${bold}Kicking off release for ${NEXT_VERSION}${normal}..."
echo
$GH workflow run release.yaml -f version=${NEXT_VERSION}

echo
echo "${bold}Waiting for release to start...${normal}"
sleep 10

set +e

echo "${bold}Head to the release workflow to monitor the release:${normal} $($GH run list --workflow=release.yaml --limit=1 --json url --jq '.[].url')"
id=$($GH run list --workflow=release.yaml --limit=1 --json databaseId --jq '.[].databaseId')
$GH run watch $id --exit-status || (echo ; echo "${bold}Logs of failed step:${normal}" && GH_PAGER="" $GH run view $id --log-failed)
