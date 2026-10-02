FROM gcr.io/distroless/static-debian12:latest AS build

FROM scratch
# needed for version check HTTPS request
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# create the /tmp dir, which is needed for image content cache
WORKDIR /tmp

# dockers_v2 lays the binaries out per-platform in the build context (e.g. linux/arm64/grant),
# so select the right one via the buildx-provided TARGETOS/TARGETARCH args
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/grant /grant

ARG BUILD_DATE
ARG BUILD_VERSION
ARG VCS_REF
ARG VCS_URL

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.title="grant"
LABEL org.opencontainers.image.description="A license scanner for container images and filesystems"
LABEL org.opencontainers.image.source=$VCS_URL
LABEL org.opencontainers.image.revision=$VCS_REF
LABEL org.opencontainers.image.vendor="Anchore, Inc."
LABEL org.opencontainers.image.version=$BUILD_VERSION
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL io.artifacthub.package.readme-url="https://raw.githubusercontent.com/anchore/grant/main/README.md"
LABEL io.artifacthub.package.logo-url="https://github.com/anchore/grant/blob/main/.github/images/grant-logo.png"
LABEL io.artifacthub.package.license="Apache-2.0"

ENTRYPOINT ["/grant"]
