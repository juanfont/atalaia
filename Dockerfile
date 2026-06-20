# syntax=docker/dockerfile:1.6
#
# Atalaia container — atalaia + pinned trufflehog + pinned kingfisher.
#
# The atalaia binary itself is built outside (goreleaser supplies it
# via the build context). The trufflehog and kingfisher binaries are
# downloaded from upstream releases at the versions pinned below.
#
# License note: trufflehog is AGPL-3.0. It is bundled here purely as
# a subprocess executable — atalaia never links against it. This is
# mere aggregation under GPL/AGPL terminology, so the image as a
# whole remains distributable under BSD-3-Clause (atalaia) + AGPL-3.0
# (trufflehog). See upstream sources for trufflehog at
# https://github.com/trufflesecurity/trufflehog.

ARG TRUFFLEHOG_VERSION=3.90.1
ARG KINGFISHER_VERSION=1.27.0

# ---- detector downloader (multi-arch via TARGETARCH) ----
FROM alpine:3.20 AS detectors
ARG TRUFFLEHOG_VERSION
ARG KINGFISHER_VERSION
ARG TARGETARCH
RUN apk add --no-cache curl tar

RUN set -eu; \
    case "${TARGETARCH}" in \
        amd64) TH_ARCH=linux_amd64; KF_ARCH=linux-x64 ;; \
        arm64) TH_ARCH=linux_arm64; KF_ARCH=linux-arm64 ;; \
        *) echo "unsupported TARGETARCH: ${TARGETARCH}"; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/th.tgz \
      "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_${TH_ARCH}.tar.gz"; \
    tar -xzf /tmp/th.tgz -C /tmp trufflehog; \
    mv /tmp/trufflehog /trufflehog; \
    chmod 0755 /trufflehog; \
    curl -fsSL -o /tmp/kf.tgz \
      "https://github.com/mongodb/kingfisher/releases/download/v${KINGFISHER_VERSION}/kingfisher-${KF_ARCH}.tgz"; \
    tar -xzf /tmp/kf.tgz -C /tmp kingfisher; \
    mv /tmp/kingfisher /kingfisher; \
    chmod 0755 /kingfisher

# ---- final image ----
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=detectors --chown=nonroot:nonroot /trufflehog /usr/local/bin/trufflehog
COPY --from=detectors --chown=nonroot:nonroot /kingfisher /usr/local/bin/kingfisher

# atalaia binary is supplied by the build context (goreleaser).
COPY --chown=nonroot:nonroot atalaia /usr/local/bin/atalaia

COPY --chown=nonroot:nonroot prompts /etc/atalaia/prompts
COPY --chown=nonroot:nonroot gitleaks-aggressive.toml /etc/atalaia/gitleaks-aggressive.toml
COPY --chown=nonroot:nonroot LICENSE /usr/share/doc/atalaia/LICENSE
COPY --chown=nonroot:nonroot README.md /usr/share/doc/atalaia/README.md

USER nonroot
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/atalaia"]
CMD ["serve"]
