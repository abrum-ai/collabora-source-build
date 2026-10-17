# Generic upstream-only source-build candidate. Publication is a separate decision.
FROM scratch AS staging-bootstrap
# Deliberately no binaries or ancestor image. This may create the package;
# it cannot establish private visibility for any later runtime by itself.
COPY LICENSE /LICENSE
COPY upstream.lock.json /build-inputs.json
LABEL org.opencontainers.image.description="License and source-build metadata only; not a runtime image" \
      org.opencontainers.image.licenses="MPL-2.0"

FROM docker.io/library/alpine:3.21@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507 AS builder
ENV UPSTREAM_COMMIT=28a3cf1a0edd6712e4079fdad8e46f5cbe6b8af8
ENV LC_CTYPE=C.UTF-8
RUN apk add --no-cache \
    build-base autoconf automake libtool pkgconf git wget ccache \
    gperf nasm libxslt flex bison zip rsync curl bash coreutils findutils tar \
    meson ninja perl python3 zstd \
    zlib-dev util-linux-dev libx11-dev libxrender-dev libxext-dev \
    libxrandr-dev libxinerama-dev fontconfig-dev freetype-dev \
    libpng-dev openssl-dev zstd-dev libcap-dev linux-pam-dev cppunit-dev \
    linux-headers py3-lxml py3-polib nodejs npm
RUN adduser -D builder && mkdir /build && chown builder:builder /build
COPY build-source.sh /usr/local/bin/build-source
COPY Dockerfile upstream.lock.json /source-recipe/
USER builder
WORKDIR /build
# Samurai is the pinned Alpine Ninja provider; GNU make flags do not constrain it.
ENV SAMUFLAGS="-j 1"
RUN sh /usr/local/bin/build-source

# Collected source evidence, not a complete offer for Alpine/base packages.
# The prepared workflow allows this only inside verified private staging.
FROM scratch AS source-evidence
COPY --from=builder /build/offer/ /

FROM docker.io/library/alpine:3.21@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507 AS runtime-base
RUN apk add --no-cache \
    libpng fontconfig cpio tzdata findutils libcap libcap-utils openssl \
    libxcb libxrender libxext libstdc++ libgcc linux-pam zstd-libs libintl \
    font-noto-cjk font-dejavu ca-certificates bash && \
    addgroup -S -g 1001 cool && \
    adduser -S -G cool -u 1001 -h /tmp/office -s /sbin/nologin cool
COPY --from=builder /build/instdir/ /
COPY --from=builder /build/offer/notices/ /usr/share/cool-source/notices/
# No setcap, setuid helper or writable /etc is needed for the nocaps candidate.
RUN setcap -r /usr/bin/coolforkit-caps 2>/dev/null || true
RUN setcap -r /usr/bin/coolmount 2>/dev/null || true
RUN chmod a-s /usr/bin/coolforkit-caps /usr/bin/coolforkit-ns /usr/bin/coolmount && \
    test -z "$(getcap /usr/bin/coolforkit-caps /usr/bin/coolforkit-ns /usr/bin/coolmount)" && \
    fc-cache /opt/collaboraoffice/share/fonts/truetype && \
    coolwsd-systemplate-setup /opt/cool/systemplate /opt/collaboraoffice && \
    apk info -v > /usr/share/cool-source/notices/runtime-apk-versions.txt && \
    apk info -a > /usr/share/cool-source/notices/runtime-apk-metadata.txt
LABEL org.opencontainers.image.source="https://github.com/CollaboraOnline/online.mirror" \
      org.opencontainers.image.revision="28a3cf1a0edd6712e4079fdad8e46f5cbe6b8af8" \
      org.opencontainers.image.description="Full source build: engine, server and browser"
ENV LC_CTYPE=C.UTF-8 DONT_GEN_SSL_CERT=1 HOME=/tmp/office \
    XDG_CACHE_HOME=/tmp/office/cache XDG_CONFIG_HOME=/tmp/office/config
USER 1001:1001
EXPOSE 9980

FROM runtime-base AS test
RUN /usr/bin/coolwsd --version && \
    test -s /usr/bin/coolwsd && test -s /usr/bin/coolforkit-ns && \
    test -s /opt/collaboraoffice/program/libmergedlo.so && \
    test -s /usr/share/coolwsd/browser/dist/cool.html && \
    test -s /usr/share/cool-source/notices/collabora-online-sbom.spdx.json && \
    test -s /usr/share/cool-source/notices/COPYING.MPL && \
    test -z "$(getcap /usr/bin/coolforkit-caps /usr/bin/coolforkit-ns /usr/bin/coolmount)"

FROM runtime-base AS runtime
ENTRYPOINT ["/usr/bin/coolwsd"]
