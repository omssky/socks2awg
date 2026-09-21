FROM golang:1.26 AS build
# Pinned upstream source; the SOCKS/AWG implementation is not forked here.
ARG WIREPROXY_REF=84f4795ea76f9c3168a61e478d0fe0e5c3238308
WORKDIR /src
RUN git init . && git remote add origin https://github.com/artem-russkikh/wireproxy-awg.git \
    && git fetch --depth 1 origin "$WIREPROXY_REF" && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "$WIREPROXY_REF"
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=socks2awg-${WIREPROXY_REF}" \
    -o /wireproxy ./cmd/wireproxy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /wireproxy /usr/bin/wireproxy
COPY --from=build /src/LICENSE /usr/share/licenses/wireproxy-awg/LICENSE
ENTRYPOINT ["/usr/bin/wireproxy"]
