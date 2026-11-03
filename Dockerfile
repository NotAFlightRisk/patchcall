FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS TARGETARCH TARGETVARIANT VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -tags timetzdata -ldflags "-s -w -X main.version=$VERSION" -o /patchcall . \
    && mkdir /data

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build --chown=65534:65534 /data /data
COPY --from=build /patchcall /patchcall
USER 65534:65534
ENV PATCHCALL_HOST=0.0.0.0 PATCHCALL_DATA=/data
VOLUME /data
EXPOSE 7282
HEALTHCHECK --interval=30s --timeout=5s CMD ["/patchcall", "--healthcheck"]
ENTRYPOINT ["/patchcall"]
