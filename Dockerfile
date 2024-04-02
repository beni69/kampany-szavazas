FROM docker.io/rust:1-alpine as builder

ARG APP_NAME="kampany_szavazas"

WORKDIR /src

RUN apk add --no-cache build-base mold && cargo init --bin
COPY ./Cargo.* ./
COPY ./.cargo ./.cargo
RUN cargo build --release && rm -rf src

COPY ./src ./src
COPY ./templates ./templates
RUN rm ./target/release/deps/${APP_NAME}* \
    && cargo build --release

FROM busybox:1-musl as tailwind
WORKDIR /src
COPY ./tw.sh ./tailwind.css ./tailwind.config.js .
COPY ./templates ./templates
COPY ./static ./static
RUN ./tw.sh --minify

FROM busybox:1-musl as final
ARG APP_NAME="kampany_szavazas"
WORKDIR /app
COPY --from=builder /src/target/release/${APP_NAME} ./bin
COPY --from=tailwind /src/static ./static
CMD [ "/app/bin" ]
