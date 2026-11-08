# syntax=docker/dockerfile:1
# Nullify.WebDav server image. Build from the repository root:
#   docker build -t nullify-webdav .
# CI gate: `docker build --target test .` runs the test suite inside the SDK image.

ARG DOTNET_VERSION=10.0

FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION} AS build
ARG VERSION=0.0.0
WORKDIR /src
COPY Nullify.WebDav.slnx ./
COPY src/Nullify.WebDav/Nullify.WebDav.csproj src/Nullify.WebDav/
COPY src/Nullify.WebDav.Client/Nullify.WebDav.Client.csproj src/Nullify.WebDav.Client/
COPY src/Nullify.WebDav.Shared/Nullify.WebDav.Shared.csproj src/Nullify.WebDav.Shared/
COPY tests/Nullify.WebDav.Tests/Nullify.WebDav.Tests.csproj tests/Nullify.WebDav.Tests/
RUN dotnet restore Nullify.WebDav.slnx
COPY src/ src/
RUN dotnet publish src/Nullify.WebDav/Nullify.WebDav.csproj -c Release --no-restore -o /app \
      -p:UseAppHost=false -p:Version="$VERSION"

FROM build AS test
COPY tests/ tests/
RUN dotnet test tests/Nullify.WebDav.Tests -c Release --no-restore --logger "console;verbosity=normal"

FROM mcr.microsoft.com/dotnet/aspnet:${DOTNET_VERSION} AS final
LABEL org.opencontainers.image.title="Nullify.WebDav" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.authors="Simon Soanes"
WORKDIR /app
ENV ASPNETCORE_HTTP_PORTS=8080 \
    Storage__DataDirectory=/data \
    Storage__FilesDirectory=/files \
    DOTNET_NOLOGO=true
# /data holds the configuration file and the key ring that protects sign-in cookies; /files is the default storage.
RUN mkdir -p /data /files && chown "$APP_UID":"$APP_UID" /data /files
COPY --from=build /app .
USER $APP_UID
VOLUME ["/data", "/files"]
EXPOSE 8080
ENTRYPOINT ["dotnet", "Nullify.WebDav.dll"]
