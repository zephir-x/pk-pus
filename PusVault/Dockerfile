# Stage 1: Build and publish both Server and Client using .NET 8 SDK
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy project files first to leverage Docker layer caching during restore
COPY src/Pus.Vault.Common/Pus.Vault.Common.csproj src/Pus.Vault.Common/
COPY src/Pus.Vault.Server/Pus.Vault.Server.csproj src/Pus.Vault.Server/
COPY src/Pus.Vault.Client/Pus.Vault.Client.csproj src/Pus.Vault.Client/

RUN dotnet restore src/Pus.Vault.Server/Pus.Vault.Server.csproj
RUN dotnet restore src/Pus.Vault.Client/Pus.Vault.Client.csproj

# Copy source code and publish Release binaries
COPY src/ src/

RUN dotnet publish src/Pus.Vault.Server/Pus.Vault.Server.csproj -c Release -o /out/server --no-restore
RUN dotnet publish src/Pus.Vault.Client/Pus.Vault.Client.csproj -c Release -o /out/client --no-restore

# Stage 2: Minimal runtime image for PUS-Vault Server
FROM mcr.microsoft.com/dotnet/runtime:8.0 AS server
WORKDIR /app

COPY --from=build /out/server ./

# Pre-create mount points for runtime volumes
RUN mkdir -p /app/certs /app/config /app/data /app/logs

EXPOSE 8443
ENTRYPOINT ["dotnet", "Pus.Vault.Server.dll"]

# Stage 3: Minimal runtime image for PUS-Vault CLI Client
FROM mcr.microsoft.com/dotnet/runtime:8.0 AS client
WORKDIR /app

COPY --from=build /out/client ./

RUN mkdir -p /app/certs

ENTRYPOINT ["dotnet", "Pus.Vault.Client.dll"]