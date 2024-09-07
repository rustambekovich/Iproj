# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0-alpine AS build
WORKDIR /src

# Copy and restore nuqtaviy fayllar (csproj)
COPY ./src/Iproj.Web/Iproj.Web.csproj ./Iproj.Web/
RUN dotnet restore ./Iproj.Web/Iproj.Web.csproj

# Copy rest of the source files
COPY ./src ./

WORKDIR /src/Iproj.Web
RUN dotnet publish -c Release -o output

# Serve stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine AS serve
WORKDIR /app
COPY --from=build /src/Iproj.Web/output .

EXPOSE 5000
ENTRYPOINT [ "dotnet", "Iproj.Web.dll" ]
