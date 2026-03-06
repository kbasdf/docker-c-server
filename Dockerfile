# Stage 1: Build the C program
FROM mcr.microsoft.com/windows/servercore:ltsc2022 AS build

# Install MinGW (or copy your compiler into the image)
# For simplicity, assume you already have mingw-w64 installer or zip
COPY ./mingw64/ /mingw64
ENV PATH="C:\\mingw64\\bin;${PATH}"

WORKDIR /src
COPY auth1.c .

# Compile the C file into an .exe
RUN gcc auth1.c -o auth1 -I/mingw64/include -L/mingw64/lib -lmicrohttpd -ljansson -lcurl -lpthread

# Stage 2: Runtime image
FROM mcr.microsoft.com/windows/servercore:ltsc2022

WORKDIR /app
COPY --from=build /src/auth1.exe .

# Run the compiled program
ENTRYPOINT ["C:\\app\\auth1.exe"]

