# Fulgens Web Server
A simple and fast plugin-based web server written in Golang.

[![Go Report Card](https://goreportcard.com/badge/git.ailur.dev/ailur/fulgens)](https://goreportcard.com/report/git.ailur.dev/ailur/fulgens) [![Go Reference](https://pkg.go.dev/badge/git.ailur.dev/ailur/fulgens.svg)](https://pkg.go.dev/git.ailur.dev/ailur/fulgens) [![wakatime](https://wakatime.com/badge/user/754e87c4-b184-4291-9f4e-0392f3c2126c/project/1f4885c6-3a1b-4f0d-b72b-5659c94ea2ad.svg)](https://wakatime.com/badge/user/754e87c4-b184-4291-9f4e-0392f3c2126c/project/1f4885c6-3a1b-4f0d-b72b-5659c94ea2ad)

It utilises Chi and the Go standard library to provide a fast and efficient web server, with the ability to add plugins to extend its functionality.

## Features
- Fast and efficient
- Plugin-based
- Easy to use
- Comes with OAuth2 and Blob storage (known as the "nucleus" services)
- SQLite and PostgreSQL support
- Easy to extend

## Installation
To install, git clone the repository:
```sh
git clone https://git.ailur.dev/Ailur/fulgens.git --depth 1
```

Then, build the server:
```sh
./build.sh
```

After that, configure the server using the `config.json` file (see below), and you're ready to go!

## Usage
To run the server, simply run the binary:
```sh
./fulgens
```

## Configuration
The server can be configured using a `config.conf` file. You can see the config format in [config.conf.example](https://git.ailur.dev/Ailur/fulgens/src/branch/master/config.conf.example).

## Contributing
Contributions are welcome! Please open a pull request with your changes.

## Plugin development
Plugins require the use of the `library` package, found [here](https://pkg.go.dev/git.ailur.dev/Ailur/fulgens/library).
This provides them with the necessary resources to interact with the rest of the server

## Enterprise support
For enterprise support, please visit [Ailur Enterprise](https://ailur.dev/enterprise).
