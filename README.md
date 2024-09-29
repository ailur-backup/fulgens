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

## Usage
To run the server, simply run the binary:
```sh
./fulgens
```

## Configuration
The server can be configured using a `config.json` file. An example configuration file is provided in the repository.
### Global
- `port` - The port the server listens on
- `ip` - The IP address the server listens on
- `serviceDirectory` - The directory where services are stored
- `resourceDirectory` - The directory where service resources are stored
### Logging
- `enabled` - Whether file logging is enabled
- `file` - The file to log to
### Database
- `type` - The type of database to use (sqlite or postgres)
- `connectionString` - The connection string for the database (postgres only)
- `databasePath` - The **directory** to store the databases (sqlite only)
It is necessary to have a separate directory for each service, as SQLite does not support multiple schemas in a single file.
### Services
#### For all services
- `subdomain` - The subdomain the service is hosted on (optional, will run on the root domain if not specified)
#### Storage
**Note** the storage service is unfinished and should not be used in production.
- `path` - The path to store blobs
- `defaultQuota` - The maximum size of the storage in bytes
#### Auth
- `privacyPolicy` - The URL to the privacy policy
- `url` - The URL it is being hosted on
- `testAppEnabled` - Whether to enable the OAuth2 test app
- `testAppIsInteralApp` - Whether the test app should have seamless logon like an internal service (required if `testAppEnabled` is true)
- `identifier` - The name of the OAuth2 service
- `adminKey` - The key used to access the admin panel and list users

## Contributing
Contributions are welcome! Please open a pull request with your changes.

## Plugin development
Plugins require the use of the `library` package, found [here](https://pkg.go.dev/git.ailur.dev/Ailur/fulgens/library).
This provides them with the necessary resources to interact with the rest of the server

## Enterprise support
For enterprise support, please visit [Ailur Enterprise](https://ailur.dev/enterprise).