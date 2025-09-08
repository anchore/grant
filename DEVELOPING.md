# Developing

## Getting started

In order to test and develop in this repo you will need the following dependencies installed:
- Golang
- Docker
- make

After cloning the following step can help you get setup:
1. run `make tools` to download tools, create the `/.tmp` dir, and download helper utilities.
2. run `make` to view the selection of developer commands in the Makefile
3. run `make build` to build the release snapshot binaries and packages
4. for an even quicker start you can run `go run cmd/grant/main.go` to print the syft help.
    - this command `go run cmd/grant/main.go check alpine:latest` will compile and run grant against the alpine:latest image
5. view the README or grant help output for more output options

The main make tasks for common static analysis and testing are `lint`, `format`, `lint-fix`, `unit`

See `make help` for all the current make tasks.

## Architecture

At a high level, this is the package structure of grant:
```
./cmd/grant/
│   ├── cli/
│   │   ├── cli.go          // where all commands are wired up
│   │   ├── command/        // all command implementations
│   │   ├── internal/       // all internal command implementations
│   │   ├── option/         // all command flags and configuration options
│   │   └── tui/            // all handlers for events that are shown on the UI
│   └── main.go             // entrypoint for the application
└── grant/                  // the "core" grant library
```

## Testing

### Levels of testing

- `unit`: The default level of test which is distributed throughout the repo are unit tests. Any `_test.go` file that
  does not reside somewhere within the `/test` directory is a unit test. Other forms of testing should be organized in
  the `/test` directory. These tests should focus on correctness of functionality in depth. % test coverage metrics
  only considers unit tests and no other forms of testing.

- `integration`: TODO

- `cli`: located with in `test/cli`, TODO

- `acceptance`: located within `test/compare` and `test/install`, these are smoke-like tests that ensure that application  
  packaging and installation works as expected. TODO