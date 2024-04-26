## Contributing

We welcome contributions to the project!

### Getting Started
After pulling the repository, you can get started by running the following command to install the necessary dependencies and build `grant` from source
```bash
make
```

After building the project, you can run the following command to run the newly built binary
```bash
./snapshot/<os>-build_<>os_<arch>/grant
```

Keep in mind the build artifacts are placed in the `snapshot` directory and built for each supported platform so choose the appropriate binary for your platform.

If you just want to run the project with any local changes you have made, you can run the following command:
```bash
go run cmd/grant/main.go
```

### Testing
You can run the tests for the project by running the following command:
```bash
make test
```

### Linting
You can run the linter for the project by running the following command:
```bash
make static-analysis
```

### Making a PR
Just fork the repository, make your changes on a branch, and submit a PR. We will review your changes and merge them if they are good to go.

When making a PR, please make sure to include a description of the changes you have made and the reasoning behind them. 
If you are adding a new feature, please include tests for the new feature. If you are fixing a bug, please include a test that reproduces the bug and ensure that the test passes after your changes.