# Falco Regression Tests

This testing suite is implemented in Go, and Go is the only dependency required in your system.

```
go generate ./...
go test ./...
```

NOTE: the `go generate` step is necessary in order to prepare the test files.
