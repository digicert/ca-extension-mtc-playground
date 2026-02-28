# Go Style Guide — mtc-bridge

## Package Design

- Keep packages small and focused. One primary type or concept per package.
- No circular dependencies. Dependency flow: cmd → internal packages → stdlib.
- Interfaces belong in the **consumer** package, not the implementor.

## Error Handling

```go
// GOOD: wrap with context
return fmt.Errorf("store.AppendEntry: %w", err)

// BAD: naked error return
return err
```

- Always wrap errors with `fmt.Errorf("pkg.Func: %w", err)` at package boundaries.
- Use `errors.Is()` and `errors.As()` for programmatic error checks.
- Define sentinel errors as package-level `var` for expected failure modes.

## Logging

```go
// GOOD: structured logging
slog.Info("entry appended", "index", idx, "serial", serial)

// BAD: printf-style
log.Printf("entry %d appended for serial %s", idx, serial)
```

- Use `log/slog` everywhere. Never `fmt.Printf` or `log.Printf` in library code.
- Log levels: `Debug` for development, `Info` for operational, `Warn` for recoverable, `Error` for failures.

## Context

- Every public function that does I/O takes `context.Context` as first argument.
- Pass context through — never store in structs.
- Use `context.WithTimeout` for database calls.

## Testing

```go
func TestTreeHash(t *testing.T) {
    tests := []struct {
        name   string
        leaves [][]byte
        want   [32]byte
    }{
        {name: "empty", leaves: nil, want: emptyHash},
        {name: "single", leaves: [][]byte{{1}}, want: singleHash},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := MTH(tt.leaves)
            if got != tt.want {
                t.Errorf("MTH() = %x, want %x", got, tt.want)
            }
        })
    }
}
```

- Table-driven tests with descriptive `t.Run` names.
- Use `testify` only if absolutely needed — prefer stdlib.
- Integration tests gated by build tags: `//go:build integration`.

## Naming

- Exported types: `PascalCase` (e.g., `LogEntry`, `TreeHash`)
- Unexported: `camelCase`
- Acronyms uniform: `SPKI`, `DER`, `TLS`, not `Spki`, `Der`
- Constructor pattern: `NewFoo(...)` returns `(*Foo, error)`
- Options pattern: `type Option func(*config)` when >3 optional params

## Formatting

- `gofmt` / `goimports` — non-negotiable
- Max line length ~120 chars, soft limit
- Group imports: stdlib, external, internal (separated by blank lines)
