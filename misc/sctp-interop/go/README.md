# Go Interop Programs

- `server.go`: listens with `ListenSCTP`, prints received stream/PPID/payload
- `client.go`: dials with `DialSCTP`, sends one message with `WriteToSCTP`

These are used by `../harness/run_matrix.sh`.
