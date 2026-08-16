# Known limitations

## Scanner support

- Scanner binaries must be installed separately. Trust Gate invokes them
  as external processes.
- DAST scanning requires explicit opt-in and scope configuration. No
  unauthenticated scanning of production targets by default.
- CodeQL requires a GitHub licence.

## Benchmarks

- Independent review of benchmark labels is pending (Phase 17.2).
- Statistical methodology review requires external expertise (Phase 26.2).
- Benchmark ground truth is manually labelled and may contain errors.

## Compliance

- Compliance mappings state what evidence is available. They do not
  claim or verify actual compliance.
- Some controls require manual verification that cannot be automated.

## Deployment

- Self-hosted mode requires Docker. Native package support is planned.
- Air-gapped operation requires manual import of vulnerability databases
  and threat intelligence feeds.

## Performance

- Large monorepos (>100k files) may benefit from changed-file scanning
  to reduce scan times.
- Parallel scanner execution is limited by available CPU and memory.

## Licensing

- Licence verification requires the `cryptography` Python package.
- Licence expiry degrades to community edition — it does not block
  access to scan results.
