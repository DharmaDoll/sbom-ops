# Fixtures

These documented mock payloads model the Dependency-Track v4 read endpoints
and GitHub Issues endpoints used by the client tests. The Finding fixture
includes `component.uuid`, `component.purl`, `vulnerability.uuid`, and
`vulnerability.source` because those fields form the preferred v2 machine
identity. Validate the fixture against the target instance's OpenAPI document
before production rollout.
