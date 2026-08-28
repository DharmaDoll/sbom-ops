# Contributing

## Development

1. Create a Python 3.12 virtual environment
2. Install `.[dev]`
3. Run `pytest -q tests`
4. Run `make dt-lab-test`
5. Run `make dt-lab-validate`
6. Run `ruff check .`
7. Run `black --check .`

## Rules

- Keep business logic out of API clients
- Add tests with each behavior change
- Update `SPEC.md` when changing contracts
- Keep `src/sbom_ops/` independent of the repository-only DT lab
- Develop lab experiments on short-lived branches and delete them after merge
- Promote lab findings only with reviewed fixtures, production tests, and docs
