# Contributing

## Development

1. Create a Python 3.12 virtual environment
2. Install `.[dev]`
3. Run `pytest`
4. Run `ruff check .`
5. Run `black --check .`

## Rules

- Keep business logic out of API clients
- Add tests with each behavior change
- Update `SPEC.md` when changing contracts
