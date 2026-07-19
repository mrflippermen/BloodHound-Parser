# Contributing

Thanks for helping improve BloodHound Parser.

## Dev setup

```bash
git clone https://github.com/mrflippermen/BloodHound-Parser.git
cd BloodHound-Parser
python -m pip install -e ".[dev]"   # pytest + ruff + mypy
```

## Run the checks locally

```bash
ruff check src tests            # lint
python -m unittest discover -s tests -v   # tests (stdlib) — or: pytest -q
mypy src/parseSharpHound.py     # optional type-check
```

CI runs the same on every push/PR (Linux + Windows, Python 3.8/3.11/3.12).

## Adding a new detection

1. Add the check inside the relevant `_analyze_*` method in
   `src/parseSharpHound.py`, appending a `Finding(category, severity, principal,
   detail, target)`.
2. Use the **exact SharpHound CE property name** (lower-case, under `Properties`).
   Guard optional structures (e.g. `Aces`, `Trusts`) with `or []`.
3. Add a counter to `ADStatistics` if it is worth a summary line.
4. Plant a matching object in `examples/sample_data/` and assert on it in
   `tests/test_parser.py`. Every detection must be regression-tested.
5. Update `CHANGELOG.md` and the detection catalog in the README.

## Guidelines

- **No external runtime dependencies** — standard library only. Dev tooling is fine.
- Keep it a single importable module so it stays a drop-on-a-box tool.
- Prefer clear, boolean-predicate detections that map 1:1 to a JSON property.
