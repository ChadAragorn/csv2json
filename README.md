# csv2json

`csv2json` is a small, fast, single-binary C utility that converts CSV data into JSON suitable for piping directly into [`jq`](https://stedolan.github.io/jq/).

It is designed to be:
- **Zero dependencies**
- **Streaming-friendly**
- **RFC4180-aware** (quotes, embedded delimiters, embedded newlines)
- **Delimiter-agnostic** (auto-detected)
- **Safe for large files**

By default, it outputs **NDJSON** (one JSON object per line), which is ideal for Unix pipelines.

---

## Features

- Auto-detects delimiter from the **first non-blank record**
  - Supported candidates: `,` `\t` `;` `|`
- Skips **truly blank lines** (empty or whitespace-only)
- Preserves delimiter-only rows like `,,,`
- Handles:
  - Quoted fields
  - Escaped quotes (`""`)
  - Embedded newlines inside quoted fields
- Optional type inference:
  - empty → `null`
  - numbers → JSON numbers
  - `true` / `false` / `null`
- Outputs either:
  - **NDJSON** (default)
  - **JSON array** (`--array`)
- Reads from a file **or stdin**

---

## Building

### Requirements
- C compiler (gcc or clang)
- POSIX-like system (Linux, macOS, BSD)

### Compile

```bash
cc -O2 -Wall -Wextra -std=c11 -o csv2json csv2json.c
```

---

## Usage

### Basic

```bash
./csv2json data.csv
```

### Pipe into jq

```bash
./csv2json data.csv | jq .
```

### Read from stdin

```bash
cat data.csv | ./csv2json
```

---

## Output Modes

### NDJSON (default)

```bash
./csv2json data.csv
```

Produces one JSON object per line.

### JSON Array

```bash
./csv2json --array data.csv
```

---

## Headers

### Default (first row is header)

```bash
./csv2json data.csv
```

### No header row

```bash
./csv2json --no-header data.csv
```

Auto-generates `col1`, `col2`, ...

---

## Type Inference

```bash
./csv2json --infer-types data.csv
```

---

## Blank Lines

Skipped:
- Empty lines
- Whitespace-only lines

Not skipped:
- Delimiter-only lines like `,,,`

---

## Delimiter Detection

Auto-detected from first non-blank row:
- `,`
- `\t`
- `;`
- `|`

---

## License

MIT License.
