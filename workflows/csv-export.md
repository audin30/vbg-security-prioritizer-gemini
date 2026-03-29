# Workflow: CSV Export

Triggered when the user asks to export results to CSV, save as a spreadsheet, or download findings.

## Steps

1. Write the data as a JSON array to a temp file:
   ```bash
   # Gemini CLI writes the JSON from a previous query result
   echo '<json_array>' > /tmp/export_data.json
   ```

2. Convert to CSV:
   ```bash
   node csv-writer/scripts/json_to_csv.cjs ./output.csv /tmp/export_data.json
   ```

3. Clean up the temp file:
   ```bash
   rm /tmp/export_data.json
   ```

## Input Formats Supported

- JSON array of objects: `[{"col1": "val", ...}, ...]`
- Single JSON object (auto-wrapped in array)
- NDJSON (newline-delimited JSON, one object per line)
- MCP tool output wrapped as `{ "output": "..." }`

## Output

Standard CSV with quoted fields. The first row is headers derived from the first object's keys.
