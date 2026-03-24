---
name: csv-writer
description: Converts JSON data (often from tool outputs) into a CSV file. Use when the user asks to "export to CSV", "save as spreadsheet", or "download the results".
---

# CSV Writer Skill

This skill allows Gemini CLI to save structured data (JSON) as a CSV file.

## Usage

When a user asks to export data to CSV:

1.  **Gather Data**: Ensure you have the JSON data ready (e.g., from a previous `execute_sql` or tool call).
2.  **Save Temporary JSON**: Write the JSON data to a temporary file (e.g., `temp_data.json`).
3.  **Run Script**: Execute the `json_to_csv.cjs` script with the output path and input file.

## Example Workflow

1.  **Run Query**: Get results from `execute_sql`.
2.  **Write Temp**: `write_file("temp.json", JSON.stringify(results))`
3.  **Convert**: `node csv-writer/scripts/json_to_csv.cjs ./output.csv ./temp.json`
4.  **Cleanup**: Delete `temp.json`.

## Script Location

The conversion script is located at: `csv-writer/scripts/json_to_csv.cjs` (relative to the skill root). When installed, use the full path.
