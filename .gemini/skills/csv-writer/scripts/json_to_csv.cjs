const fs = require('fs');
const path = require('path');

/**
 * Converts an array of JSON objects to CSV format and writes to a file.
 * Usage: node json_to_csv.cjs <output_file_path> <json_string_or_file>
 */

const args = process.argv.slice(2);
if (args.length < 2) {
  console.error('Usage: node json_to_csv.cjs <output_file_path> <json_string_or_file>');
  process.exit(1);
}

const outputPath = args[0];
let inputData = args[1];

// Check if input is a file path or raw JSON string
if (fs.existsSync(inputData)) {
  try {
    inputData = fs.readFileSync(inputData, 'utf8');
  } catch (err) {
    console.error(`Error reading input file: ${err.message}`);
    process.exit(1);
  }
}

let data;
try {
  data = JSON.parse(inputData);
} catch (err) {
  console.error(`Error parsing JSON: ${err.message}`);
  process.exit(1);
}

// Handle wrapped output from MCP tools (often comes as { "output": "..." } or array of objects)
if (data.output && typeof data.output === 'string') {
  try {
      // Try to parse the inner string if it looks like JSON
      // Often MCP output is a stringified JSON array of lines
      const lines = data.output.trim().split('\n');
      data = lines.map(line => JSON.parse(line));
  } catch (e) {
      // If straightforward parse fails, it might just be the array directly
      try {
        data = JSON.parse(data.output);
      } catch (e2) {
         console.error("Could not parse inner output as JSON array or NDJSON.");
         process.exit(1);
      }
  }
} else if (data.output && Array.isArray(data.output)) {
    data = data.output;
}

if (!Array.isArray(data)) {
    // If it's a single object, wrap it
    if (typeof data === 'object' && data !== null) {
        data = [data];
    } else {
        console.error('Input data must be an array of objects or a single object.');
        process.exit(1);
    }
}

if (data.length === 0) {
  console.log('No data to write.');
  process.exit(0);
}

// Extract headers
const headers = Object.keys(data[0]);

// Convert to CSV
const csvRows = [];
csvRows.push(headers.join(',')); // Header row

for (const row of data) {
  const values = headers.map(header => {
    const escaped = ('' + (row[header] === null ? '' : row[header])).replace(/"/g, '""');
    return `"${escaped}"`;
  });
  csvRows.push(values.join(','));
}

const csvContent = csvRows.join('\n');

try {
  // Ensure directory exists
  const dir = path.dirname(outputPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(outputPath, csvContent);
  console.log(`Successfully wrote ${data.length} rows to ${outputPath}`);
} catch (err) {
  console.error(`Error writing CSV file: ${err.message}`);
  process.exit(1);
}
