export function normalizeValue(value) {
  if (typeof value === "bigint") {
    return Number(value);
  }

  return value;
}

export function normalizeRow(row) {
  const json = row.toJSON();
  const normalized = {};

  Object.entries(json).forEach(([key, value]) => {
    normalized[key] = normalizeValue(value);
  });

  return normalized;
}

export function normalizeTable(result) {
  return result.toArray().map(normalizeRow);
}