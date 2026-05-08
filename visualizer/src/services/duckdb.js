import * as duckdb from "@duckdb/duckdb-wasm";

import duckdbMvpWasm from "@duckdb/duckdb-wasm/dist/duckdb-mvp.wasm?url";

import duckdbEhWasm from "@duckdb/duckdb-wasm/dist/duckdb-eh.wasm?url";

import duckdbMvpWorker from "@duckdb/duckdb-wasm/dist/duckdb-browser-mvp.worker.js?url";

import duckdbEhWorker from "@duckdb/duckdb-wasm/dist/duckdb-browser-eh.worker.js?url";

let connection = null;

export async function getConnection() {
  if (connection) {
    return connection;
  }

  const MANUAL_BUNDLES = {
    mvp: {
      mainModule: duckdbMvpWasm,
      mainWorker: duckdbMvpWorker,
    },

    eh: {
      mainModule: duckdbEhWasm,
      mainWorker: duckdbEhWorker,
    },
  };

  const bundle =
    await duckdb.selectBundle(
      MANUAL_BUNDLES
    );

  const worker = new Worker(
    bundle.mainWorker
  );

  const logger =
    new duckdb.ConsoleLogger();

  const db =
    new duckdb.AsyncDuckDB(
      logger,
      worker
    );

  await db.instantiate(
    bundle.mainModule
  );

  connection =
    await db.connect();

  await db.registerFileURL(
  "repository_risk.parquet",
  "/parquet/repository_risk.parquet",
  duckdb.DuckDBDataProtocol.HTTP,
  false
);

await db.registerFileURL(
  "language_risk.parquet",
  "/parquet/language_risk.parquet",
  duckdb.DuckDBDataProtocol.HTTP,
  false
);

await db.registerFileURL(
  "top_vulnerable_packages.parquet",
  "/parquet/top_vulnerable_packages.parquet",
  duckdb.DuckDBDataProtocol.HTTP,
  false
);

await db.registerFileURL(
  "top_cwes.parquet",
  "/parquet/top_cwes.parquet",
  duckdb.DuckDBDataProtocol.HTTP,
  false
);

await db.registerFileURL(
  "cross_repository_patterns.parquet",
  "/parquet/cross_repository_patterns.parquet",
  duckdb.DuckDBDataProtocol.HTTP,
  false
);

await db.registerFileURL(
  "repository_dependency_stats.parquet",
  "/parquet/repository_dependency_stats.parquet",
  duckdb.DuckDBDataProtocol.HTTP,
  false
);

await db.registerFileURL(
  "severity_distribution.parquet",
  "/parquet/severity_distribution.parquet",
  duckdb.DuckDBDataProtocol.HTTP,
  false
);

  console.log(
    "[DuckDB] initialized"
  );

  return connection;
}