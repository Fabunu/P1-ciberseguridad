# SBOM Analysis — Proyecto 1 de Ciberseguridad

## Integrantes del grupo

| Fabiola Chequelaf 
| Francisco Cárdenas
| Yasmin Henriquez

---

Pipeline automatizado de análisis de seguridad sobre el ecosistema de repositorios de [TrinoDB](https://trinodb.io). Implementa extracción de SBOMs, escaneo de vulnerabilidades en dependencias (SCA), análisis estático de código (SAST), y un dashboard interactivo de visualización.

---

## Organización analizada: TrinoDB

<p align="center">
  <img src="trinodb.png" alt="TrinoDB Logo" width="200"/>
  <br>
  <em>Logo oficial de TrinoDB</em>
</p>

TrinoDB es la organización open-source detrás de [Trino](https://github.com/trinodb/trino), un motor de consultas SQL distribuidas de alta concurrencia (anteriormente PrestoSQL). La organización alberga más de 40 repositorios que incluyen el motor principal, clientes nativos (Python, Go, Java, JavaScript, C#, .NET), conectores (Hive, Cassandra, Kafka), herramientas de infraestructura (Docker, Kubernetes Operator, Helm Charts), y utilidades de integración continua.

El análisis cubre los **42 repositorios públicos** listados en `data/repos.json`, clonados localmente en `data/repos/`.

---

## Arquitectura del proyecto

```
P1-ciberseguridad/
├── miner/                          # Capa de extracción y normalización
│   ├── adapters/
│   │   ├── generate_sboms.py       # Syft — generación de SBOMs
│   │   ├── generate_grype.py       # Grype — escaneo de vulnerabilidades SCA
│   │   ├── generate_codeql.py      # CodeQL — análisis estático SAST
│   │   └── generate_ci_analysis.py # Checkov — análisis de CI/CD
│   ├── run_extraction.py           # Orquestador de extracción
│   ├── run_normalization.py        # Normalización a esquema unificado (Parquet)
│   └── run_pipeline.py             # Pipeline completo (extracción + normalización)
├── analyzer/                       # Capa de análisis y métricas
│   ├── scripts/
│   │   ├── load_data.py            # Carga de datasets normalizados
│   │   ├── metrics.py              # Métricas y transformaciones analíticas
│   │   ├── aggregations.py         # Pipeline de agregaciones
│   │   └── export_gold_dataset.py  # Exportación a gold datasets (Parquet)
│   ├── notebooks/                  # Jupyter notebooks por dominio
│   │   ├── 00_data_validation.ipynb
│   │   ├── 01_repository_overview.ipynb
│   │   ├── 02_dependency_analysis.ipynb
│   │   ├── 03_codeql_analysis.ipynb
│   │   ├── 04_risk_scoring.ipynb
│   │   └── 05_cross_repository_patterns.ipynb
│   └── outputs/                    # Gold datasets generados (Parquet)
├── visualizer/                     # Dashboard web interactivo (React + DuckDB-WASM)
│   ├── src/
│   │   ├── components/             # Componentes UI (KPIs, tablas, charts)
│   │   ├── services/               # Conexión DuckDB-WASM + queries SQL
│   │   └── utils/                  # Normalizadores y generación de insights
│   └── public/parquet/             # Gold datasets servidos estáticamente
├── data/
│   ├── repos.json                  # Catálogo de repositorios (TrinoDB)
│   ├── repos/                      # Repos clonados (git clone --depth 1)
│   ├── raw/                        # Datos crudos por herramienta
│   │   ├── syft/                   # SBOMs nativos (Syft JSON)
│   │   ├── grype/                  # Vulnerabilidades SCA (Grype JSON)
│   │   └── codeql/                 # Hallazgos SAST (CodeQL SARIF → JSON)
│   └── normalized/                 # Datos normalizados (Parquet)
└── scripts/
    └── add_submodules.py           # Script de clonado de repositorios
```

### Flujo de datos

```
Repositorios (git clone)
    ↓
┌─────────────────┐
│  MINER           │
│  ├─ Syft (SBOM)  │  → data/raw/syft/
│  ├─ Grype (SCA)  │  → data/raw/grype/
│  ├─ CodeQL (SAST)│  → data/raw/codeql/
│  └─ Checkov (CI) │  → data/results/
└─────────────────┘
    ↓  run_normalization.py
┌─────────────────────┐
│  NORMALIZED (Parquet)│
│  ├─ repositories    │
│  ├─ dependencies    │
│  ├─ dep_vulns       │
│  └─ code_vulns      │
└─────────────────────┘
    ↓  export_gold_dataset.py
┌────────────────┐
│  ANALYZER       │
│  ├─ metrics.py  │
│  └─ notebooks/  │
└────────────────┘
    ↓  gold datasets (Parquet)
┌────────────────────┐
│  VISUALIZER         │
│  ├─ DuckDB-WASM    │  (SQL in-browser)
│  ├─ Recharts       │  (gráficos)
│  └─ React          │  (UI)
└────────────────────┘
```

### Decisiones de diseño

| Decisión | Justificación |
|---|---|
| **Parquet como formato unificado** | Columnar, comprimido, eficiente para análisis exploratorio y consultas SQL vía DuckDB. La capa de normalización convierte JSON → Parquet con esquemas fijos. |
| **Pipeline secuencial (extracción → normalización → análisis)** | Separación clara de responsabilidades. Cada etapa produce artefactos en disco, permitiendo reanudar desde cualquier punto sin re-ejecutar etapas anteriores. |
| **DuckDB-WASM en el visualizador** | Ejecuta SQL analítico directamente en el navegador sin backend. Los Parquet se sirven como assets estáticos desde `public/parquet/`. Esto elimina la necesidad de un servidor de datos intermedio. |
| **ID hash (SHA-1) como claves surrogate** | Cada entidad (repositorio, dependencia, vulnerabilidad) recibe un `sha1_hash(<contexto>)` como identificador determinístico. Permite joins entre datasets sin depender de IDs secuenciales y facilita la deduplicación. |
| **Idempotencia en extracción** | Cada adapter verifica si su output ya existe (`skip if exists`). La extracción es reanudable tras fallos parciales sin regenerar datos previos. |
| **Detección de lenguajes en CodeQL** | En lugar de depender del autobuild de CodeQL (que requiere metadatos Git y puede fallar en repos clonados con `--depth 1`), se implementa detección por extensiones de archivo y se pasa `--language` explícitamente. |
| **Scripts como entry points (no notebooks)** | Las métricas y transformaciones están implementadas como módulos Python reutilizables (`metrics.py`, `aggregations.py`). Los notebooks solo consumen los gold datasets ya generados, separando análisis reproducible de exploración ad-hoc. |

---

## Configuración del Dev Container

El proyecto incluye un Dev Container completo en `.devcontainer/`:

- **Imagen base**: `mcr.microsoft.com/devcontainers/python:1-3.11-bullseye`
- **Gestor de paquetes**: `uv` (instalado desde `ghcr.io/astral-sh/uv:latest`)
- **Herramientas de seguridad**:
  - [Syft](https://github.com/anchore/syft) — generación de SBOMs
  - [Grype](https://github.com/anchore/grype) — escáner de vulnerabilidades
  - [CodeQL CLI v2.25.1](https://github.com/github/codeql-cli-binaries) — análisis estático
  - [Checkov](https://www.checkov.io/) — análisis de infraestructura como código
- **Node.js 20** — necesario para CodeQL (JS/TS), npm y el visualizer
- **Query packs CodeQL pre-descargados**: `python-queries`, `javascript-queries`, `java-queries`
- **PostCreateCommand**: configura `uv sync`, instala kernel Jupyter, descarga query packs, actualiza DB de Grype
- **Extensiones VSCode**: Python, Pylance, Black, Jupyter
- **Kernel Jupyter personalizado**: `Python (ciberseguridad)`

Para abrir en Dev Container:

```bash
# Opción 1: VSCode + Remote Containers
# Abrir la carpeta en VSCode → Cmd+Shift+P → "Dev Containers: Reopen in Container"

# Opción 2: GitHub Codespaces
# Crear codespace desde el repositorio
```

---

## Instrucciones de ejecución

### 1. Clonar repositorios objetivo

```bash
python scripts/add_submodules.py
```

Clona los 42 repositorios de TrinoDB en `data/repos/` con `git clone --depth 1`.

### 2. Extracción de datos crudos (Miner)

```bash
# Pipeline completo (Syft + Grype + CodeQL)
python miner/run_pipeline.py

# Extracción únicamente
python miner/run_extraction.py

# Extracción individual por herramienta
python miner/adapters/generate_sboms.py     # Syft
python miner/adapters/generate_grype.py     # Grype
python miner/adapters/generate_codeql.py    # CodeQL

# Diagnóstico de entorno (verificar que las herramientas estén instaladas)
python miner/adapters/generate_codeql.py --diagnose
python miner/adapters/generate_grype.py --diagnose

# Dry-run (ver qué se ejecutaría sin correr las herramientas)
python miner/run_extraction.py --dry-run
```

Salida: archivos JSON en `data/raw/{syft,grype,codeql}/`.

### 3. Normalización (raw → Parquet)

```bash
python miner/run_normalization.py
```

Convierte los JSON crudos a 4 tablas Parquet en `data/normalized/`:
- `repositories.parquet` — catálogo de repositorios con conteos agregados
- `dependencies.parquet` — dependencias extraídas por Syft
- `dependency_vulnerabilities.parquet` — vulnerabilidades SCA (Grype)
- `code_vulnerabilities.parquet` — hallazgos SAST (CodeQL)

### 4. Análisis y gold datasets (Analyzer)

```bash
python analyzer/scripts/export_gold_dataset.py
```

Genera 9 gold datasets en `analyzer/outputs/`:

| Dataset | Descripción |
|---|---|
| `repository_summary.parquet` | Resumen por repositorio |
| `severity_distribution.parquet` | Distribución de severidades |
| `repository_risk.parquet` | Ranking de riesgo por repo |
| `top_vulnerable_packages.parquet` | Paquetes con más CVEs |
| `top_cwes.parquet` | CWE más frecuentes |
| `language_risk.parquet` | Riesgo agregado por lenguaje |
| `repository_dependency_stats.parquet` | Estadísticas SCA por repo |
| `repository_codeql_stats.parquet` | Estadísticas SAST por repo |
| `cross_repository_patterns.parquet` | CVEs que afectan múltiples repos |

### 5. Jupyter Notebooks (análisis exploratorio)

```bash
# Iniciar Jupyter Lab
jupyter lab

# Navegar a analyzer/notebooks/ y ejecutar en orden:
# 00_data_validation.ipynb   → Validación de esquemas y calidad
# 01_repository_overview.ipynb  → Visión general
# 02_dependency_analysis.ipynb  → Análisis de dependencias
# 03_codeql_analysis.ipynb     → Análisis CodeQL
# 04_risk_scoring.ipynb       → Scoring de riesgo
# 05_cross_repository_patterns.ipynb → Patrones entre repos
```

### 6. Copiar gold datasets al visualizador

```bash
# Los scripts de análisis copian los Parquet a visualizer/public/parquet/
# Si se requiere manualmente:
cp analyzer/outputs/*.parquet visualizer/public/parquet/
```

### 7. Dashboard web (Visualizer)

```bash
cd visualizer

# Instalar dependencias (solo primera vez)
npm install

# Desarrollo (hot reload en http://localhost:5173)
npm run dev

# Build de producción
npm run build

# Vista previa del build
npm run preview
```

El visualizador es una SPA en React 18 que:
- Carga los Parquet vía **DuckDB-WASM** (SQL in-browser)
- Consulta cada dataset con SQL y renderiza gráficos con **Recharts** y **@tremor/react**
- Muestra KPIs, ranking de riesgo por repositorio, distribución de severidad (pie chart), riesgo por lenguaje, paquetes más vulnerables, CWE frecuentes, y patrones entre repositorios

---

## Resumen de comandos

```bash
# 1. Clonar repos
python scripts/add_submodules.py

# 2. Extraer (Syft + Grype + CodeQL)
python miner/run_pipeline.py

# 3. Normalizar
python miner/run_normalization.py

# 4. Generar gold datasets
python analyzer/scripts/export_gold_dataset.py

# 5. Copiar al visualizador
cp analyzer/outputs/*.parquet visualizer/public/parquet/

# 6. Iniciar dashboard
cd visualizer && npm run dev
```
