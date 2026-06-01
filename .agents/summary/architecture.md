# Architecture

## System Overview

```mermaid
graph LR
    subgraph "Pipeline"
        E["cve-metadata-extractor"]
        C["cve-corrector"]
        A["cve-agent"]
    end
    E -->|cve-metadata.json| C
    C -->|exit code + state| A
    A -->|subprocess| C
    subgraph "External"
        D["Debian Tracker"]
        O["OSV API"]
        N["NVD / CVEList V5"]
        U["Ubuntu API"]
        Y["Yocto devtool"]
        AI["kiro-cli (AI)"]
    end
    E --> D & O & N & U
    C --> Y
    A --> AI
```

## Dependency Graph (Internal)

```mermaid
graph BT
    shared["shared (leaf)"]
    extractor["cve_metadata_extractor"]
    corrector["cve_corrector"]
    agent["cve_agent"]
    extractor --> shared
    corrector --> shared
    agent --> shared
    agent -.->|subprocess only| corrector
```

**Invariant**: `shared` has zero upward dependencies. No package imports from a sibling package at the Python level. The agent invokes the corrector only via `subprocess.run()`.

## Process Isolation

The agent and corrector run in separate processes:

```mermaid
sequenceDiagram
    participant Agent as cve-agent
    participant Corrector as cve-corrector
    participant AI as kiro-cli

    Agent->>Corrector: subprocess.run([python, -m, cve_corrector, ...])
    Corrector-->>Agent: exit code (0-12)
    alt Recoverable (1, 3, 4)
        Agent->>AI: spawn session with context
        AI-->>Agent: resolved / timed out
        Agent->>Corrector: re-run with --continue
    else Unrecoverable (2, 5-12)
        Agent-->>Agent: escalate immediately
    end
```

This design ensures:
- Corrector crashes don't take down the agent
- AI sessions operate in an isolated git workspace
- State is persisted to disk between invocations (resume after interruption)

## Plugin System

Both the extractor and agent support runtime plugin discovery:

```mermaid
graph TD
    subgraph "Plugin Loading"
        dir["extra/ directory"]
        env["CVE_EXTRA_SOURCES_DIR / CVE_EXTRA_BACKENDS_DIR"]
        loader["importlib.util.spec_from_file_location"]
    end
    dir --> loader
    env -->|override| dir
    loader -->|CveSource| SR["SOURCE_REGISTRY"]
    loader -->|AIBackend| BR["_BACKENDS dict"]
```

**Security controls**:
- Directory must be owned by current user (`st_uid == os.getuid()`)
- Directory must not be world-writable (`st_mode & 0o002 == 0`)
- Files starting with `_` are skipped
- Load errors are caught and logged (no crash)
- Backend loader additionally rejects symlinks and world-writable files

## State Management

The corrector uses a serializable `WorkflowState` dataclass persisted as JSON:

```mermaid
stateDiagram-v2
    [*] --> setup_workspace
    setup_workspace --> cherry_pick
    cherry_pick --> build : success
    cherry_pick --> CONFLICT : conflict
    build --> ptest : success
    build --> BUILD_ERROR : failure
    ptest --> finish : success
    ptest --> PTEST_ERROR : failure
    finish --> [*]
    CONFLICT --> [*] : exit 1
    BUILD_ERROR --> [*] : exit 4
    PTEST_ERROR --> [*] : exit 3
```

State files are written atomically (`tempfile` + `os.replace`) to the build directory's state dir.

## Security Architecture

| Boundary | Mechanism |
|----------|-----------|
| Git subprocess env | `GIT_ENV_ALLOWLIST` — only safe vars passed through |
| Plugin loading | Ownership + permission checks before `exec_module` |
| AI file scope | Pre-commit hook restricts which files AI can modify |
| Secrets | Never passed to git env; `GITHUB_TOKEN` used only in HTTP requests |
| Atomic writes | State files use `tempfile` + `os.replace` to prevent corruption |

## Configuration Hierarchy

```mermaid
graph TD
    ENV["Environment Variables"]
    CLI["CLI Arguments"]
    CFG["config.json"]
    XDG["XDG Base Dirs"]
    CLI -->|highest priority| FINAL["Effective Config"]
    ENV --> FINAL
    CFG --> FINAL
    XDG -->|defaults| FINAL
```

Priority: CLI args > environment variables > config.json > XDG defaults.
