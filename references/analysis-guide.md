# StarRocks Upgrade Analysis Guide

Use this reference after `sr_upgrade_compare.py` generates the initial report.

## High-Value Source Anchors

- FE configs: `fe/fe-core/src/main/java/com/starrocks/common/Config.java`
- Session variables: `fe/fe-core/src/main/java/com/starrocks/qe/SessionVariable.java`
- System variables: `fe/fe-core/src/main/java/com/starrocks/qe/GlobalVariable.java`
- SQL variable manager: `fe/fe-core/src/main/java/com/starrocks/qe/VariableMgr.java`
- BE configs: `be/src/common/config.h`
- MV metadata and reload: `fe/fe-core/src/main/java/com/starrocks/catalog/MaterializedView.java`
- MV status changes: `fe/fe-core/src/main/java/com/starrocks/alter/AlterJobMgr.java`
- MV alter and inactive paths: `fe/fe-core/src/main/java/com/starrocks/alter/AlterMVJobExecutor.java`
- MV refresh execution: `fe/fe-core/src/main/java/com/starrocks/scheduler/PartitionBasedMvRefreshProcessor.java`
- Protocol: `gensrc/thrift/`, `gensrc/proto/`
- Parser: `fe/fe-core/src/main/java/com/starrocks/sql/parser/`, `fe/fe-core/src/main/cup/`, `fe/fe-core/src/main/jflex/`

## Risk Model

Treat these as higher risk until source tracing proves otherwise:

- Removed config or variable that may still exist in user `fe.conf` or `be.conf`
- Removed or renamed `@VarAttr` system variable that may still exist in `SHOW VARIABLES`, `SHOW GLOBAL VARIABLES`, SQL init scripts, user properties, MV properties, or automation using `SET GLOBAL`
- Default value flips for optimizer, MV rewrite, timeout, memory, compaction, storage, or type conversion behavior
- New feature paths that change timeout ownership, buffering, queueing, commit behavior, or client parameters even when the feature is opt-in
- Protocol field removal, required field addition, enum renumbering, or service signature change
- Storage format version, tablet metadata, rowset/segment encoding, or compression behavior change
- MV refresh, rewrite, partition mapping, schema compatibility, reload, activation, or inactive logic changes
- Parser grammar changes that add reserved words or change existing syntax

## Config-Specific Checks

When the user provides config:

- Removed config + exists in user conf: HIGH; user must remove it before upgrade.
- Default changed + user does not override it: risk follows scanner severity.
- Default changed + user explicitly sets old value: MEDIUM; user is preserving old behavior and should decide intentionally.
- Default changed + user has a custom non-default value: LOW unless source tracing shows the value is no longer valid.

When the user does not provide config:

- Report default changes.
- State that production-specific config conflicts were not checked.
- Do not ask for config unless the user wants a production checklist.

## System Variable Checks

StarRocks SQL-layer system parameters are not FE/BE config file keys. `VariableMgr` builds them from `SessionVariable` and `GlobalVariable` `@VarAttr` annotations.

- `SessionVariable` entries can be changed per session; `SET GLOBAL` changes the default session variable and is persisted unless the variable is `SESSION_ONLY`.
- `GlobalVariable` entries are process-wide global variables; `READ_ONLY` entries cannot be changed.
- `SHOW VARIABLES` displays `attr.show()` when present, otherwise `attr.name()`; aliases may still be accepted by `SET`.
- The upgrade report should compare source-level `@VarAttr` additions, removals, default flips, aliases, and flags.

When the user provides `SHOW VARIABLES` or `SHOW GLOBAL VARIABLES` output:

- Removed variable + exists in snapshot: HIGH; remove it from automation/init SQL before upgrade.
- Default changed + snapshot matches old default: MEDIUM; behavior will change unless the value is explicitly preserved where allowed.
- Default changed + snapshot has custom value: LOW/MEDIUM depending on scanner severity; verify the value is still accepted.
- Variable changed to or from `READ_ONLY`, `SESSION_ONLY`, `GLOBAL`, or `INVISIBLE`: check `VariableMgr.checkUpdate`, `setSystemVariable`, and `dump` behavior.

## MV Lifecycle Checks

For MV findings, trace these flows:

- `AlterJobMgr.alterMaterializedViewStatus`: ACTIVE re-parses MV SQL and rebuilds relationships.
- `MaterializedView.onReload`: reloads/query-analyzes MV metadata and may activate or deactivate MVs.
- `AlterMVJobExecutor.inactiveRelatedMaterializedViews`: base table schema changes may invalidate MVs.
- `PartitionBasedMvRefreshProcessor`: computes partitions and executes MV refresh.
- `MaterializedView.getUpdatedPartitionNamesOfOlapTable`: checks base table partition versions through refresh context.

Always ask:

- Does the change force full refresh or clear visible version maps?
- Can existing MVs become inactive after FE restart or leader transfer?
- Can query rewrite silently stop matching?
- Does rolling upgrade create old/new FE or BE mixed behavior?

## Feature Impact Checks

For `feature-impact-findings.json`, treat each item as a candidate that needs source verification and a user-facing behavior entry.

First check `type`:

- `feature_introduced`: base lacks the feature anchors and target contains them. It is valid to describe old behavior as "not supported / no such path".
- `feature_behavior_changed`: both versions already contain the feature anchors. Do not say the feature is newly introduced. Explain the exact changed default, header, routing, timeout, queueing, or task path after reading the diff/source.

### INSERT-like task timeout

Search keys:

- `insert_timeout`
- `INSERT_TIMEOUT`
- `setInsertTimeout`
- `MV_SESSION_INSERT_TIMEOUT`
- `task.insert_timeout`
- `isExecLoadType`

Check whether the target version routes `INSERT`, `UPDATE`, `DELETE`, `CTAS`, MV refresh, statistics collection, PIPE, or scheduler tasks through `insert_timeout` instead of `query_timeout`.

User-facing conclusion should say:

- For `feature_introduced`, before/now should compare old `query_timeout` or old task properties against target `insert_timeout`, including the default when visible in `SessionVariable`.
- For `feature_behavior_changed`, before/now should compare the two concrete implementations, not repeat the introduced-feature wording.
- Trigger: SQL/task/MV/PIPE paths that can be affected.
- Impact: old `query_timeout` tuning may no longer bound these jobs; timeouts can become longer or different than expected.
- Handling: set `insert_timeout` explicitly through session/global defaults, MV/session properties, task properties, PIPE properties, or SQL hints where supported.

### Stream Load merge_commit / batch write

Search keys:

- `enable_merge_commit`
- `merge_commit`
- `merge_commit_async`
- `merge_commit_interval_ms`
- `merge_commit_parallel`
- `enable_batch_write`
- `batch_write`

Check Stream Load HTTP headers, FE batch-write scheduling, BE batch-write execution, transaction state polling, queue/thread-pool configs, and response behavior.

User-facing conclusion should say:

- For `feature_introduced`, before/now should say old versions do not route Stream Load through merge commit/batch write, while target accepts merge-commit headers and routes loads through batching/merge-commit queues.
- For `feature_behavior_changed`, before/now should compare the exact changed header, default, routing, queueing, timeout, or transaction-state behavior.
- Trigger: clients/connectors setting `enable_merge_commit=true` or related headers/configs.
- Impact: suitable for many small concurrent writes, but unsuitable scenarios can add buffering/wait time, queue pressure, commit delay, or performance regression.
- Handling: inventory client headers, pressure-test enabled/disabled paths, tune batch size/concurrency/interval, and keep a rollback switch by stopping `enable_merge_commit`.

## Final Report Shape

Prioritize:

1. Blockers and HIGH/CRITICAL risks
2. Config and system-variable conflicts if user context was provided
3. MV risks
4. Rolling upgrade risks
5. Medium and low findings
6. PR/commit summary

Keep user-facing output short. Put detailed raw artifacts in the output directory.
