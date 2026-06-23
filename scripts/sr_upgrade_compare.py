#!/usr/bin/env python3
"""Codex-friendly StarRocks upgrade comparison.

The script performs deterministic local collection and first-pass scanning.
Codex should still read source and trace callers for HIGH/CRITICAL findings.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


FIELD_SEP = "\x01"
REC_SEP = "\x02"
GIT_LOG_FORMAT = f"%H{FIELD_SEP}%an{FIELD_SEP}%ad{FIELD_SEP}%s{FIELD_SEP}%b{REC_SEP}"
PR_PATTERN = re.compile(r"#(\d{3,7})")

FE_CONFIG_PATH = "fe/fe-core/src/main/java/com/starrocks/common/Config.java"
SESSION_VARIABLE_PATH = "fe/fe-core/src/main/java/com/starrocks/qe/SessionVariable.java"
GLOBAL_VARIABLE_PATHS = [
    "fe/fe-core/src/main/java/com/starrocks/qe/GlobalVariable.java",
    "fe/fe-core/src/main/java/com/starrocks/qe/SysVariable.java",
]
BE_CONFIG_PATH = "be/src/common/config.h"

HIGH_RISK_NAMES = {
    "mysql_server_version",
    "transform_type_prefer_string_for_varchar",
    "max_varchar_length",
    "enable_materialized_view_rewrite",
    "enable_materialized_view_view_delta_rewrite",
    "enable_materialized_view_union_rewrite",
    "enable_materialized_view_rewrite_or_error",
    "query_timeout",
    "insert_timeout",
    "pipeline_dop",
    "parallel_fragment_exec_instance_num",
    "prefer_compute_node",
    "sql_mode",
    "transaction_isolation",
    "enable_load_volume_from_conf",
    "enable_alter_struct_column",
    "enable_rollback_default_warehouse",
    "max_tablet_version_count",
    "tablet_max_versions",
    "storage_root_path",
    "mem_limit",
    "chunk_reserved_bytes_limit",
    "primary_key_limit_size",
    "storage_format_version",
    "bitmap_serialize_version",
    "null_encoding",
    "thrift_rpc_strict_mode",
    "thrift_max_message_size",
}

DATA_IMPACT_NAMES = {
    "max_varchar_length",
    "transform_type_prefer_string_for_varchar",
    "enable_alter_struct_column",
    "max_tablet_version_count",
    "tablet_max_versions",
    "storage_format_version",
    "bitmap_serialize_version",
    "null_encoding",
    "primary_key_limit_size",
    "chunk_reserved_bytes_limit",
}

BEHAVIOR_IMPACT_NAMES = {
    "mysql_server_version",
    "enable_materialized_view_rewrite",
    "enable_materialized_view_view_delta_rewrite",
    "enable_materialized_view_union_rewrite",
    "enable_materialized_view_rewrite_or_error",
    "query_timeout",
    "insert_timeout",
    "pipeline_dop",
    "parallel_fragment_exec_instance_num",
    "prefer_compute_node",
    "sql_mode",
}

HIGH_TIER_PATHS = [
    "fe/fe-core/src/main/java/com/starrocks/sql/optimizer/",
    "fe/fe-core/src/main/java/com/starrocks/planner/",
    "fe/fe-core/src/main/java/com/starrocks/execution/",
    "fe/fe-core/src/main/java/com/starrocks/catalog/",
    "fe/fe-core/src/main/java/com/starrocks/analysis/",
    "fe/fe-core/src/main/java/com/starrocks/sql/ast/",
    "fe/fe-core/src/main/java/com/starrocks/qe/",
    "fe/fe-core/src/main/java/com/starrocks/server/",
    "fe/fe-core/src/main/java/com/starrocks/service/",
    "fe/fe-core/src/main/java/com/starrocks/transaction/",
    "fe/fe-core/src/main/java/com/starrocks/load/",
    "fe/fe-core/src/main/java/com/starrocks/alter/",
    "fe/fe-core/src/main/java/com/starrocks/persist/",
    "be/src/runtime/",
    "be/src/storage/",
    "be/src/service/",
    "be/src/agent/",
    "gensrc/proto/",
    "gensrc/thrift/",
]

HIGH_TIER_FILES = [
    "MaterializedView*.java",
    "MVRefresh*.java",
    "MaterializedViewRewriter.java",
    "MaterializedViewHandler.java",
    "Column.java",
    "ScalarType.java",
    "Type.java",
    "SchemaChangeJob*.java",
    "AlterJob*.java",
    "GlobalStateMgr.java",
    "StorageEngine.*",
    "config.h",
    "Config.java",
    "SessionVariable.java",
    "GlobalVariable.java",
    "*.thrift",
    "*.proto",
]

MEDIUM_TIER_PATHS = [
    "fe/fe-core/src/main/java/com/starrocks/connector/",
    "fe/fe-core/src/main/java/com/starrocks/authentication/",
    "fe/fe-core/src/main/java/com/starrocks/privilege/",
    "fe/fe-core/src/main/java/com/starrocks/sql/parser/",
    "fe/fe-core/src/main/java/com/starrocks/scheduler/",
    "fe/fe-core/src/main/java/com/starrocks/common/",
    "be/src/exprs/",
    "be/src/column/",
    "be/src/connector/",
    "be/src/http/",
]

SKIP_PATHS = [
    "fe/fe-core/src/test/",
    "be/src/test/",
    "docs/",
    ".github/",
    "testlibs/",
]

SKIP_PREFIXES = {"build", "chore", "ci", "style", "revert", "test", "docs"}

SCANNER_PATTERNS = {
    "protocol": {
        "patterns": ["*.thrift", "*.proto"],
        "keywords": ["required", "optional", "struct", "enum", "service", "rpc", "message"],
        "risk": "medium",
        "impact": {"behavior": True, "rolling_upgrade": True},
    },
    "parser": {
        "patterns": ["StarRocksParser.g4", "StarRocksLex.jflex", "AstBuilder.java", "SqlParser.java", "*.cup", "*.jflex"],
        "keywords": ["ALTER", "DROP", "CREATE", "nonReserved", "reserved", "UNSUPPORTED", "DEPRECATED"],
        "risk": "medium",
        "impact": {"behavior": True},
    },
    "auth": {
        "patterns": ["AuthenticationManager.java", "PrivilegeManager.java", "AuthorizationMgr.java", "AccessController*.java"],
        "keywords": ["GRANT", "REVOKE", "privilege", "authentication", "role", "user", "password", "LDAP", "OIDC"],
        "risk": "medium",
        "impact": {"operational": True},
    },
    "storage_format": {
        "patterns": ["segment_format*.h", "tablet_meta*.h", "storage_types.h", "rowset/*.cpp", "rowset/segment*.cpp"],
        "keywords": ["VERSION", "FORMAT", "ENCODING", "COMPRESSION", "TABLET_FORMAT_VERSION", "ROWSET_VERSION"],
        "risk": "critical",
        "impact": {"data": True, "behavior": True, "operational": True, "rolling_upgrade": True},
    },
    "charset_collation": {
        "patterns": ["Collation*.java", "Charset*.java", "charset*.java"],
        "keywords": ["utf8", "utf8mb4", "collation", "binary", "unicode", "general_ci"],
        "risk": "medium",
        "impact": {"data": True, "behavior": True},
    },
    "mv": {
        "patterns": ["MaterializedView*.java", "MVRefresh*.java", "MaterializedViewRewriter.java", "TaskRun.java"],
        "keywords": ["MaterializedView", "refresh", "rewrite", "partition", "onReload", "setActive", "clearVisibleVersionMap"],
        "risk": "high",
        "impact": {"data": True, "behavior": True, "operational": True},
    },
    "type_system": {
        "patterns": ["Type.java", "ScalarType.java", "Column.java", "ColumnRefOperator.java", "AnalyzerUtils.java"],
        "keywords": ["varchar", "string", "CHAR", "isCompatible", "schema", "transformTableColumnType"],
        "risk": "high",
        "impact": {"data": True, "behavior": True},
    },
}

FEATURE_IMPACT_RULES = [
    {
        "id": "insert_timeout_controls_insert_like_tasks",
        "introduced_title": "INSERT-like task timeout is introduced with insert_timeout",
        "changed_title": "INSERT-like task timeout behavior changed",
        "risk": "high",
        "impact": {"data": False, "behavior": True, "operational": True, "rolling_upgrade": False},
        "patterns": [
            "fe/fe-core/src/main/java/com/starrocks/qe/SessionVariable.java",
            "fe/fe-core/src/main/java/com/starrocks/qe/ConnectContext.java",
            "fe/fe-core/src/main/java/com/starrocks/qe/StmtExecutor.java",
            "fe/fe-core/src/main/java/com/starrocks/transaction/TransactionStmtExecutor.java",
            "fe/fe-core/src/main/java/com/starrocks/scheduler/PartitionBasedMvRefreshProcessor.java",
            "fe/fe-core/src/main/java/com/starrocks/scheduler/TaskRun.java",
            "fe/fe-core/src/main/java/com/starrocks/load/pipe/**",
            "fe/fe-core/src/main/java/com/starrocks/statistic/**",
            "fe/fe-core/src/main/java/com/starrocks/alter/**",
            "fe/fe-core/src/main/java/com/starrocks/common/util/PropertyAnalyzer.java",
        ],
        "presence_patterns": [
            "fe/fe-core/src/main/java/com/starrocks/qe/SessionVariable.java",
            "fe/fe-core/src/main/java/com/starrocks/qe/ConnectContext.java",
            "fe/fe-core/src/main/java/com/starrocks/qe/StmtExecutor.java",
            "fe/fe-core/src/main/java/com/starrocks/transaction/TransactionStmtExecutor.java",
            "fe/fe-core/src/main/java/com/starrocks/scheduler/PartitionBasedMvRefreshProcessor.java",
            "fe/fe-core/src/main/java/com/starrocks/scheduler/TaskRun.java",
            "fe/fe-core/src/main/java/com/starrocks/load/pipe/**",
        ],
        "keywords": [
            "insert_timeout",
            "INSERT_TIMEOUT",
            "setInsertTimeout",
            "MV_SESSION_INSERT_TIMEOUT",
            "isExecLoadType",
            "task.insert_timeout",
        ],
        "presence_keywords": [
            "INSERT_TIMEOUT",
            "\"insert_timeout\"",
            "insertTimeoutS",
            "MV_SESSION_INSERT_TIMEOUT",
            "task.insert_timeout",
        ],
        "change_keywords": [
            "insertTimeoutS",
            "setInsertTimeoutS",
            "setInsertTimeout",
            "isExecLoadType",
            "MV_SESSION_INSERT_TIMEOUT",
            "task.insert_timeout",
            "@VariableMgr.VarAttr(name = INSERT_TIMEOUT)",
        ],
        "before_behavior": "INSERT-like tasks may have followed query_timeout in the older version.",
        "now_behavior": "Target code defines insert_timeout and uses it in INSERT/load-like execution paths; default is commonly 14400 seconds when present.",
        "changed_behavior": "Both versions already define insert_timeout; target changed related timeout defaults, routing, task properties, or execution paths and needs source review.",
        "trigger": "INSERT/UPDATE/DELETE/CTAS, materialized view refresh, statistics collection, PIPE, or task properties that previously tuned query_timeout only.",
        "impact_hint": "Old query_timeout tuning may no longer control these jobs. Jobs can wait longer than expected, time out differently, or require session/task/MV property changes.",
        "handling_hint": "Check SHOW VARIABLES, user properties, MV properties, PIPE/task properties and SQL hints. Set insert_timeout explicitly where these jobs need a non-default timeout.",
    },
    {
        "id": "stream_load_merge_commit_feature",
        "introduced_title": "Stream Load merge_commit/batch write path is introduced",
        "changed_title": "Stream Load merge_commit/batch write behavior changed",
        "risk": "high",
        "impact": {"data": False, "behavior": True, "operational": True, "rolling_upgrade": True},
        "patterns": [
            "fe/fe-core/src/main/java/com/starrocks/load/batchwrite/**",
            "fe/fe-core/src/main/java/com/starrocks/load/streamload/**",
            "fe/fe-core/src/main/java/com/starrocks/common/Config.java",
            "be/src/http/action/stream_load.cpp",
            "be/src/http/http_common.h",
            "be/src/runtime/batch_write/**",
            "be/src/runtime/stream_load/**",
            "be/src/runtime/exec_env.cpp",
            "be/src/common/config.h",
        ],
        "presence_patterns": [
            "fe/fe-core/src/main/java/com/starrocks/load/batchwrite/**",
            "fe/fe-core/src/main/java/com/starrocks/load/streamload/StreamLoadHttpHeader.java",
            "be/src/http/action/stream_load.cpp",
            "be/src/http/http_common.h",
            "be/src/runtime/batch_write/**",
            "be/src/runtime/exec_env.cpp",
            "be/src/common/config.h",
        ],
        "keywords": [
            "merge_commit",
            "enable_merge_commit",
            "merge_commit_async",
            "merge_commit_interval_ms",
            "merge_commit_parallel",
            "enable_batch_write",
            "batch write",
        ],
        "presence_keywords": [
            "HTTP_ENABLE_MERGE_COMMIT",
            "enable_merge_commit",
            "MergeCommitJob",
            "batch_write_mgr",
            "merge_commit_thread_pool",
        ],
        "change_keywords": [
            "HTTP_ENABLE_MERGE_COMMIT",
            "HTTP_MERGE_COMMIT_ASYNC",
            "HTTP_MERGE_COMMIT_INTERVAL_MS",
            "HTTP_MERGE_COMMIT_PARALLEL",
            "merge_commit_default_timeout_ms",
            "merge_commit_thread_pool",
            "merge_commit_txn_state",
            "enable_batch_write",
            "_handle_batch_write",
            "append_data",
            "subscribe_state",
        ],
        "before_behavior": "Older versions do not have the Stream Load merge_commit/batch write execution path.",
        "now_behavior": "Target code may accept Stream Load merge_commit headers and route requests through batch write / merge commit queues and transaction-state polling.",
        "changed_behavior": "Both versions already have merge_commit/batch write; target changed related headers, routing, queueing, timeout, transaction-state, or BE execution paths and needs source review.",
        "trigger": "Stream Load clients or connectors that set enable_merge_commit=true or related merge_commit headers/configs.",
        "impact_hint": "Merge commit can improve many small concurrent loads, but unsuitable workloads can see extra buffering, commit wait, queue pressure, or latency/performance regression.",
        "handling_hint": "Inventory Stream Load headers/client configs, verify batch size/concurrency/latency needs, pressure-test both enabled and disabled paths, and keep a rollback switch to stop setting enable_merge_commit.",
    },
]

PUBLIC_SURFACE_RULES = [
    {
        "surface": "http_header",
        "risk": "medium",
        "impact": {"data": False, "behavior": True, "operational": True, "rolling_upgrade": False},
        "patterns": [
            "be/src/http/**",
            "fe/fe-core/src/main/java/com/starrocks/http/**",
            "fe/fe-core/src/main/java/com/starrocks/load/streamload/**",
        ],
        "regexes": [
            r'(?:static\s+const\s+std::string|public\s+static\s+final\s+String)\s+(HTTP_[A-Z0-9_]+)\s*=\s*"([^"]+)"',
        ],
    },
    {
        "surface": "sql_or_task_property",
        "risk": "medium",
        "impact": {"data": False, "behavior": True, "operational": True, "rolling_upgrade": False},
        "patterns": [
            "fe/fe-core/src/main/java/com/starrocks/common/util/PropertyAnalyzer.java",
            "fe/fe-core/src/main/java/com/starrocks/sql/ast/**",
            "fe/fe-core/src/main/java/com/starrocks/load/**",
            "fe/fe-core/src/main/java/com/starrocks/scheduler/**",
            "fe/fe-core/src/main/java/com/starrocks/alter/**",
        ],
        "regexes": [
            r'(?:public\s+)?(?:static\s+)?(?:final\s+)?String\s+([A-Z0-9_]*(?:PROPERTY|PROPERTIES)[A-Z0-9_]*)\s*=\s*"([^"]+)"',
            r'(?:public\s+static\s+final\s+String|private\s+static\s+final\s+String)\s+([A-Z0-9_]+)\s*=\s*"((?:session|task|properties?)\.[^"]+)"',
        ],
    },
    {
        "surface": "sql_grammar_keyword",
        "risk": "medium",
        "impact": {"data": False, "behavior": True, "operational": False, "rolling_upgrade": False},
        "patterns": [
            "fe/fe-core/src/main/java/com/starrocks/sql/parser/*.g4",
        ],
        "regexes": [
            r"^\s*([A-Z][A-Z0-9_]{2,})\s*:",
        ],
        "keyword_filter": {
            "ADD",
            "ALTER",
            "CREATE",
            "DROP",
            "INSERT",
            "SELECT",
            "TABLE",
            "WHERE",
            "FROM",
            "TRUE",
            "FALSE",
            "NULL",
        },
    },
]

SOURCE_DOMAIN_RULES = [
    {
        "domain": "config_and_variables",
        "risk": "high",
        "impact": {"data": False, "behavior": True, "operational": True, "rolling_upgrade": False},
        "patterns": [
            "fe/fe-core/src/main/java/com/starrocks/common/Config.java",
            "fe/fe-core/src/main/java/com/starrocks/qe/SessionVariable.java",
            "fe/fe-core/src/main/java/com/starrocks/qe/GlobalVariable.java",
            "fe/fe-core/src/main/java/com/starrocks/qe/SysVariable.java",
            "fe/fe-core/src/main/java/com/starrocks/qe/VariableMgr.java",
            "be/src/common/config.h",
        ],
    },
    {
        "domain": "materialized_view",
        "risk": "high",
        "impact": {"data": True, "behavior": True, "operational": True, "rolling_upgrade": True},
        "patterns": [
            "fe/fe-core/src/main/java/com/starrocks/catalog/MaterializedView*.java",
            "fe/fe-core/src/main/java/com/starrocks/alter/*MV*.java",
            "fe/fe-core/src/main/java/com/starrocks/scheduler/*MV*.java",
            "fe/fe-core/src/main/java/com/starrocks/sql/optimizer/*/*MaterializedView*.java",
            "fe/fe-core/src/main/java/com/starrocks/sql/optimizer/rule/transformation/materialization/**",
        ],
    },
    {
        "domain": "optimizer_planner",
        "risk": "medium",
        "impact": {"data": False, "behavior": True, "operational": True, "rolling_upgrade": False},
        "patterns": [
            "fe/fe-core/src/main/java/com/starrocks/sql/optimizer/**",
            "fe/fe-core/src/main/java/com/starrocks/planner/**",
            "fe/fe-core/src/main/java/com/starrocks/sql/plan/**",
            "fe/fe-core/src/main/java/com/starrocks/sql/analyzer/**",
        ],
    },
    {
        "domain": "execution_runtime",
        "risk": "medium",
        "impact": {"data": False, "behavior": True, "operational": True, "rolling_upgrade": True},
        "patterns": [
            "fe/fe-core/src/main/java/com/starrocks/execution/**",
            "be/src/runtime/**",
            "be/src/exec/**",
            "be/src/pipeline/**",
            "be/src/exprs/**",
            "be/src/vec/**",
        ],
    },
    {
        "domain": "storage_format",
        "risk": "critical",
        "impact": {"data": True, "behavior": True, "operational": True, "rolling_upgrade": True},
        "patterns": [
            "be/src/storage/**",
            "be/src/olap/**",
            "be/src/column/**",
            "be/src/serde/**",
            "be/src/types/**",
            "be/src/fs/**",
            "be/src/io/**",
        ],
    },
    {
        "domain": "cache_datacache",
        "risk": "high",
        "impact": {"data": False, "behavior": True, "operational": True, "rolling_upgrade": True},
        "patterns": [
            "be/src/cache/**",
            "be/src/block_cache/**",
            "be/src/datacache/**",
            "be/src/storage/lake/persistent_index_cache.*",
        ],
    },
    {
        "domain": "file_formats_io",
        "risk": "medium",
        "impact": {"data": True, "behavior": True, "operational": True, "rolling_upgrade": False},
        "patterns": ["be/src/formats/**"],
    },
    {
        "domain": "metadata_catalog_schema",
        "risk": "high",
        "impact": {"data": True, "behavior": True, "operational": True, "rolling_upgrade": True},
        "patterns": [
            "fe/fe-core/src/main/java/com/starrocks/catalog/**",
            "fe/fe-core/src/main/java/com/starrocks/server/**",
            "fe/fe-core/src/main/java/com/starrocks/persist/**",
            "fe/fe-core/src/main/java/com/starrocks/alter/**",
            "fe/fe-core/src/main/java/com/starrocks/lake/**",
            "fe/fe-core/src/main/java/com/starrocks/warehouse/**",
        ],
    },
    {
        "domain": "transaction_load",
        "risk": "high",
        "impact": {"data": True, "behavior": True, "operational": True, "rolling_upgrade": True},
        "patterns": [
            "fe/fe-core/src/main/java/com/starrocks/transaction/**",
            "fe/fe-core/src/main/java/com/starrocks/load/**",
            "fe/fe-core/src/main/java/com/starrocks/load/loadv2/**",
            "fe/fe-core/src/main/java/com/starrocks/http/**",
            "be/src/runtime/load_channel*",
            "be/src/runtime/tablets_channel*",
            "be/src/service/*load*",
            "be/src/http/**",
        ],
    },
    {
        "domain": "protocol_rpc",
        "risk": "high",
        "impact": {"data": False, "behavior": True, "operational": True, "rolling_upgrade": True},
        "patterns": ["gensrc/thrift/**", "gensrc/proto/**", "be/src/service/**", "fe/fe-core/src/main/java/com/starrocks/service/**"],
    },
    {
        "domain": "sql_parser",
        "risk": "medium",
        "impact": {"data": False, "behavior": True, "operational": False, "rolling_upgrade": False},
        "patterns": [
            "fe/fe-core/src/main/java/com/starrocks/sql/parser/**",
            "fe/fe-core/src/main/cup/**",
            "fe/fe-core/src/main/jflex/**",
        ],
    },
    {
        "domain": "connector_external_catalog",
        "risk": "medium",
        "impact": {"data": False, "behavior": True, "operational": True, "rolling_upgrade": False},
        "patterns": [
            "fe/fe-core/src/main/java/com/starrocks/connector/**",
            "be/src/connector/**",
            "be/src/formats/**",
        ],
    },
    {
        "domain": "connector_iceberg",
        "risk": "high",
        "impact": {"data": True, "behavior": True, "operational": True, "rolling_upgrade": False},
        "patterns": [
            "fe/fe-core/src/main/java/com/starrocks/connector/iceberg/**",
            "fe/fe-core/src/main/java/com/starrocks/connector/metadata/iceberg/**",
            "fe/fe-core/src/main/java/com/starrocks/server/IcebergTableFactory.java",
            "fe/fe-core/src/main/java/com/starrocks/sql/optimizer/**/*Iceberg*.java",
            "be/src/exec/iceberg/**",
            "be/src/runtime/iceberg_table_sink.*",
            "java-extensions/hadoop-ext/src/main/java/com/starrocks/connector/share/iceberg/**",
        ],
    },
    {
        "domain": "connector_paimon",
        "risk": "high",
        "impact": {"data": True, "behavior": True, "operational": True, "rolling_upgrade": False},
        "patterns": [
            "fe/fe-core/src/main/java/com/starrocks/connector/paimon/**",
            "fe/fe-core/src/main/java/com/starrocks/sql/optimizer/**/*Paimon*.java",
            "be/src/exec/paimon/**",
        ],
    },
    {
        "domain": "auth_privilege_security",
        "risk": "medium",
        "impact": {"data": False, "behavior": True, "operational": True, "rolling_upgrade": False},
        "patterns": [
            "fe/fe-core/src/main/java/com/starrocks/authentication/**",
            "fe/fe-core/src/main/java/com/starrocks/privilege/**",
            "fe/fe-core/src/main/java/com/starrocks/authorization/**",
        ],
    },
    {
        "domain": "scheduler_task",
        "risk": "medium",
        "impact": {"data": False, "behavior": True, "operational": True, "rolling_upgrade": True},
        "patterns": [
            "fe/fe-core/src/main/java/com/starrocks/scheduler/**",
            "fe/fe-core/src/main/java/com/starrocks/task/**",
            "fe/fe-core/src/main/java/com/starrocks/statistic/**",
        ],
    },
]


def run_cmd(cmd: list[str], cwd: str | Path | None = None, timeout: int = 120, check: bool = False) -> str | None:
    try:
        result = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"[WARN] command error: {exc}", file=sys.stderr)
        return None
    if result.returncode != 0:
        if check:
            print(f"[WARN] command failed: {' '.join(cmd)}", file=sys.stderr)
            if result.stderr:
                print(result.stderr.strip(), file=sys.stderr)
        return None
    return result.stdout.strip()


def save_json(data: Any, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def extract_pr_numbers(text: str | None) -> list[int]:
    if not text:
        return []
    return sorted({int(m) for m in PR_PATTERN.findall(text)})


def ref_exists(repo: Path, ref: str) -> bool:
    return run_cmd(["git", "rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=repo) is not None


def resolve_ref(repo: Path, value: str, is_version: bool = False) -> dict[str, Any]:
    candidates = [value]
    if is_version:
        parts = value.split(".")
        major_minor = ".".join(parts[:2]) if len(parts) >= 2 else value
        candidates.extend(
            [
                f"v{value}",
                f"branch-{value}",
                f"upstream/branch-{value}",
                f"origin/branch-{value}",
                f"remotes/upstream/branch-{value}",
                f"remotes/origin/branch-{value}",
                f"branch-{major_minor}",
                f"upstream/branch-{major_minor}",
                f"origin/branch-{major_minor}",
                f"remotes/upstream/branch-{major_minor}",
                f"remotes/origin/branch-{major_minor}",
            ]
        )
    seen = []
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.append(candidate)
        if ref_exists(repo, candidate):
            sha = run_cmd(["git", "rev-parse", f"{candidate}^{{commit}}"], cwd=repo) or ""
            return {"input": value, "resolved": candidate, "sha": sha, "candidates": seen}
    raise SystemExit(f"[ERROR] Cannot resolve ref/version '{value}'. Tried: {', '.join(seen)}")


def get_commits(repo: Path, left: str, right: str) -> list[dict[str, Any]]:
    output = run_cmd(
        ["git", "log", f"--format={GIT_LOG_FORMAT}", "--no-merges", f"{left}..{right}"],
        cwd=repo,
        timeout=300,
        check=True,
    )
    if not output:
        return []
    commits: list[dict[str, Any]] = []
    for record in output.split(REC_SEP):
        if not record.strip():
            continue
        fields = record.split(FIELD_SEP)
        if len(fields) < 5:
            continue
        commit_hash, author, date, subject, body = [f.strip() for f in fields[:5]]
        commits.append(
            {
                "hash": commit_hash,
                "author": author,
                "date": date,
                "subject": subject,
                "body": body,
                "pr_numbers": extract_pr_numbers(subject + " " + body),
            }
        )
    return commits


def changed_files_between(repo: Path, left: str, right: str) -> list[str]:
    output = run_cmd(["git", "diff", "--name-only", f"{left}..{right}"], cwd=repo, timeout=300)
    if not output:
        return []
    return [line.strip() for line in output.splitlines() if line.strip()]


def diff_numstat(repo: Path, left: str, right: str) -> dict[str, dict[str, int | None]]:
    output = run_cmd(["git", "diff", "--numstat", f"{left}..{right}"], cwd=repo, timeout=300)
    stats: dict[str, dict[str, int | None]] = {}
    if not output:
        return stats
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        added_raw, removed_raw, path = parts[0], parts[1], parts[2]
        stats[path] = {
            "added": None if added_raw == "-" else int(added_raw),
            "removed": None if removed_raw == "-" else int(removed_raw),
        }
    return stats


def path_matches_any_pattern(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)


def merge_impact(base: dict[str, bool], extra: dict[str, bool]) -> dict[str, bool]:
    merged = dict(base)
    for key, value in extra.items():
        merged[key] = bool(merged.get(key)) or bool(value)
    return merged


def classify_source_domains(changed_files: list[str], numstat: dict[str, dict[str, int | None]]) -> dict[str, Any]:
    domains: dict[str, dict[str, Any]] = {}
    unmatched = []
    risk_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    for file_path in changed_files:
        matched = False
        for rule in SOURCE_DOMAIN_RULES:
            if not path_matches_any_pattern(file_path, rule["patterns"]):
                continue
            matched = True
            domain = str(rule["domain"])
            existing = domains.setdefault(
                domain,
                {
                    "domain": domain,
                    "risk": "low",
                    "impact": {"data": False, "behavior": False, "operational": False, "rolling_upgrade": False},
                    "files": [],
                    "file_count": 0,
                    "added": 0,
                    "removed": 0,
                    "binary_or_unknown_files": 0,
                },
            )
            if risk_rank[str(rule["risk"])] > risk_rank[str(existing["risk"])]:
                existing["risk"] = rule["risk"]
            existing["impact"] = merge_impact(existing["impact"], rule["impact"])
            stat = numstat.get(file_path, {})
            added = stat.get("added")
            removed = stat.get("removed")
            if added is None or removed is None:
                existing["binary_or_unknown_files"] += 1
            else:
                existing["added"] += added
                existing["removed"] += removed
            existing["files"].append(file_path)
        if not matched and not path_matches(file_path, SKIP_PATHS):
            unmatched.append(file_path)
    for value in domains.values():
        value["files"] = sorted(value["files"])
        value["file_count"] = len(value["files"])
    ordered = sorted(domains.values(), key=lambda item: (risk_rank[str(item["risk"])], item["file_count"]), reverse=True)
    return {
        "domains": ordered,
        "unmatched_source_files": sorted(unmatched),
        "summary": {
            "domain_count": len(ordered),
            "critical_or_high_domains": len([d for d in ordered if d["risk"] in {"critical", "high"}]),
            "unmatched_source_files": len(unmatched),
        },
    }


def changed_files_for_commit(repo: Path, commit_hash: str) -> list[str]:
    output = run_cmd(["git", "show", "--name-only", "--format=", commit_hash], cwd=repo, timeout=60)
    if not output:
        return []
    return [line.strip() for line in output.splitlines() if line.strip()]


def get_diff(repo: Path, left: str, right: str, file_path: str | None = None, max_lines: int = 400) -> str:
    cmd = ["git", "diff", f"{left}..{right}"]
    if file_path:
        cmd.extend(["--", file_path])
    output = run_cmd(cmd, cwd=repo, timeout=120) or ""
    lines = output.splitlines()
    if len(lines) > max_lines:
        return "\n".join(lines[:max_lines]) + f"\n... truncated {len(lines) - max_lines} lines"
    return output


def get_commit_diff(repo: Path, commit_hash: str, max_lines: int = 800) -> str:
    output = run_cmd(["git", "show", "--format=", commit_hash], cwd=repo, timeout=120) or ""
    lines = output.splitlines()
    if len(lines) > max_lines:
        return "\n".join(lines[:max_lines]) + f"\n... truncated {len(lines) - max_lines} lines"
    return output


def path_matches(path: str, prefixes: list[str]) -> bool:
    return any(path.startswith(prefix) for prefix in prefixes)


def basename_matches(path: str, patterns: list[str]) -> bool:
    base = os.path.basename(path)
    return any(fnmatch.fnmatch(base, pattern) for pattern in patterns)


def classify_commit(commit: dict[str, Any], files: list[str]) -> tuple[str, str]:
    subject = commit.get("subject", "")
    match = re.match(r"^(\w+)(?:\(.*?\))?(!)?:\s", subject)
    prefix = match.group(1).lower() if match else ""
    if prefix in SKIP_PREFIXES:
        return "SKIP", f"commit type: {prefix}"
    if files and all(path_matches(f, SKIP_PATHS) for f in files):
        return "SKIP", "only test/docs/build paths"
    reasons = []
    for file_path in files:
        if path_matches(file_path, HIGH_TIER_PATHS):
            reasons.append("core path")
        if basename_matches(file_path, HIGH_TIER_FILES):
            reasons.append(f"critical file: {os.path.basename(file_path)}")
    if reasons:
        return "HIGH", "; ".join(sorted(set(reasons)))
    medium = []
    for file_path in files:
        if path_matches(file_path, MEDIUM_TIER_PATHS):
            medium.append("business path")
    if prefix in {"feat", "fix"} and any(f.endswith((".java", ".cpp", ".h", ".hpp", ".py", ".g4")) for f in files):
        medium.append("feat/fix source change")
    if medium:
        return "MEDIUM", "; ".join(sorted(set(medium)))
    return "LOW", "non-core change"


def classify_commits(repo: Path, commits: list[dict[str, Any]], output_dir: Path, label: str, save_diffs: bool) -> dict[str, Any]:
    detail_dir = output_dir / "commits" / "detail"
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "SKIP": 0}
    metas = []
    for i, commit in enumerate(commits, start=1):
        files = changed_files_for_commit(repo, commit["hash"])
        tier, reason = classify_commit(commit, files)
        counts[tier] += 1
        meta = {
            "hash": commit["hash"],
            "subject": commit["subject"],
            "author": commit.get("author", ""),
            "date": commit.get("date", ""),
            "pr_numbers": commit.get("pr_numbers", []),
            "tier": tier,
            "tier_reason": reason,
            "changed_files": files,
        }
        if save_diffs and tier in {"HIGH", "MEDIUM"}:
            detail_dir.mkdir(parents=True, exist_ok=True)
            diff_file = detail_dir / f"{commit['hash']}-diff.txt"
            diff_file.write_text(get_commit_diff(repo, commit["hash"]), encoding="utf-8")
            meta["diff_file"] = f"detail/{commit['hash']}-diff.txt"
        metas.append(meta)
    meta_path = output_dir / "commits" / f"tiered-{safe_label(label)}.json"
    save_json(metas, meta_path)
    return {"tier_counts": counts, "commit_metas": metas, "meta_file": str(meta_path.relative_to(output_dir))}


def safe_label(label: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", label)


def file_at_ref(repo: Path, ref: str, path: str) -> str | None:
    return run_cmd(["git", "show", f"{ref}:{path}"], cwd=repo, timeout=120)


def strip_inline_comment(value: str) -> str:
    return re.sub(r"\s+//.*$", "", value).strip()


def parse_java_string_constants(content: str | None) -> dict[str, str]:
    if not content:
        return {}
    constants: dict[str, str] = {}
    pattern = re.compile(
        r"(?:public|private|protected)?\s*static\s+final\s+String\s+(\w+)\s*=\s*(.+?);",
        re.S,
    )
    for match in pattern.finditer(content):
        name, expr = match.groups()
        string_parts = re.findall(r'"([^"]*)"', expr)
        if string_parts:
            constants[name] = "".join(string_parts)
        else:
            ref = expr.strip()
            if ref in constants:
                constants[name] = constants[ref]
    changed = True
    while changed:
        changed = False
        for match in pattern.finditer(content):
            name, expr = match.groups()
            ref = expr.strip()
            if name not in constants and ref in constants:
                constants[name] = constants[ref]
                changed = True
    return constants


def parse_annotation_attr(annotation: str, attr: str) -> str | None:
    match = re.search(rf"\b{re.escape(attr)}\s*=\s*([^,)]+)", annotation)
    if not match:
        return None
    return match.group(1).strip()


def resolve_java_attr_value(token: str | None, constants: dict[str, str]) -> str | None:
    if not token:
        return None
    token = token.strip()
    if len(token) >= 2 and token[0] == token[-1] == '"':
        return token[1:-1]
    if token in constants:
        return constants[token]
    if "." in token:
        short_name = token.rsplit(".", 1)[-1]
        if short_name in constants:
            return constants[short_name]
    return token


def parse_flag_names(flag: str | None) -> list[str]:
    if not flag:
        return []
    return sorted(set(re.findall(r"VariableMgr\.(\w+)", flag) + re.findall(r"\b(SESSION_ONLY|GLOBAL|READ_ONLY|INVISIBLE|DISABLE_FORWARD_TO_LEADER)\b", flag)))


def parse_java_fields_with_annotation(content: str | None, annotation_name: str) -> dict[str, dict[str, Any]]:
    if not content:
        return {}
    fields: dict[str, dict[str, Any]] = {}
    constants = parse_java_string_constants(content)
    wanted_annotation = annotation_name.lstrip("@")
    annotation = ""
    in_annotation = False
    deprecated = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "@Deprecated":
            deprecated = True
            continue
        if stripped.startswith("@") and wanted_annotation in stripped:
            annotation = stripped
            in_annotation = "(" in stripped and ")" not in stripped
            continue
        if in_annotation:
            annotation += " " + stripped
            if ")" in stripped:
                in_annotation = False
            continue
        match = re.match(
            r"\s*(?:(?:public|private|protected)\s+)?(?:(?:static|final)\s+)*([\w<>.?]+)\s+(\w+)\s*=\s*(.+?);",
            stripped,
        )
        if match:
            if not annotation:
                deprecated = False
                continue
            typ, name, raw_value = match.groups()
            mutable = None
            ann_name = None
            alias = None
            show_name = None
            flag = None
            comment = None
            if annotation:
                mutable_match = re.search(r"mutable\s*=\s*(true|false)", annotation)
                if mutable_match:
                    mutable = mutable_match.group(1) == "true"
                ann_name = resolve_java_attr_value(parse_annotation_attr(annotation, "name"), constants)
                alias = resolve_java_attr_value(parse_annotation_attr(annotation, "alias"), constants)
                show_name = resolve_java_attr_value(parse_annotation_attr(annotation, "show"), constants)
                flag = parse_annotation_attr(annotation, "flag")
                comment_match = re.search(r'comment\s*=\s*"([^"]*)"', annotation)
                if comment_match:
                    comment = comment_match.group(1)
            public_name = show_name or ann_name or name
            fields[public_name] = {
                "type": typ,
                "field_name": name,
                "value": strip_inline_comment(raw_value),
                "mutable": mutable,
                "annotation_name": ann_name,
                "alias": alias,
                "show_name": show_name,
                "flag": flag,
                "flag_names": parse_flag_names(flag),
                "comment": comment,
                "deprecated": deprecated,
            }
            annotation = ""
            deprecated = False
        elif stripped and not stripped.startswith("//") and not stripped.startswith("@"):
            annotation = ""
            deprecated = False
    return fields


def parse_be_config(content: str | None) -> dict[str, dict[str, Any]]:
    if not content:
        return {}
    configs = {}
    pattern = re.compile(r"CONF_(m?\w+)\((\w+),\s*(?:/\*.*?\*/\s*)?\"([^\"]*)\"", re.S)
    for match in pattern.finditer(content):
        macro_type, name, value = match.groups()
        configs[name] = {"type": macro_type, "value": value, "mutable": macro_type.startswith("m")}
    return configs


def normalize_value(value: Any) -> str:
    if value is None:
        return ""
    val = str(value).strip().rstrip(";").strip()
    val = re.sub(r"(?<=\d)[Llfd]$", "", val)
    if len(val) >= 2 and ((val[0] == val[-1] == '"') or (val[0] == val[-1] == "'")):
        val = val[1:-1]
    return val.strip()


def risk_for_name(name: str, old_value: str | None = None, new_value: str | None = None, removed: bool = False) -> str:
    name = name.lower()
    if removed:
        return "high"
    if any(token == name or token in name or name in token for token in HIGH_RISK_NAMES):
        return "high"
    if old_value in {"true", "false"} and new_value in {"true", "false"} and old_value != new_value:
        return "medium"
    return "low"


def impact_for_name(name: str, extra: dict[str, bool] | None = None) -> dict[str, bool]:
    name = name.lower()
    impact = {
        "data": any(token == name or token in name or name in token for token in DATA_IMPACT_NAMES),
        "behavior": any(token == name or token in name or name in token for token in BEHAVIOR_IMPACT_NAMES),
        "operational": any(token == name or token in name or name in token for token in HIGH_RISK_NAMES),
        "rolling_upgrade": False,
    }
    if extra:
        impact.update(extra)
    return impact


def field_metadata(field: dict[str, Any]) -> dict[str, Any]:
    return {
        "field_name": field.get("field_name"),
        "annotation_name": field.get("annotation_name"),
        "alias": field.get("alias"),
        "show_name": field.get("show_name"),
        "flag": field.get("flag"),
        "flag_names": field.get("flag_names", []),
        "mutable": field.get("mutable"),
        "deprecated": field.get("deprecated"),
    }


def compare_field_maps(old: dict[str, dict[str, Any]], new: dict[str, dict[str, Any]], source: str, file_path: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for name in sorted(set(old) & set(new)):
        if normalize_value(old[name]["value"]) != normalize_value(new[name]["value"]):
            risk = risk_for_name(name, normalize_value(old[name]["value"]), normalize_value(new[name]["value"]))
            if new[name].get("mutable") is False and risk == "low":
                risk = "medium"
            findings.append(
                {
                    "type": f"{source}_changed",
                    "name": name,
                    "file": file_path,
                    "old_value": old[name]["value"],
                    "new_value": new[name]["value"],
                    "value_type": old[name].get("type"),
                    "old_metadata": field_metadata(old[name]),
                    "new_metadata": field_metadata(new[name]),
                    "mutable": new[name].get("mutable"),
                    "risk": risk,
                    "impact": impact_for_name(name),
                }
            )
        if old[name].get("mutable") != new[name].get("mutable") and old[name].get("mutable") is not None:
            findings.append(
                {
                    "type": f"{source}_mutability_changed",
                    "name": name,
                    "file": file_path,
                    "old_mutable": old[name].get("mutable"),
                    "new_mutable": new[name].get("mutable"),
                    "old_metadata": field_metadata(old[name]),
                    "new_metadata": field_metadata(new[name]),
                    "risk": "medium",
                    "impact": {"data": False, "behavior": False, "operational": True, "rolling_upgrade": False},
                }
            )
        old_meta = field_metadata(old[name])
        new_meta = field_metadata(new[name])
        old_meta_without_mutable = {k: v for k, v in old_meta.items() if k != "mutable"}
        new_meta_without_mutable = {k: v for k, v in new_meta.items() if k != "mutable"}
        if old_meta_without_mutable != new_meta_without_mutable:
            changed_keys = sorted(
                key for key in set(old_meta_without_mutable) | set(new_meta_without_mutable)
                if old_meta_without_mutable.get(key) != new_meta_without_mutable.get(key)
            )
            risk = "high" if "flag_names" in changed_keys and {
                "READ_ONLY",
                "SESSION_ONLY",
                "GLOBAL",
                "INVISIBLE",
                "DISABLE_FORWARD_TO_LEADER",
            } & (set(old_meta.get("flag_names", [])) | set(new_meta.get("flag_names", []))) else "medium"
            findings.append(
                {
                    "type": f"{source}_metadata_changed",
                    "name": name,
                    "file": file_path,
                    "changed_metadata": changed_keys,
                    "old_metadata": old_meta,
                    "new_metadata": new_meta,
                    "risk": risk,
                    "impact": {"data": False, "behavior": True, "operational": True, "rolling_upgrade": False},
                }
            )
    for name in sorted(set(new) - set(old)):
        default = normalize_value(new[name].get("value"))
        if default in {"", "0", "null", "{}"}:
            continue
        risk = risk_for_name(name)
        findings.append(
            {
                "type": f"{source}_added",
                "name": name,
                "file": file_path,
                "new_value": new[name]["value"],
                "value_type": new[name].get("type"),
                "new_metadata": field_metadata(new[name]),
                "mutable": new[name].get("mutable"),
                "risk": risk,
                "impact": impact_for_name(name),
            }
        )
    for name in sorted(set(old) - set(new)):
        findings.append(
            {
                "type": f"{source}_removed",
                "name": name,
                "file": file_path,
                "old_value": old[name]["value"],
                "value_type": old[name].get("type"),
                "old_metadata": field_metadata(old[name]),
                "risk": "high",
                "impact": impact_for_name(name),
            }
        )
    return findings


def scan_configs(repo: Path, base_ref: str, target_ref: str) -> dict[str, list[dict[str, Any]]]:
    old_fe = parse_java_fields_with_annotation(file_at_ref(repo, base_ref, FE_CONFIG_PATH), "@ConfField")
    new_fe = parse_java_fields_with_annotation(file_at_ref(repo, target_ref, FE_CONFIG_PATH), "@ConfField")
    session_old = parse_java_fields_with_annotation(file_at_ref(repo, base_ref, SESSION_VARIABLE_PATH), "@VarAttr")
    session_new = parse_java_fields_with_annotation(file_at_ref(repo, target_ref, SESSION_VARIABLE_PATH), "@VarAttr")
    old_be = parse_be_config(file_at_ref(repo, base_ref, BE_CONFIG_PATH))
    new_be = parse_be_config(file_at_ref(repo, target_ref, BE_CONFIG_PATH))
    system_findings: list[dict[str, Any]] = []
    for path in GLOBAL_VARIABLE_PATHS:
        old_sys = parse_java_fields_with_annotation(file_at_ref(repo, base_ref, path), "@VarAttr")
        new_sys = parse_java_fields_with_annotation(file_at_ref(repo, target_ref, path), "@VarAttr")
        system_findings.extend(compare_field_maps(old_sys, new_sys, "system_variable", path))
    return {
        "fe_config": compare_field_maps(old_fe, new_fe, "fe_config", FE_CONFIG_PATH),
        "session_variable": compare_field_maps(session_old, session_new, "session_variable", SESSION_VARIABLE_PATH),
        "system_variable": system_findings,
        "be_config": compare_field_maps(old_be, new_be, "be_config", BE_CONFIG_PATH),
    }


def diff_changed_lines(diff: str) -> tuple[list[str], list[str]]:
    added, removed = [], []
    for line in diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:].strip())
        elif line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:].strip())
    return added, removed


def keyword_lines(lines: list[str], keywords: list[str], limit: int) -> list[str]:
    matched = []
    lowered_keywords = [kw.lower() for kw in keywords]
    for line in lines:
        lowered = line.lower()
        if any(keyword in lowered for keyword in lowered_keywords):
            matched.append(line)
            if len(matched) >= limit:
                break
    return matched


def non_comment_changed_lines(lines: list[str]) -> list[str]:
    result = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "/*", "*", "#")):
            continue
        result.append(line)
    return result


def files_at_ref_matching(repo: Path, ref: str, patterns: list[str]) -> list[str]:
    output = run_cmd(["git", "ls-tree", "-r", "--name-only", ref], cwd=repo, timeout=120) or ""
    files = [line.strip() for line in output.splitlines() if line.strip()]
    return [path for path in files if any(fnmatch.fnmatch(path, pattern) for pattern in patterns)]


def ref_contains_keywords(repo: Path, ref: str, patterns: list[str], keywords: list[str]) -> bool:
    for file_path in files_at_ref_matching(repo, ref, patterns):
        content = file_at_ref(repo, ref, file_path)
        if not content:
            continue
        lowered = content.lower()
        if any(keyword.lower() in lowered for keyword in keywords):
            return True
    return False


def literal_exists_at_ref(repo: Path, ref: str, literal: str, cache: dict[tuple[str, str], bool]) -> bool:
    key = (ref, literal)
    if key not in cache:
        output = run_cmd(["git", "grep", "-F", "-l", "-e", literal, ref, "--"], cwd=repo, timeout=120)
        cache[key] = bool(output)
    return cache[key]


def scan_pattern_findings(repo: Path, base_ref: str, target_ref: str, changed_files: list[str]) -> dict[str, list[dict[str, Any]]]:
    results: dict[str, list[dict[str, Any]]] = {}
    for scanner, spec in SCANNER_PATTERNS.items():
        scanner_results = []
        patterns = spec["patterns"]
        keywords = spec["keywords"]
        for file_path in changed_files:
            if path_matches(file_path, SKIP_PATHS):
                continue
            if not basename_matches(file_path, patterns) and not any(fnmatch.fnmatch(file_path, p) for p in patterns):
                continue
            diff = get_diff(repo, base_ref, target_ref, file_path)
            if not diff:
                continue
            added, removed = diff_changed_lines(diff)
            joined = "\n".join(added + removed)
            matched = sorted({kw for kw in keywords if kw.lower() in joined.lower()})
            if not matched:
                continue
            risk = str(spec["risk"])
            if scanner == "protocol":
                removed_required = [line for line in removed if "required" in line.lower()]
                removed_field = [line for line in removed if re.search(r"\b\d+\s*[:=]", line)]
                added_required = [line for line in added if "required" in line.lower()]
                if removed_required or removed_field:
                    risk = "critical"
                elif added_required:
                    risk = "high"
            scanner_results.append(
                {
                    "type": f"{scanner}_change",
                    "file": file_path,
                    "keywords": matched,
                    "risk": risk,
                    "impact": {
                        "data": bool(spec.get("impact", {}).get("data", False)),
                        "behavior": bool(spec.get("impact", {}).get("behavior", False)),
                        "operational": bool(spec.get("impact", {}).get("operational", False)),
                        "rolling_upgrade": bool(spec.get("impact", {}).get("rolling_upgrade", False)),
                    },
                    "lines_changed": len(added) + len(removed),
                    "diff_preview": "\n".join((removed + added)[:40]),
                }
            )
        results[scanner] = scanner_results
    return results


def scan_feature_impact_findings(repo: Path, base_ref: str, target_ref: str, changed_files: list[str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for rule in FEATURE_IMPACT_RULES:
        source_files = []
        matched_keywords: set[str] = set()
        matched_change_keywords: set[str] = set()
        diff_previews = []
        lines_changed = 0
        base_present = ref_contains_keywords(repo, base_ref, rule["presence_patterns"], rule["presence_keywords"])
        target_present = ref_contains_keywords(repo, target_ref, rule["presence_patterns"], rule["presence_keywords"])
        if not target_present:
            continue
        for file_path in changed_files:
            if path_matches(file_path, SKIP_PATHS):
                continue
            if not any(fnmatch.fnmatch(file_path, pattern) for pattern in rule["patterns"]):
                continue
            diff = get_diff(repo, base_ref, target_ref, file_path)
            if not diff:
                continue
            added, removed = diff_changed_lines(diff)
            joined = "\n".join(added + removed)
            file_keywords = sorted({kw for kw in rule["keywords"] if kw.lower() in joined.lower()})
            if not file_keywords:
                continue
            semantic_joined = "\n".join(non_comment_changed_lines(added + removed))
            file_change_keywords = sorted({kw for kw in rule["change_keywords"] if kw.lower() in semantic_joined.lower()})
            source_files.append(file_path)
            matched_keywords.update(file_keywords)
            matched_change_keywords.update(file_change_keywords)
            lines_changed += len(added) + len(removed)
            if len(diff_previews) < 60:
                diff_previews.extend(keyword_lines(removed + added, file_keywords, max(0, 60 - len(diff_previews))))
        if not source_files:
            continue
        if not base_present:
            change_type = "feature_introduced"
            title = rule["introduced_title"]
            before_behavior = rule["before_behavior"]
            now_behavior = rule["now_behavior"]
        else:
            if not matched_change_keywords:
                continue
            change_type = "feature_behavior_changed"
            title = rule["changed_title"]
            before_behavior = "Both compared versions already contain this feature surface."
            now_behavior = rule["changed_behavior"]
        findings.append(
            {
                "type": change_type,
                "id": rule["id"],
                "name": title,
                "risk": rule["risk"],
                "impact": rule["impact"],
                "base_feature_present": base_present,
                "target_feature_present": target_present,
                "files": sorted(source_files),
                "keywords": sorted(matched_keywords),
                "change_keywords": sorted(matched_change_keywords),
                "lines_changed": lines_changed,
                "before_behavior": before_behavior,
                "now_behavior": now_behavior,
                "trigger": rule["trigger"],
                "impact_hint": rule["impact_hint"],
                "handling_hint": rule["handling_hint"],
                "diff_preview": "\n".join(diff_previews),
            }
        )
    return findings


def extract_public_surface_values(line: str, rule: dict[str, Any]) -> list[dict[str, str]]:
    values = []
    ignored = set(rule.get("keyword_filter", set()))
    for regex in rule["regexes"]:
        for match in re.finditer(regex, line):
            if len(match.groups()) >= 2:
                symbol, value = match.group(1), match.group(2)
            else:
                symbol = match.group(1)
                value = symbol.lower()
            if symbol in ignored:
                continue
            if len(value) <= 1:
                continue
            values.append({"symbol": symbol, "value": value})
    return values


def scan_public_surface_findings(repo: Path, base_ref: str, target_ref: str, changed_files: list[str]) -> list[dict[str, Any]]:
    findings = []
    base_literal_cache: dict[tuple[str, str], bool] = {}
    for rule in PUBLIC_SURFACE_RULES:
        by_value: dict[str, dict[str, Any]] = {}
        for file_path in changed_files:
            if path_matches(file_path, SKIP_PATHS):
                continue
            if not any(fnmatch.fnmatch(file_path, pattern) for pattern in rule["patterns"]):
                continue
            diff = get_diff(repo, base_ref, target_ref, file_path)
            if not diff:
                continue
            added, removed = diff_changed_lines(diff)
            removed_values = {
                item["value"]
                for line in non_comment_changed_lines(removed)
                for item in extract_public_surface_values(line, rule)
            }
            for line in non_comment_changed_lines(added):
                for item in extract_public_surface_values(line, rule):
                    value = item["value"]
                    if value in removed_values:
                        continue
                    if literal_exists_at_ref(repo, base_ref, value, base_literal_cache):
                        continue
                    existing = by_value.setdefault(
                        value,
                        {
                            "type": "public_surface_added",
                            "name": value,
                            "surface": rule["surface"],
                            "risk": rule["risk"],
                            "impact": rule["impact"],
                            "symbols": [],
                            "files": [],
                            "diff_preview": [],
                        },
                    )
                    if item["symbol"] not in existing["symbols"]:
                        existing["symbols"].append(item["symbol"])
                    if file_path not in existing["files"]:
                        existing["files"].append(file_path)
                    if len(existing["diff_preview"]) < 20:
                        existing["diff_preview"].append(line)
        for value in sorted(by_value):
            finding = by_value[value]
            finding["symbols"] = sorted(finding["symbols"])
            finding["files"] = sorted(finding["files"])
            finding["diff_preview"] = "\n".join(finding["diff_preview"])
            findings.append(finding)
    return findings


def parse_conf_content(content: str | None) -> dict[str, str]:
    if not content:
        return {}
    parsed = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key:
            parsed[key] = value.strip()
    return parsed


def normalize_var_name(name: str) -> str:
    name = name.strip().strip("`")
    name = re.sub(r"^@@(?:global|session)?\.?", "", name, flags=re.I)
    return name.lower()


def parse_system_vars_content(content: str | None) -> dict[str, str]:
    if not content:
        return {}
    content = content.strip()
    if not content:
        return {}
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            return {normalize_var_name(str(k)): str(v).strip() for k, v in data.items()}
    except json.JSONDecodeError:
        pass

    parsed: dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or set(line) <= {"+", "-"}:
            continue
        if line.startswith("|") and line.endswith("|"):
            parts = [part.strip() for part in line.strip("|").split("|")]
            if len(parts) >= 2 and parts[0].lower() not in {"variable_name", "variable_name".lower(), "name"}:
                parsed[normalize_var_name(parts[0])] = parts[1]
            continue
        if "\t" in line:
            parts = [part.strip() for part in line.split("\t")]
            if len(parts) >= 2 and parts[0].lower() not in {"variable_name", "name"}:
                parsed[normalize_var_name(parts[0])] = parts[1]
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            key = key.strip()
            if key:
                parsed[normalize_var_name(key)] = value.strip().strip(";")
            continue
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].lower() not in {"variable_name", "name"}:
            parsed[normalize_var_name(parts[0])] = parts[1].strip()
    return parsed


def parse_system_vars_object(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {normalize_var_name(str(k)): str(v).strip() for k, v in value.items()}
    if isinstance(value, list):
        parsed: dict[str, str] = {}
        for item in value:
            if isinstance(item, dict):
                name = item.get("Variable_name") or item.get("variable_name") or item.get("name")
                val = item.get("Value") or item.get("value")
                if name is not None and val is not None:
                    parsed[normalize_var_name(str(name))] = str(val).strip()
        return parsed
    if isinstance(value, str):
        return parse_system_vars_content(value)
    return {}


def build_user_context(args: argparse.Namespace) -> dict[str, Any] | None:
    context: dict[str, Any] = {}
    if args.fe_conf:
        context["fe_conf"] = Path(args.fe_conf).read_text(encoding="utf-8")
    if args.be_conf:
        context["be_conf"] = Path(args.be_conf).read_text(encoding="utf-8")
    if args.system_vars:
        context["system_variables"] = Path(args.system_vars).read_text(encoding="utf-8")
    fe_conf = parse_conf_content(context.get("fe_conf"))
    be_conf = parse_conf_content(context.get("be_conf"))
    system_vars = parse_system_vars_object(context.get("system_variables"))
    if not fe_conf and not be_conf and not system_vars:
        return None
    context["fe_conf_parsed"] = fe_conf
    context["be_conf_parsed"] = be_conf
    context["system_vars_parsed"] = system_vars
    context["sources"] = {
        "fe_conf": bool(args.fe_conf),
        "be_conf": bool(args.be_conf),
        "system_vars": bool(args.system_vars),
    }
    return context


def finding_candidate_names(finding: dict[str, Any]) -> list[str]:
    names = [finding.get("name")]
    for meta_key in ("old_metadata", "new_metadata"):
        meta = finding.get(meta_key) or {}
        names.extend([meta.get("annotation_name"), meta.get("alias"), meta.get("show_name"), meta.get("field_name")])
    result = []
    for name in names:
        if name:
            normalized = normalize_var_name(str(name))
            if normalized not in result:
                result.append(normalized)
    return result


def lookup_system_var_value(system_vars: dict[str, str], finding: dict[str, Any]) -> tuple[str | None, str | None]:
    for name in finding_candidate_names(finding):
        if name in system_vars:
            return name, system_vars[name]
    return None, None


def config_conflicts(context: dict[str, Any] | None, config_findings: dict[str, list[dict[str, Any]]]) -> dict[str, Any] | None:
    if not context:
        return None
    fe_conf = context.get("fe_conf_parsed", {})
    be_conf = context.get("be_conf_parsed", {})
    system_vars = context.get("system_vars_parsed", {})
    conflicts = []
    system_conflicts = []
    for group, findings in config_findings.items():
        if group not in {"fe_config", "be_config"}:
            continue
        source_conf = be_conf if group == "be_config" else fe_conf
        conf_label = "be_conf" if group == "be_config" else "fe_conf"
        if not source_conf:
            continue
        for finding in findings:
            name = finding.get("name")
            if not name:
                continue
            if finding["type"].endswith("_removed") and name in source_conf:
                conflicts.append(
                    {
                        "type": "removed_config_in_conf",
                        "config_name": name,
                        "conf_source": conf_label,
                        "current_value": source_conf[name],
                        "risk": "high",
                        "recommendation": f"Remove {name} from {conf_label} before upgrade.",
                    }
                )
            elif finding["type"].endswith("_changed"):
                old_default = normalize_value(finding.get("old_value"))
                new_default = normalize_value(finding.get("new_value"))
                if name in source_conf:
                    current = normalize_value(source_conf[name])
                    if current == old_default:
                        conflicts.append(
                            {
                                "type": "config_changed_using_old_default",
                                "config_name": name,
                                "conf_source": conf_label,
                                "old_default": old_default,
                                "new_default": new_default,
                                "current_in_conf": source_conf[name],
                                "risk": "medium",
                                "recommendation": f"{name} matches the old default; decide whether to keep it explicitly.",
                            }
                        )
                    else:
                        conflicts.append(
                            {
                                "type": "config_changed_custom_override",
                                "config_name": name,
                                "conf_source": conf_label,
                                "old_default": old_default,
                                "new_default": new_default,
                                "current_in_conf": source_conf[name],
                                "risk": "low",
                                "recommendation": f"{name} is overridden; verify the custom value is still valid.",
                            }
                        )
                elif finding.get("risk") in {"high", "critical"}:
                    conflicts.append(
                        {
                            "type": "config_changed_no_override",
                            "config_name": name,
                            "conf_source": conf_label,
                            "old_default": old_default,
                            "new_default": new_default,
                            "current_in_conf": None,
                            "risk": finding.get("risk"),
                            "recommendation": f"{name} default changes and is not overridden.",
                        }
                    )
    if system_vars:
        for group in ("session_variable", "system_variable"):
            for finding in config_findings.get(group, []):
                name = finding.get("name")
                if not name:
                    continue
                matched_name, current_raw = lookup_system_var_value(system_vars, finding)
                if current_raw is None:
                    continue
                current = normalize_value(current_raw)
                var_scope = "global" if group == "system_variable" else "session/default"
                if finding["type"].endswith("_removed"):
                    system_conflicts.append(
                        {
                            "type": "removed_system_variable_in_snapshot",
                            "variable_name": matched_name,
                            "reported_name": name,
                            "scope": var_scope,
                            "current_value": current_raw,
                            "risk": "high",
                            "recommendation": f"Remove or stop setting {matched_name}; target version no longer defines it.",
                        }
                    )
                elif finding["type"].endswith("_changed"):
                    old_default = normalize_value(finding.get("old_value"))
                    new_default = normalize_value(finding.get("new_value"))
                    if current == new_default:
                        continue
                    if current == old_default:
                        risk = "medium" if finding.get("risk") != "critical" else "critical"
                        reason = "matches old default"
                    else:
                        risk = "low" if finding.get("risk") not in {"high", "critical"} else "medium"
                        reason = "custom value"
                    system_conflicts.append(
                        {
                            "type": "system_variable_changed_with_current_value",
                            "variable_name": matched_name,
                            "reported_name": name,
                            "scope": var_scope,
                            "old_default": old_default,
                            "new_default": new_default,
                            "current_value": current_raw,
                            "risk": risk,
                            "reason": reason,
                            "recommendation": f"{matched_name} default changes from {old_default} to {new_default}; verify whether to keep current value {current_raw}.",
                        }
                    )
    return {
        "context_loaded": True,
        "sources": context.get("sources", {}),
        "config_conflicts": conflicts,
        "system_variable_conflicts": system_conflicts,
        "summary": {
            "total_conflicts": len(conflicts),
            "total_system_variable_conflicts": len(system_conflicts),
            "high_risk": len([c for c in conflicts if c["risk"] == "high"]),
            "system_high_risk": len([c for c in system_conflicts if c["risk"] in {"high", "critical"}]),
            "medium_risk": len([c for c in conflicts if c["risk"] == "medium"]),
            "system_medium_risk": len([c for c in system_conflicts if c["risk"] == "medium"]),
            "low_risk": len([c for c in conflicts if c["risk"] == "low"]),
            "system_low_risk": len([c for c in system_conflicts if c["risk"] == "low"]),
        },
    }


def flatten_findings(config_findings: dict[str, list[dict[str, Any]]], pattern_findings: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    all_findings = []
    for group, items in config_findings.items():
        for item in items:
            copied = dict(item)
            copied["scanner"] = group
            all_findings.append(copied)
    for group, items in pattern_findings.items():
        for item in items:
            copied = dict(item)
            copied["scanner"] = group
            all_findings.append(copied)
    return all_findings


def summarize_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    risks = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    impacts = {"data": 0, "behavior": 0, "operational": 0, "rolling_upgrade": 0}
    for finding in findings:
        risk = finding.get("risk", "low")
        risks[risk] = risks.get(risk, 0) + 1
        impact = finding.get("impact", {})
        for key in impacts:
            if impact.get(key):
                impacts[key] += 1
    return {"by_risk": risks, "by_impact": impacts, "total": len(findings)}


def write_markdown_report(
    path: Path,
    summary: dict[str, Any],
    findings: list[dict[str, Any]],
    conflicts: dict[str, Any] | None,
    source_domains: dict[str, Any],
) -> None:
    high = [f for f in findings if f.get("risk") in {"critical", "high"}]
    medium = [f for f in findings if f.get("risk") == "medium"]
    lines = [
        "# StarRocks Upgrade Scanner Report",
        "",
        "> This is an automated scanner artifact, not the final user-facing upgrade conclusion. Codex must read source and verify behavior before reporting.",
        "",
        f"- Base: {summary['base']['input']} -> {summary['base']['resolved']} ({summary['base']['sha'][:12]})",
        f"- Target: {summary['target']['input']} -> {summary['target']['resolved']} ({summary['target']['sha'][:12]})",
        f"- Commits only in target: {summary['commits']['target_only']}",
        f"- Commits only in base: {summary['commits']['base_only']}",
        f"- Findings: {summary['findings']['total']} (critical={summary['findings']['by_risk'].get('critical', 0)}, high={summary['findings']['by_risk'].get('high', 0)}, medium={summary['findings']['by_risk'].get('medium', 0)})",
        "",
        "## High And Critical Findings",
        "",
    ]
    if high:
        for item in high[:80]:
            name = item.get("name") or item.get("file")
            lines.append(f"- [{str(item.get('risk')).upper()}] {item.get('scanner')}: {name} ({item.get('type')})")
            if item.get("old_value") is not None or item.get("new_value") is not None:
                lines.append(f"  - Value: {item.get('old_value')} -> {item.get('new_value')}")
            if item.get("file"):
                lines.append(f"  - File: {item.get('file')}")
            if item.get("files"):
                files = item.get("files", [])
                lines.append(f"  - Files: {', '.join(files[:6])}")
                if len(files) > 6:
                    lines.append(f"  - ... {len(files) - 6} more files")
            if item.get("keywords"):
                lines.append(f"  - Keywords: {', '.join(item.get('keywords', [])[:8])}")
            if item.get("surface"):
                lines.append(f"  - Surface: {item.get('surface')}")
            if item.get("symbols"):
                lines.append(f"  - Symbols: {', '.join(item.get('symbols', [])[:8])}")
            if item.get("before_behavior"):
                lines.append(f"  - Before: {item.get('before_behavior')}")
            if item.get("now_behavior"):
                lines.append(f"  - Now: {item.get('now_behavior')}")
            if item.get("trigger"):
                lines.append(f"  - Trigger: {item.get('trigger')}")
            if item.get("impact_hint"):
                lines.append(f"  - Impact: {item.get('impact_hint')}")
            if item.get("handling_hint"):
                lines.append(f"  - Handling: {item.get('handling_hint')}")
    else:
        lines.append("- No high or critical findings from automated scanners.")
    lines.extend(["", "## Source Domain Summary", ""])
    domains = source_domains.get("domains", [])
    if domains:
        for item in domains[:30]:
            lines.append(
                f"- [{str(item.get('risk')).upper()}] {item.get('domain')}: "
                f"{item.get('file_count')} files, +{item.get('added')}/-{item.get('removed')}"
            )
            for file_path in item.get("files", [])[:8]:
                lines.append(f"  - {file_path}")
            if len(item.get("files", [])) > 8:
                lines.append(f"  - ... {len(item.get('files', [])) - 8} more files")
    else:
        lines.append("- No source domain changes matched the built-in rules.")
    lines.extend(["", "## Config And System Context", ""])
    if conflicts:
        cs = conflicts.get("summary", {})
        lines.append(f"- Config conflicts: {cs.get('total_conflicts', 0)} (high={cs.get('high_risk', 0)}, medium={cs.get('medium_risk', 0)})")
        lines.append(
            f"- System variable conflicts: {cs.get('total_system_variable_conflicts', 0)} "
            f"(high={cs.get('system_high_risk', 0)}, medium={cs.get('system_medium_risk', 0)})"
        )
        for item in conflicts.get("config_conflicts", [])[:50]:
            lines.append(f"- [{str(item.get('risk')).upper()}] {item.get('config_name')}: {item.get('recommendation')}")
        for item in conflicts.get("system_variable_conflicts", [])[:50]:
            lines.append(
                f"- [{str(item.get('risk')).upper()}] {item.get('variable_name')}: "
                f"{item.get('recommendation')}"
            )
    else:
        lines.append("- No user config or system variables supplied; environment-specific conflicts were not checked.")
    lines.extend(["", "## Medium Findings", ""])
    for item in medium[:80]:
        name = item.get("name") or item.get("file")
        lines.append(f"- [MEDIUM] {item.get('scanner')}: {name} ({item.get('type')})")
    lines.extend(
        [
            "",
            "## Next Source Checks",
            "",
            "- Trace every HIGH/CRITICAL finding with rg before final user-facing conclusions.",
            "- Read feature-impact-findings.json first when present; these are behavior/performance candidates that must be expanded for the user.",
            "- Read public-surface-findings.json when present; group added headers/properties/grammar keywords into user-visible feature candidates before deciding what to report.",
            "- For MV findings, inspect AlterJobMgr, AlterMVJobExecutor, MaterializedView, and PartitionBasedMvRefreshProcessor flows.",
            "- For load findings, inspect Stream Load headers, batch write / merge_commit code paths, and transaction/load timeout behavior.",
            "- For Iceberg/Paimon findings, inspect connector_iceberg/connector_paimon domains, external catalog properties, metadata refresh, scan planning, delete files, schema evolution, and MV refresh/rewrite paths.",
            "- For config conflicts, check whether the config is mutable and whether restart is required.",
            "- For system variable conflicts, check whether the value is GLOBAL, SESSION_ONLY, READ_ONLY, or invisible.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_compare(args: argparse.Namespace) -> dict[str, Any]:
    repo = Path(args.repo or os.getcwd()).resolve()
    if not (repo / ".git").exists():
        raise SystemExit(f"[ERROR] Not a git repository: {repo}")
    if args.base_ref:
        base = resolve_ref(repo, args.base_ref, is_version=False)
    elif args.base_version:
        base = resolve_ref(repo, args.base_version, is_version=True)
    else:
        raise SystemExit("[ERROR] Provide --base-version or --base-ref")
    if args.target_ref:
        target = resolve_ref(repo, args.target_ref, is_version=False)
    elif args.target_version:
        target = resolve_ref(repo, args.target_version, is_version=True)
    else:
        raise SystemExit("[ERROR] Provide --target-version or --target-ref")
    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[INFO] Base: {base['input']} -> {base['resolved']} {base['sha'][:12]}")
    print(f"[INFO] Target: {target['input']} -> {target['resolved']} {target['sha'][:12]}")
    print(f"[INFO] Output: {output_dir}")

    only_target = get_commits(repo, base["resolved"], target["resolved"])
    only_base = get_commits(repo, target["resolved"], base["resolved"])
    target_tiers = classify_commits(repo, only_target, output_dir, target["resolved"], save_diffs=not args.skip_commit_diffs)
    base_tiers = classify_commits(repo, only_base, output_dir, base["resolved"], save_diffs=False)

    save_json(only_target, output_dir / "commits" / f"only-in-{safe_label(target['resolved'])}.json")
    save_json(only_base, output_dir / "commits" / f"only-in-{safe_label(base['resolved'])}.json")

    pr_target = sorted({pr for commit in only_target for pr in commit.get("pr_numbers", [])})
    pr_base = sorted({pr for commit in only_base for pr in commit.get("pr_numbers", [])})
    save_json(
        {
            "in_target": pr_target,
            "in_base": pr_base,
            "only_in_target": sorted(set(pr_target) - set(pr_base)),
            "only_in_base": sorted(set(pr_base) - set(pr_target)),
            "common": sorted(set(pr_base) & set(pr_target)),
        },
        output_dir / "pr-diff.json",
    )

    changed_files = changed_files_between(repo, base["resolved"], target["resolved"])
    save_json(changed_files, output_dir / "changed-files.json")
    source_domains = classify_source_domains(changed_files, diff_numstat(repo, base["resolved"], target["resolved"]))
    save_json(source_domains, output_dir / "source-domain-summary.json")

    config_findings = scan_configs(repo, base["resolved"], target["resolved"])
    pattern_findings = scan_pattern_findings(repo, base["resolved"], target["resolved"], changed_files)
    feature_impact_findings = scan_feature_impact_findings(repo, base["resolved"], target["resolved"], changed_files)
    save_json({"feature_impact": feature_impact_findings}, output_dir / "feature-impact-findings.json")
    if feature_impact_findings:
        pattern_findings["feature_impact"] = feature_impact_findings
    public_surface_findings = scan_public_surface_findings(repo, base["resolved"], target["resolved"], changed_files)
    save_json({"public_surface": public_surface_findings}, output_dir / "public-surface-findings.json")
    if public_surface_findings:
        pattern_findings["public_surface"] = public_surface_findings
    all_findings = flatten_findings(config_findings, pattern_findings)
    findings_summary = summarize_findings(all_findings)
    incompatibilities = {
        "config_findings": config_findings,
        "pattern_findings": pattern_findings,
        "feature_impact_findings": feature_impact_findings,
        "public_surface_findings": public_surface_findings,
        "all_findings": all_findings,
        "summary": findings_summary,
    }
    save_json(incompatibilities, output_dir / "incompatibilities.json")

    user_context = build_user_context(args)
    conflicts = config_conflicts(user_context, config_findings)
    if conflicts:
        save_json(conflicts, output_dir / "context-conflicts.json")

    summary = {
        "mode": "version-compare",
        "repo": str(repo),
        "base": base,
        "target": target,
        "commits": {
            "target_only": len(only_target),
            "base_only": len(only_base),
            "target_tiers": target_tiers["tier_counts"],
            "base_tiers": base_tiers["tier_counts"],
        },
        "prs": {
            "target_only": len(set(pr_target) - set(pr_base)),
            "base_only": len(set(pr_base) - set(pr_target)),
            "common": len(set(pr_base) & set(pr_target)),
        },
        "changed_files": len(changed_files),
        "source_domains": source_domains["summary"],
        "findings": findings_summary,
        "config_context": conflicts["summary"] if conflicts else None,
        "generated_at": datetime.now().isoformat(),
    }
    save_json(summary, output_dir / "summary.json")
    write_markdown_report(output_dir / "upgrade-report.md", summary, all_findings, conflicts, source_domains)

    print("[DONE] comparison complete")
    print(f"[DONE] summary: {output_dir / 'summary.json'}")
    print(f"[DONE] report: {output_dir / 'upgrade-report.md'}")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare StarRocks upgrade versions/refs with optional user context.")
    parser.add_argument("--repo", default=os.getcwd(), help="Path to local StarRocks repository.")
    parser.add_argument("--base-version", help="Base StarRocks version, for example 3.3.16.")
    parser.add_argument("--target-version", help="Target StarRocks version, for example 3.5.17.")
    parser.add_argument("--base-ref", help="Base git ref/tag/branch/commit. Overrides --base-version.")
    parser.add_argument("--target-ref", help="Target git ref/tag/branch/commit. Overrides --target-version.")
    parser.add_argument("--output", default="./upgrade-report", help="Output directory.")
    parser.add_argument("--fe-conf", help="Optional production fe.conf path.")
    parser.add_argument("--be-conf", help="Optional production be.conf path.")
    parser.add_argument("--system-vars", help="Optional SHOW VARIABLES / SHOW GLOBAL VARIABLES snapshot path.")
    parser.add_argument("--skip-commit-diffs", action="store_true", help="Do not save HIGH/MEDIUM per-commit diff files.")
    args = parser.parse_args()
    run_compare(args)


if __name__ == "__main__":
    main()
