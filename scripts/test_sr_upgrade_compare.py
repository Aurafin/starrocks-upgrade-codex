#!/usr/bin/env python3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sr_upgrade_compare import (
    classify_source_domains,
    classify_commit,
    compare_field_maps,
    config_conflicts,
    extract_pr_numbers,
    normalize_value,
    parse_be_config,
    parse_conf_content,
    parse_java_fields_with_annotation,
    parse_system_vars_content,
    risk_for_name,
    scan_feature_impact_findings,
    scan_public_surface_findings,
)


class TestParsing(unittest.TestCase):
    def test_extract_pr_numbers(self):
        self.assertEqual(extract_pr_numbers("fix thing (#12345) and #12345 #54321"), [12345, 54321])

    def test_parse_conf_content(self):
        conf = "a = 1\n# comment\nJAVA_OPTS = \"-Xmx1g -Dk=v\"\n"
        self.assertEqual(parse_conf_content(conf)["a"], "1")
        self.assertEqual(parse_conf_content(conf)["JAVA_OPTS"], '"-Xmx1g -Dk=v"')

    def test_parse_fe_config(self):
        content = """
        @ConfField(mutable = true, comment = "server version")
        public static String mysql_server_version = "8.0.33";
        @Deprecated
        @ConfField
        public static int old_config = 1;
        """
        fields = parse_java_fields_with_annotation(content, "@ConfField")
        self.assertTrue(fields["mysql_server_version"]["mutable"])
        self.assertEqual(fields["mysql_server_version"]["value"], '"8.0.33"')
        self.assertTrue(fields["old_config"]["deprecated"])

    def test_parse_be_config(self):
        content = 'CONF_mInt32(max_tablet_version_count, "5000");\nCONF_String(storage_root_path, "${STARROCKS_HOME}/storage");'
        parsed = parse_be_config(content)
        self.assertTrue(parsed["max_tablet_version_count"]["mutable"])
        self.assertEqual(parsed["storage_root_path"]["value"], "${STARROCKS_HOME}/storage")

    def test_parse_var_attr_constants_and_show_name(self):
        content = """
        public static final String QUERY_TIMEOUT = "query_timeout";
        public static final String SQL_MODE = "sql_mode";
        public static final String SQL_MODE_STORAGE_NAME = "sql_mode_v2";
        @VariableMgr.VarAttr(name = QUERY_TIMEOUT, flag = VariableMgr.INVISIBLE)
        private int queryTimeoutS = 300;
        @VariableMgr.VarAttr(name = SQL_MODE_STORAGE_NAME, alias = SQL_MODE, show = SQL_MODE)
        private long sqlMode = 0L;
        """
        fields = parse_java_fields_with_annotation(content, "@VarAttr")
        self.assertIn("query_timeout", fields)
        self.assertEqual(fields["query_timeout"]["field_name"], "queryTimeoutS")
        self.assertIn("INVISIBLE", fields["query_timeout"]["flag_names"])
        self.assertIn("sql_mode", fields)
        self.assertEqual(fields["sql_mode"]["annotation_name"], "sql_mode_v2")
        self.assertEqual(fields["sql_mode"]["alias"], "sql_mode")

    def test_normalize_value(self):
        self.assertEqual(normalize_value('"8.0.33";'), "8.0.33")
        self.assertEqual(normalize_value("1024L"), "1024")

    def test_parse_system_vars_content(self):
        table = """
        +---------------+-------+
        | Variable_name | Value |
        +---------------+-------+
        | query_timeout | 300   |
        | @@global.sql_mode | 0 |
        +---------------+-------+
        """
        parsed = parse_system_vars_content(table)
        self.assertEqual(parsed["query_timeout"], "300")
        self.assertEqual(parsed["sql_mode"], "0")


class TestRiskAndTier(unittest.TestCase):
    def test_high_risk_name(self):
        self.assertEqual(risk_for_name("mysql_server_version", '"5.1.0"', '"8.0.33"'), "high")

    def test_insert_timeout_high_risk_name(self):
        self.assertEqual(risk_for_name("insert_timeout", None, "14400"), "high")

    def test_bool_flip_medium(self):
        self.assertEqual(risk_for_name("unknown_toggle", "false", "true"), "medium")

    def test_var_attr_metadata_change_without_default_change(self):
        old = {
            "query_timeout": {
                "field_name": "queryTimeoutS",
                "annotation_name": "query_timeout",
                "value": "300",
                "type": "int",
                "mutable": None,
                "flag_names": [],
            }
        }
        new = {
            "query_timeout": {
                "field_name": "queryTimeoutS",
                "annotation_name": "query_timeout",
                "value": "300",
                "type": "int",
                "mutable": None,
                "flag": "VariableMgr.SESSION_ONLY",
                "flag_names": ["SESSION_ONLY"],
            }
        }
        findings = compare_field_maps(old, new, "session_variable", "SessionVariable.java")
        metadata = [item for item in findings if item["type"] == "session_variable_metadata_changed"]
        self.assertEqual(len(metadata), 1)
        self.assertEqual(metadata[0]["risk"], "high")
        self.assertIn("flag_names", metadata[0]["changed_metadata"])

    def test_classify_mv_commit_high(self):
        tier, reason = classify_commit(
            {"subject": "fix: mv refresh issue"},
            ["fe/fe-core/src/main/java/com/starrocks/catalog/MaterializedView.java"],
        )
        self.assertEqual(tier, "HIGH")
        self.assertIn("critical file", reason)

    def test_classify_docs_skip(self):
        tier, _ = classify_commit({"subject": "docs: update release note"}, ["docs/zh/a.md"])
        self.assertEqual(tier, "SKIP")

    def test_classify_source_domains(self):
        summary = classify_source_domains(
            [
                "fe/fe-core/src/main/java/com/starrocks/catalog/MaterializedView.java",
                "be/src/storage/rowset/segment.cpp",
                "fe/fe-core/src/main/java/com/starrocks/connector/iceberg/IcebergMetadata.java",
                "fe/fe-core/src/main/java/com/starrocks/connector/paimon/PaimonMetadata.java",
                "be/src/exec/iceberg/iceberg_delete_file_iterator.cpp",
                "be/src/exec/paimon/paimon_delete_file_builder.cpp",
            ],
            {
                "fe/fe-core/src/main/java/com/starrocks/catalog/MaterializedView.java": {"added": 10, "removed": 2},
                "be/src/storage/rowset/segment.cpp": {"added": 5, "removed": 1},
                "fe/fe-core/src/main/java/com/starrocks/connector/iceberg/IcebergMetadata.java": {"added": 20, "removed": 4},
                "fe/fe-core/src/main/java/com/starrocks/connector/paimon/PaimonMetadata.java": {"added": 12, "removed": 3},
                "be/src/exec/iceberg/iceberg_delete_file_iterator.cpp": {"added": 7, "removed": 1},
                "be/src/exec/paimon/paimon_delete_file_builder.cpp": {"added": 6, "removed": 2},
            },
        )
        domains = {item["domain"]: item for item in summary["domains"]}
        self.assertIn("materialized_view", domains)
        self.assertIn("storage_format", domains)
        self.assertIn("connector_iceberg", domains)
        self.assertIn("connector_paimon", domains)
        self.assertEqual(domains["storage_format"]["risk"], "critical")
        self.assertEqual(domains["connector_iceberg"]["risk"], "high")
        self.assertEqual(domains["connector_paimon"]["risk"], "high")

    def test_system_variable_conflict(self):
        conflicts = config_conflicts(
            {"system_vars_parsed": {"query_timeout": "300"}, "sources": {"system_vars": True}},
            {
                "session_variable": [
                    {
                        "type": "session_variable_changed",
                        "name": "query_timeout",
                        "old_value": "300",
                        "new_value": "600",
                        "risk": "high",
                    }
                ]
            },
        )
        self.assertEqual(conflicts["summary"]["total_system_variable_conflicts"], 1)
        self.assertEqual(conflicts["system_variable_conflicts"][0]["variable_name"], "query_timeout")


class TestFeatureImpactScan(unittest.TestCase):
    def _run_git(self, repo: Path, *args: str) -> str:
        result = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=True)
        return result.stdout.strip()

    def _commit_all(self, repo: Path, message: str) -> str:
        self._run_git(repo, "add", ".")
        self._run_git(repo, "commit", "-m", message)
        return self._run_git(repo, "rev-parse", "HEAD")

    def test_feature_impact_findings_are_grouped(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self._run_git(repo, "init")
            self._run_git(repo, "config", "user.email", "test@example.com")
            self._run_git(repo, "config", "user.name", "Test")

            session_variable = repo / "fe/fe-core/src/main/java/com/starrocks/qe/SessionVariable.java"
            stream_header = repo / "be/src/http/http_common.h"
            session_variable.parent.mkdir(parents=True)
            stream_header.parent.mkdir(parents=True)
            session_variable.write_text('public static final String QUERY_TIMEOUT = "query_timeout";\n', encoding="utf-8")
            stream_header.write_text("// stream load headers\n", encoding="utf-8")
            base = self._commit_all(repo, "base")

            session_variable.write_text(
                'public static final String INSERT_TIMEOUT = "insert_timeout";\n'
                "@VariableMgr.VarAttr(name = INSERT_TIMEOUT)\n"
                "private int insertTimeoutS = 14400;\n",
                encoding="utf-8",
            )
            stream_header.write_text(
                'static const std::string HTTP_ENABLE_MERGE_COMMIT = "enable_merge_commit";\n'
                'static const std::string HTTP_MERGE_COMMIT_INTERVAL_MS = "merge_commit_interval_ms";\n',
                encoding="utf-8",
            )
            target = self._commit_all(repo, "target")

            findings = scan_feature_impact_findings(
                repo,
                base,
                target,
                [
                    "fe/fe-core/src/main/java/com/starrocks/qe/SessionVariable.java",
                    "be/src/http/http_common.h",
                ],
            )
            ids = {item["id"] for item in findings}
            self.assertIn("insert_timeout_controls_insert_like_tasks", ids)
            self.assertIn("stream_load_merge_commit_feature", ids)
            self.assertEqual({item["type"] for item in findings}, {"feature_introduced"})

    def test_existing_feature_comment_only_change_is_not_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self._run_git(repo, "init")
            self._run_git(repo, "config", "user.email", "test@example.com")
            self._run_git(repo, "config", "user.name", "Test")

            session_variable = repo / "fe/fe-core/src/main/java/com/starrocks/qe/SessionVariable.java"
            stream_header = repo / "be/src/http/http_common.h"
            session_variable.parent.mkdir(parents=True)
            stream_header.parent.mkdir(parents=True)
            session_variable.write_text(
                'public static final String INSERT_TIMEOUT = "insert_timeout";\n'
                "@VariableMgr.VarAttr(name = INSERT_TIMEOUT)\n"
                "private int insertTimeoutS = 14400;\n",
                encoding="utf-8",
            )
            stream_header.write_text(
                'static const std::string HTTP_ENABLE_MERGE_COMMIT = "enable_merge_commit";\n',
                encoding="utf-8",
            )
            base = self._commit_all(repo, "base")

            session_variable.write_text(
                'public static final String INSERT_TIMEOUT = "insert_timeout";\n'
                "@VariableMgr.VarAttr(name = INSERT_TIMEOUT)\n"
                "private int insertTimeoutS = 14400;\n"
                "// insert_timeout docs only\n",
                encoding="utf-8",
            )
            stream_header.write_text(
                'static const std::string HTTP_ENABLE_MERGE_COMMIT = "enable_merge_commit";\n'
                "// enable_batch_write docs only\n",
                encoding="utf-8",
            )
            target = self._commit_all(repo, "target")

            findings = scan_feature_impact_findings(
                repo,
                base,
                target,
                [
                    "fe/fe-core/src/main/java/com/starrocks/qe/SessionVariable.java",
                    "be/src/http/http_common.h",
                ],
            )
            self.assertEqual(findings, [])

    def test_existing_feature_behavior_change_is_reported_as_changed(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self._run_git(repo, "init")
            self._run_git(repo, "config", "user.email", "test@example.com")
            self._run_git(repo, "config", "user.name", "Test")

            session_variable = repo / "fe/fe-core/src/main/java/com/starrocks/qe/SessionVariable.java"
            stream_header = repo / "be/src/http/http_common.h"
            session_variable.parent.mkdir(parents=True)
            stream_header.parent.mkdir(parents=True)
            session_variable.write_text(
                'public static final String INSERT_TIMEOUT = "insert_timeout";\n'
                "@VariableMgr.VarAttr(name = INSERT_TIMEOUT)\n"
                "private int insertTimeoutS = 14400;\n",
                encoding="utf-8",
            )
            stream_header.write_text(
                'static const std::string HTTP_ENABLE_MERGE_COMMIT = "enable_merge_commit";\n'
                "bool enable_batch_write = false;\n",
                encoding="utf-8",
            )
            base = self._commit_all(repo, "base")

            session_variable.write_text(
                'public static final String INSERT_TIMEOUT = "insert_timeout";\n'
                "@VariableMgr.VarAttr(name = INSERT_TIMEOUT)\n"
                "private int insertTimeoutS = 7200;\n",
                encoding="utf-8",
            )
            stream_header.write_text(
                'static const std::string HTTP_ENABLE_MERGE_COMMIT = "enable_merge_commit";\n'
                "bool enable_batch_write = true;\n",
                encoding="utf-8",
            )
            target = self._commit_all(repo, "target")

            findings = scan_feature_impact_findings(
                repo,
                base,
                target,
                [
                    "fe/fe-core/src/main/java/com/starrocks/qe/SessionVariable.java",
                    "be/src/http/http_common.h",
                ],
            )
            self.assertEqual({item["type"] for item in findings}, {"feature_behavior_changed"})

    def test_public_surface_added_finds_headers_and_properties(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self._run_git(repo, "init")
            self._run_git(repo, "config", "user.email", "test@example.com")
            self._run_git(repo, "config", "user.name", "Test")

            header = repo / "be/src/http/http_common.h"
            props = repo / "fe/fe-core/src/main/java/com/starrocks/common/util/PropertyAnalyzer.java"
            header.parent.mkdir(parents=True)
            props.parent.mkdir(parents=True)
            header.write_text("// headers\n", encoding="utf-8")
            props.write_text("public class PropertyAnalyzer {}\n", encoding="utf-8")
            base = self._commit_all(repo, "base")

            header.write_text(
                'static const std::string HTTP_ENABLE_NEW_LOAD_MODE = "enable_new_load_mode";\n',
                encoding="utf-8",
            )
            props.write_text(
                'public static final String PROPERTIES_NEW_TABLE_FEATURE = "new_table_feature";\n',
                encoding="utf-8",
            )
            target = self._commit_all(repo, "target")

            findings = scan_public_surface_findings(
                repo,
                base,
                target,
                [
                    "be/src/http/http_common.h",
                    "fe/fe-core/src/main/java/com/starrocks/common/util/PropertyAnalyzer.java",
                ],
            )
            by_name = {item["name"]: item for item in findings}
            self.assertEqual(by_name["enable_new_load_mode"]["surface"], "http_header")
            self.assertEqual(by_name["new_table_feature"]["surface"], "sql_or_task_property")

    def test_public_surface_added_skips_existing_literal_moved_to_new_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self._run_git(repo, "init")
            self._run_git(repo, "config", "user.email", "test@example.com")
            self._run_git(repo, "config", "user.name", "Test")

            old_header = repo / "be/src/http/old_headers.h"
            new_header = repo / "be/src/http/http_common.h"
            old_header.parent.mkdir(parents=True)
            old_header.write_text(
                'static const std::string HTTP_FORMAT = "format";\n',
                encoding="utf-8",
            )
            base = self._commit_all(repo, "base")

            new_header.write_text(
                'static const std::string HTTP_FORMAT = "format";\n',
                encoding="utf-8",
            )
            target = self._commit_all(repo, "target")

            findings = scan_public_surface_findings(
                repo,
                base,
                target,
                ["be/src/http/http_common.h"],
            )
            self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
