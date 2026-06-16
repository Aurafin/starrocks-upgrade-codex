#!/usr/bin/env python3
import unittest

from sr_upgrade_compare import (
    classify_source_domains,
    classify_commit,
    config_conflicts,
    extract_pr_numbers,
    normalize_value,
    parse_be_config,
    parse_conf_content,
    parse_java_fields_with_annotation,
    parse_system_vars_content,
    risk_for_name,
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

    def test_bool_flip_medium(self):
        self.assertEqual(risk_for_name("unknown_toggle", "false", "true"), "medium")

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
            ],
            {
                "fe/fe-core/src/main/java/com/starrocks/catalog/MaterializedView.java": {"added": 10, "removed": 2},
                "be/src/storage/rowset/segment.cpp": {"added": 5, "removed": 1},
            },
        )
        domains = {item["domain"]: item for item in summary["domains"]}
        self.assertIn("materialized_view", domains)
        self.assertIn("storage_format", domains)
        self.assertEqual(domains["storage_format"]["risk"], "critical")

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


if __name__ == "__main__":
    unittest.main()
