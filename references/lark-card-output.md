# Feishu/Lark Upgrade Card Output

Use this reference only when the user wants the StarRocks upgrade report sent
to Feishu/Lark, a group post, a Feishu document, or through `lark-cli`.

## Output Choice

Prefer interactive cards for chat messages. For best readability, send one card
per important risk item when the user approves multiple Feishu messages:

```bash
lark-cli im +messages-send --chat-id oc_xxx --as bot --msg-type interactive --content '<card-json>'
```

For large cards, avoid shell-quoting long JSON. Save the card to a temporary
file and send it through Python subprocess:

```bash
python3 - <<'PY'
import json
import subprocess

card_path = "/tmp/starrocks-upgrade-card.json"
chat_id = "oc_xxx"
identity = "bot"

with open(card_path, "r", encoding="utf-8") as f:
    content = json.dumps(json.load(f), ensure_ascii=False)

subprocess.run(
    [
        "lark-cli", "im", "+messages-send",
        "--chat-id", chat_id,
        "--as", identity,
        "--msg-type", "interactive",
        "--content", content,
    ],
    check=True,
)
PY
```

Use text fallback only when:

- the user only wants copyable text;
- no `chat_id` / `user_id` is available;
- the user has not approved sending a message;
- interactive cards are unavailable.

Before sending, confirm recipient, content summary, and identity (`--as bot` or
`--as user`). Do not send to a chat without explicit approval.

## Card Layout

Use a compact card with real card sections, not Markdown separators.

- Header title: `StarRocks 升级评估｜<base> -> <target>`.
- Header template:
  - `red`: blocking issue or do not upgrade directly.
  - `orange`: canary/gray upgrade with high-risk validation required.
  - `blue`: normal gray upgrade.
  - `green`: low-risk patch upgrade.
- First `div`: summary lines for version, judgment, context scope, and number of
  high-risk items.
- Each risk item:
  - title line: natural title only, for example `**MV refresh 对过滤数据默认更严格**`;
  - first field row: `之前行为` / `现在行为`;
  - second field row: `触发条件` / `影响`;
  - final full-width row: `处理方式`;
  - optional final full-width row: `例`;
  - `hr` between items.
- Put at most 6 risk items in one card. Split into multiple cards when there are
  more than 6 important items. If the user wants the best Feishu reading
  experience and approves multiple messages, use one card per risk item.
- Add an action button only when there is a real URL, such as a Feishu doc or
  hosted report. Do not create a button for local paths like `/tmp/...`.

## Field Style

- Keep every field concise. Long paragraphs make cards harder to scan.
- Use inline code only for short config names, variables, headers, or SQL
  keywords.
- Do not wrap long `key=value` strings, local paths, or whole sentences in code
  spans; Feishu renders them as long gray blocks and line breaks badly.
- Do not add numbering, risk levels, or domain labels to risk item titles. Use
  simple titles like `transform_type_prefer_string_for_varchar 默认变更`.
- Use the full field names `之前行为`, `现在行为`, `触发条件`, `影响`, `处理方式`.
- Handling steps should be one concise sentence; avoid nested bullets.

## Minimal Interactive Card Template

Fill this JSON with the actual analysis. `content` passed to `lark-cli` is the
card JSON object itself.

```json
{
  "config": {
    "wide_screen_mode": true
  },
  "header": {
    "template": "orange",
    "title": {
      "tag": "plain_text",
      "content": "StarRocks 升级评估｜3.3.22-ee -> 3.5.18-ee"
    }
  },
  "elements": [
    {
      "tag": "div",
      "text": {
        "tag": "lark_md",
        "content": "**判断**：可以灰度升级，但不建议无验证直接全量滚动\\n**范围**：未提供真实 fe.conf、be.conf、SHOW VARIABLES，本次是源码通用风险差异\\n**重点**：导入、MV、DataCache、客户端兼容、shared-data/lake"
      }
    },
    {
      "tag": "hr"
    },
    {
      "tag": "div",
      "text": {
        "tag": "lark_md",
        "content": "**insert_timeout 接管 INSERT-like 任务超时**"
      }
    },
    {
      "tag": "div",
      "fields": [
        {
          "is_short": true,
          "text": {
            "tag": "lark_md",
            "content": "**之前行为**\\n3.3.22-ee 没有独立 `insert_timeout`，DML/CTAS/MV refresh 更依赖 `query_timeout` 或任务自身 timeout。"
          }
        },
        {
          "is_short": true,
          "text": {
            "tag": "lark_md",
            "content": "**现在行为**\\n3.5.18-ee 新增 `insert_timeout`，默认 14400 秒，相关任务路径会使用它。"
          }
        }
      ]
    },
    {
      "tag": "div",
      "fields": [
        {
          "is_short": true,
          "text": {
            "tag": "lark_md",
            "content": "**触发条件**\\nINSERT、UPDATE、DELETE、CTAS、MV refresh、统计收集、调度任务。"
          }
        },
        {
          "is_short": true,
          "text": {
            "tag": "lark_md",
            "content": "**影响**\\n旧的 `query_timeout` 调参可能不再限制这些任务，等待时间或超时口径会变化。"
          }
        }
      ]
    },
    {
      "tag": "div",
      "text": {
        "tag": "lark_md",
        "content": "**处理方式**\\n盘点 SQL 初始化、任务属性、MV session property；对大导入和 MV refresh 显式验证 `insert_timeout`。"
      }
    }
  ]
}
```

## Optional Button

Only add this when `url` is a real Feishu doc, Jira, GitHub, or hosted report
URL:

```json
{
  "tag": "action",
  "actions": [
    {
      "tag": "button",
      "text": {
        "tag": "plain_text",
        "content": "查看完整报告"
      },
      "type": "primary",
      "url": "https://example.com/report"
    }
  ]
}
```

## Text Fallback

If a card cannot be sent, use compact ordered-list Markdown. This is not a card
and should not be described as one. Use 4 ordinary spaces before each nested
bullet so Feishu keeps the indentation and usually renders the bullets as
hollow circles:

```text
升级结论
版本：<base> -> <target>
判断：<judgment>
范围：<context>

重点差异
1. INSERT 类任务超时改由 insert_timeout 控制
    - 之前行为：3.3.22 没有独立的 insert_timeout 变量，插入类任务更容易跟 query_timeout 或各自任务属性绑定。
    - 现在行为：4.0.10 有 insert_timeout，默认 14400 秒。
    - 触发条件：INSERT、UPDATE、DELETE、CTAS、MV refresh、统计信息收集、PIPE 等 insert-like task。
    - 影响：旧版本里通过调 query_timeout 控制这些任务的方式，升级后可能不再覆盖，任务超时可能变长或行为不符合预期。
    - 处理方式：升级前检查作业、MV、PIPE、统计任务是否依赖 query_timeout；需要时显式设置 insert_timeout，或给 MV/task property 单独配置。

2. MV refresh 对过滤数据默认更严格
    - 之前行为：3.3.22 使用 enable_mv_refresh_insert_strict 这类旧逻辑，默认不完全等价于 4.0 的严格过滤失败策略。
    - 现在行为：4.0.10 使用 mv_refresh_fail_on_filter_data=true，并通过 insert_max_filter_ratio 控制过滤数据容忍度。
    - 触发条件：MV refresh 过程中发生数据过滤、类型转换失败、脏数据、外表分区数据不一致等。
    - 影响：升级后原来能刷新的 MV 可能刷新失败，或者需要显式设置过滤比例。
    - 处理方式：重点回归高频 MV refresh；必要时设置 insert_max_filter_ratio 或调整 mv_refresh_fail_on_filter_data。
```
