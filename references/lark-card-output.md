# Feishu/Lark Upgrade Card Output

Use this reference only when the user wants the StarRocks upgrade report sent
to Feishu/Lark, a group post, a Feishu document, or through `lark-cli`.

## Output Choice

Prefer an interactive card for chat messages:

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
  - title line: `**【NN｜等级｜领域】标题**`;
  - first field row: `旧行为` / `新行为`;
  - second field row: `触发` / `影响`;
  - final full-width row: `处理`;
  - optional final full-width row: `例`;
  - `hr` between items.
- Put at most 6 risk items in one card. Split into multiple cards when there are
  more than 6 important items.
- Add an action button only when there is a real URL, such as a Feishu doc or
  hosted report. Do not create a button for local paths like `/tmp/...`.

## Field Style

- Keep every field concise. Long paragraphs make cards harder to scan.
- Use inline code only for short config names, variables, headers, or SQL
  keywords.
- Do not wrap long `key=value` strings, local paths, or whole sentences in code
  spans; Feishu renders them as long gray blocks and line breaks badly.
- Use risk levels: `阻断`, `高`, `中`, `低`, `需验证`.
- Use short domains: `导入`, `MV`, `配置`, `变量`, `缓存`, `存储`, `客户端`,
  `协议`, `权限`, `查询`.
- Handling steps should be one sentence, using `1）...；2）...；3）...。`
  instead of nested bullets.

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
        "content": "**【01｜高｜导入】insert_timeout 接管 INSERT-like 任务超时**"
      }
    },
    {
      "tag": "div",
      "fields": [
        {
          "is_short": true,
          "text": {
            "tag": "lark_md",
            "content": "**旧行为**\\n3.3.22-ee 没有独立 `insert_timeout`，DML/CTAS/MV refresh 更依赖 `query_timeout` 或任务自身 timeout。"
          }
        },
        {
          "is_short": true,
          "text": {
            "tag": "lark_md",
            "content": "**新行为**\\n3.5.18-ee 新增 `insert_timeout`，默认 14400 秒，相关任务路径会使用它。"
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
            "content": "**触发**\\nINSERT、UPDATE、DELETE、CTAS、MV refresh、统计收集、调度任务。"
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
        "content": "**处理**\\n1）盘点 SQL 初始化、任务属性、MV session property；2）对大导入和 MV refresh 显式验证 `insert_timeout`。"
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

If a card cannot be sent, use compact plain text. This is not a card and should
not be described as one:

```text
升级结论
版本：<base> -> <target>
判断：<judgment>
范围：<context>

重点差异
────────────────
【01｜高｜导入】<title>
　　旧行为：...
　　新行为：...
　　触发：...
　　影响：...
　　处理：...
```
