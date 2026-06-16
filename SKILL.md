---
name: starrocks-upgrade-codex
description: 基于本地 StarRocks 源码仓库比较两个版本、分支、tag 或 commit 的升级差异，生成源码证据驱动的功能差异、行为变化、兼容性、配置冲突、系统变量差异、MV 风险、滚动升级风险和升级建议。用户只给版本号也必须能分析；用户提供 fe.conf、be.conf、SHOW VARIABLES、SHOW GLOBAL VARIABLES 或粘贴文本时，将这些真实上下文用于收敛风险，但不能阻塞源码差异主流程。
---

# StarRocks 升级差异分析

用于做 StarRocks 升级前的版本差异分析.

## 核心原则

- 源码比较是主流程：先比较版本/ref 的代码、配置定义、系统变量定义、协议、parser、MV、storage、load/transaction、optimizer/planner 等变化。
- 用户配置只是上下文：有真实 `fe.conf`、`be.conf`、`SHOW VARIABLES` 或 `SHOW GLOBAL VARIABLES` 时，用它们判断“这个环境是否踩中差异”；没有也继续做版本差异分析。
- 不要求用户提供集群配置文件。不要使用示例、模板、虚构规模、虚构参数当成用户环境。
- 支持用户直接贴文本。如果用户贴了配置或变量输出，先把原文保存为临时文件，再传给脚本。
- 如果用户只给版本号，例如 `3.3.16 -> 3.5.17`，也要直接运行比较并输出通用升级风险。
- 对 HIGH/CRITICAL 结论必须回到源码阅读和 `rg` 追调用链，不能只引用自动扫描结果。
- 对新增功能带来的行为、性能、超时、队列或客户端使用方式变化，要当成独立升级差异输出；不要只看配置默认值是否变化。

## 支持输入

- 版本号：`3.3.16 -> 3.5.17`
- Git ref：`branch-3.3.16 -> branch-3.5.17`、`upstream/branch-3.5`、tag、commit SHA
- 真实配置文件：用户给的 `fe.conf`、`be.conf` 本地路径或附件
- 真实配置文本：用户直接粘贴的 `fe.conf`、`be.conf` 内容
- 系统变量快照：`SHOW VARIABLES`、`SHOW GLOBAL VARIABLES`、`mysql -B` TSV、JSON、`key=value` 文本

系统变量是 SQL 层参数，由 `VariableMgr`、`SessionVariable`、`GlobalVariable` 的 `@VarAttr` 管理，不是 FE/BE 配置文件。

如果用户贴的文本无法判断类型，只问一个最小问题：这是 FE 配置、BE 配置，还是 `SHOW VARIABLES` 输出？

## 工作流

1. 确认本地 StarRocks 源码仓库路径。当前目录有 `.git` 时优先使用当前目录。
2. 只要版本/ref 足够，就先运行源码比较：

```shell
python3 scripts/sr_upgrade_compare.py --repo /path/to/starrocks --base-version 3.3.16 --target-version 3.5.17 --output /tmp/sr-upgrade-report
```

用户给的是明确分支、tag 或 commit 时使用 ref：

```shell
python3 scripts/sr_upgrade_compare.py --repo /path/to/starrocks --base-ref upstream/branch-3.3.16 --target-ref upstream/branch-3.5.17 --output /tmp/sr-upgrade-report
```

用户给了真实文件路径时，把路径传给脚本：

```shell
python3 scripts/sr_upgrade_compare.py --repo /path/to/starrocks --base-version 3.3.16 --target-version 3.5.17 --fe-conf /path/fe.conf --be-conf /path/be.conf
```

用户贴了文本时，先原样保存为临时文件，再传给脚本。例如贴的是 `SHOW VARIABLES`：

```shell
python3 scripts/sr_upgrade_compare.py --repo /path/to/starrocks --base-version 3.3.16 --target-version 3.5.17 --system-vars /tmp/show-variables.txt
```

只有内容来自用户或真实目标环境时，才允许传 `--fe-conf`、`--be-conf`、`--system-vars`。

3. 优先读取这些产物：

- `summary.json`
- `upgrade-report.md`
- `incompatibilities.json`
- `feature-impact-findings.json`
- `public-surface-findings.json`
- `source-domain-summary.json`
- `context-conflicts.json`，仅当用户提供配置或系统变量上下文时存在
- `commits/tiered-*.json`

4. 对每个 HIGH/CRITICAL 项、`feature-impact-findings.json` 和 `public-surface-findings.json` 里的候选项做源码复核：

- 读自动扫描指向的源码文件。
- 用 `rg` 查关键类、函数、配置名、变量名、协议字段或日志关键字。
- 分清默认值变化、移除、重命名、可变性变化、协议兼容性、存储格式变化、MV 激活/刷新/改写变化。
- 只把源码证据能支撑的内容写进最终结论。

## 源码比较覆盖面

自动脚本会做第一轮系统扫描：

- commit 双向差异：target-only、base-only、PR 号、HIGH/MEDIUM/LOW/SKIP 分层
- 源码域影响面：config/variables、MV、optimizer/planner、execution/runtime、storage、catalog/schema、transaction/load、protocol/rpc、parser、connector、auth、scheduler
- FE 配置定义：`Config.java` 的 `@ConfField` 新增、移除、默认值变化、mutable 变化
- BE 配置定义：`be/src/common/config.h` 的 `CONF_*` 宏变化
- SQL 变量定义：`SessionVariable`、`GlobalVariable`、`SysVariable` 的 `@VarAttr` 变化、alias/show/flag/mutable 变化
- 关键源码模式：Thrift/protobuf、parser、auth、storage format、MV、type system 等高风险文件和关键词
- 新增功能影响面：例如 `insert_timeout` 接管 INSERT-like task 超时、Stream Load `merge_commit`/batch write 引入后的性能和队列行为变化
- 新增用户可见入口：HTTP header、Stream Load/load property、任务 property、表/MV property、SQL grammar keyword 等，作为新增功能候选而不是最终结论
- 用户上下文命中：真实 `fe.conf`、`be.conf`、系统变量快照是否踩中被移除或默认值变化的配置/变量

脚本是第一轮筛选，不是最终结论。最终回答必须结合源码复核。

## 需要读取参考文档的情况

当发现涉及下面主题时，读取 `references/analysis-guide.md`：

- FE/BE 配置默认值或 mutable 变化
- `@VarAttr`、`VariableMgr`、`SHOW VARIABLES`、`SET GLOBAL`、持久化全局默认值
- MV 刷新、改写、激活、失效、schema 兼容、分区刷新
- Thrift/protobuf 协议变化
- parser grammar 或保留字变化
- storage format、tablet metadata、rowset/segment 编码变化
- 新增功能影响导入、事务、超时、队列、MV 刷新、统计任务或客户端行为

## 输出要求

最终给用户的升级结论必须使用中文，不要只复述脚本扫描结果。默认先给总判断，再按“差异条目”一条一条展开：

硬性要求：
- 大版本或跨 minor 升级默认输出 5-12 条“重点差异”；不要只给 3-4 条摘要。
- 每条重点差异必须多行展开，至少包含：之前行为、现在行为、触发条件、影响、处理方式。
- 不允许把“之前行为 / 现在行为 / 触发条件 / 影响 / 处理方式”压缩成一段风险描述；最终回答里必须显式保留这些字段名。
- 最终回答的“重点差异”必须使用飞书稳定格式：标题行用 `【1】<变化点名称>`、`【10】<变化点名称>`；字段行使用两个全角空格 `　　` 缩进后直接写字段名。
- 最终回答的“重点差异”不要使用 Markdown ordered list，例如 `1.`、`2.`、`10.`；也不要使用嵌套 `-`、`*` 子弹列表。避免飞书 post/Markdown 渲染在双位编号时吃掉缩进。
- 如果同一主题下包含多个独立行为变化，拆成多个条目，不要只写成一个“某模块变化较大”的概括。
- 不要把多个互不相关的变化合并成一句，例如“配置默认值变化：a、b、c”。每个会影响用户操作的变化都要独立成条。
- 自动扫描的 finding 数量、commit 数量、源码域数量只能作为内部筛选依据，不能作为最终结论主体。
- `feature-impact-findings.json` 里的候选项不能直接照抄，但必须逐项判断是否应该进入“重点差异”；如果丢弃，要有源码复核后的理由。
- 区分 `feature_introduced` 和 `feature_behavior_changed`：只有 base 不存在、target 存在时才写“新增功能”；两边都存在时只能写“已有功能行为变化候选”，必须说明具体变更点，不能套用跨 minor 的旧/新行为结论。
- `public-surface-findings.json` 只表示“新增用户可见入口”，不是自动等于升级风险；必须回到实现代码判断它是否改变默认行为、需要用户配置、影响兼容性、影响性能，或只是新增可选能力。
- 优先输出用户能直接验证或调整的行为变化：SQL 语义、配置默认值、配置移除/改名、系统变量、MV 激活/刷新/改写、导入/事务、存储/DataCache、客户端兼容、滚动升级风险。
- 如果发现“源版本所在分支已有修复但目标版本缺失”，单独作为“版本选择风险”写清楚受影响场景；不要只列 PR 号或一句“建议升更高 patch”。

```text
升级结论：
- 是否建议升级，是否存在明确阻断项。
- 如果没有阻断项，也要说明仍需重点验证的风险面。

重点差异：
【1】<变化点名称>
　　之前行为：说明基准版本的行为；如果基准版本没有该能力，明确写“旧版本没有该路径/参数/语义”。
　　现在行为：说明目标版本的新行为；写出默认值、参数名、开关名或用户可见入口。
　　触发条件：什么 SQL、配置、Schema、MV、导入、查询或运行场景会触发。
　　影响：可能出现的报错、结果变化、性能变化、兼容性风险或运维影响。
　　例子：只有能帮助用户理解时才给 SQL、错误信息或匹配示例；不要每条都强行给例子。
　　处理方式：按需给配置、SQL、升级前检查、灰度验证、回滚或规避方案。

【2】<变化点名称>
　　之前行为：...
　　现在行为：...
　　触发条件：...
　　影响：...
　　处理方式：...

建议：
- 给出升级前检查、灰度验证、配置调整或回滚预案。
```

差异条目的粒度应该面向用户能理解和执行的行为变化。例如：
- 配置默认值变化：写清楚默认值从什么变成什么、哪些 SQL/MV/表 schema 会受影响、需要设置哪个 FE/BE 配置规避。
- 配置移除或改名：写清楚旧配置是否还会被配置文件容忍、动态 `ADMIN SET CONFIG` 是否会失败、替代配置是什么。
- SQL 行为变化：写清楚相较旧版本的解析或执行差异、新版本与 MySQL 是否对齐、需要怎么改 SQL。
- MV 风险：写清楚为什么升级后激活、刷新、schema check 或 query rewrite 可能变化，并给出可执行的 `ALTER MATERIALIZED VIEW ... ACTIVE` 或相关配置建议。
- 导入/事务变化：写清楚影响 Stream Load、Routine Load、Flink/Spark Connector、Broker Load 还是 INSERT，并给出压测或参数建议。
- 新增功能影响：即使是可选功能，也要说明“旧版本没有 / 新版本支持后如何触发 / 不适用场景有什么副作用 / 如何关闭或验证”。例如 Stream Load `enable_merge_commit=true` 可能引入合并等待、队列压力或小批低延迟场景性能下降；3.4+ 的 INSERT-like task 超时可能改由 `insert_timeout` 控制，旧的 `query_timeout` 调整不再覆盖 `UPDATE`、`DELETE`、`CTAS`、MV refresh、统计收集、PIPE 等任务。
- 系统变量和任务属性变化：必须写清旧变量/属性是否还生效、新变量默认值、哪些任务路径改用新变量。例如 `insert_timeout` 要写出旧行为、目标默认 `14400` 秒、影响的任务类型，以及如何通过 session/global、MV/session property 或任务属性设置。
- 存储/DataCache 变化：写清楚缓存路径、容量、水位、预加载、compaction 或 storage volume 行为变化，以及需要检查的 `be.conf`/`fe.conf` 项。
- 协议、存储、导入、权限等风险：只在源码证据足够时输出，并说明滚动升级或混部验证要点。

不要输出 Java/C++ 代码片段。需要示例时优先给 SQL、配置、错误信息、输入输出行为对比。
不要单独输出“依据”“来源”“扫描过程”这类证据段落；PR、commit、源码文件只作为内部校验使用，除非用户明确要求看证据。

证据不足时再补充：

```text
还缺：
- ...
```

不要输出完整搜索过程。不要编造行号、配置名、变量名、PR、commit 或 StarRocks 行为。
