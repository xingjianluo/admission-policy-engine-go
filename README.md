# admission-policy-engine-go

本地准入策略评估与热更新引擎：从本地策略清单加载并归一到统一模型，
对资源清单做准入判定；支持策略热更新与并发评估，结论一致、可解释。
在此之上提供三项能力：**批量判定**、**变更预演**、**版本溯源**。

## 策略结构

策略清单为 JSON 文件，顶层包含 `policies` 数组，单条策略：

```json
{
  "policies": [
    {
      "name": "deny-debug-pods",
      "effect": "deny",
      "priority": 20,
      "match": {
        "kinds": ["Pod"],
        "namespaces": ["prod"],
        "labels": {"mode": "debug"}
      },
      "except": [
        {"namespaces": ["sandbox"]}
      ]
    }
  ]
}
```

| 字段       | 说明                                                         |
| ---------- | ------------------------------------------------------------ |
| `name`     | 必填，全局唯一；重名视为冲突（`CONFLICT`）                   |
| `effect`   | 必填，`allow` 或 `deny`                                      |
| `priority` | 可选，整数；数值大者先评估，同级按名称排序，结论与书写顺序无关 |
| `match`    | 必填且非空；`kinds`/`namespaces`/`labels` 之间为 AND         |
| `except`   | 可选，例外子句列表；资源命中任一子句时跳过本规则             |

待判定资源：

```json
{"kind": "Pod", "namespace": "prod", "name": "p1", "labels": {"mode": "debug"}}
```

## 加载与校验

`LoadManifest(data)` 将清单归一到统一模型：

- 字段缺失、类型错误、取值非法、策略冲突分别返回稳定原因码
  `MISSING_FIELD` / `INVALID_TYPE` / `INVALID_VALUE` / `CONFLICT`，
  绝不静默跳过；
- 单条非法策略被剔除并逐条返回 `LoadError`，不影响其余策略的可用性；
- 清单整体无法解析时返回全局错误 `MALFORMED_DOC`，当前视图保持不变。

## 匹配、优先级与例外语义

- 选择器内所有非空字段需同时满足（AND）；例外子句同理。
- 评估按 `priority` 降序、名称升序进行，结论确定且与清单书写顺序无关。
- **拒绝覆盖放行**：任一 `deny` 规则命中（且未被例外跳过）即拒绝，
  无论有多少 `allow` 规则命中、书写顺序如何。
- **例外只对命中的资源生效**：资源命中规则的 `except` 子句时，
  仅该规则对该资源被跳过，其余规则不受影响。
- 三种情况按原因码区分：
  - `NO_MATCH`：无任何规则命中；
  - `EXCEPTED`：规则命中但全部被例外跳过（记录于 `ExceptedPolicies`）；
  - `DENIED`：命中拒绝规则（记录于 `MatchedPolicies`）。
- 每次评估返回 `Decision`，含命中/被例外策略列表与人类可读的
  `Explanation` 判定依据。

## 批量判定

`Store.EvaluateBatch(ctx, resources)` 一次传入一批资源，返回
`[]ResourceDecision`，逐条给出放行/拒绝、判定依据、命中策略与被例外
跳过的策略。

- **同序且确定**：返回切片与输入严格同序，`Index` 与下标对应；
  命中列表来自按优先级/名称排序后的不可变快照，故同一批输入反复跑，
  结论和顺序完全一样，与协程调度无关。
- **并发不互相阻塞**：各资源在有界 worker 池（上限 `GOMAXPROCS`，
  封顶 8）中独立评估，结论写入各自独立下标、无需加锁；读路径仍无锁，
  批量判定不会持有全局锁，也不会把同时在跑的单条判定拖慢。
- **同一版本**：批量开始时取一次当前快照，整批复用同一份完整一致的
  策略视图与版本号；空批次返回长度为 0 的非 nil 切片。

## 变更预演

`Store.Preview(ctx, candidateManifest, resources)` 在**不动当前生效
策略**的前提下，拿一份候选策略清单对同一批资源试算，并与当前策略逐条
对比，返回 `PreviewResult`：

- 逐资源给出 `Current` / `Candidate` 两份结论与差异归类：
  - `ALLOW_TO_DENY`：原来放行，候选下被拒；
  - `DENY_TO_ALLOW`：原来拒绝，候选下放行；
  - `BASIS_CHANGED`：放行/拒绝方向没变，但原因码、命中或例外依据变了；
  - `UNCHANGED`：完全无变化。每条都带一句话 `Summary`，差异一眼看清。
- **隔离且只读**：候选策略只编译成本次调用内的临时快照，不读取也不
  写入当前视图；预演绝不修改当前生效策略，也不推进版本号。预演期间
  其它协程的正式判定/热更新继续进行，正式请求始终看到完整一致的当前
  版本（新或旧之一），不会出现半新半旧。
- **候选自身有问题时明确报坏**：为空、字段不全、取值非法、重名冲突等
  逐条记录在 `Errors`（定位到策略名或下标），`CandidateOK=false`，
  其余合法条目照常参与试算；即使合法条目为零，也显式返回
  `EMPTY_CANDIDATE` 原因码，**绝不混同为“没策略、一律放行”**。
- **整份解析失败直接失败**：候选内容根本解析不了（`MALFORMED_DOC`）
  时返回全局错误、结果为 nil，当前策略与版本保持现状。
- 预演是只读操作，可与正式 `Update` 并发安全调用。

## 版本溯源

- 每个生效的策略快照对应一个**只增不减**的 `int64` 版本号：初始生效
  版本为 `1`，此后每次**成功**的 `Update` +1；更新以互斥串行化，保证
  版本严格单调递增。
- **失败的更新不推进版本**（整份解析失败时视图与版本保持原样）；
  **单纯预演不推进版本**（候选使用独立的内容指纹标识，不占正式版本号）。
- 每条 `Decision.Version` 标明本次判定用的是哪个版本；批量判定中每条
  结论都带同一快照版本。
- `PreviewResult` 同时标清对比双方：`CurrentVersion` 为预演所基于的
  当前生效版本，`CandidateVersion` 为候选内容的稳定指纹
  （`candidate-<sha256 前缀>`，相同候选内容指纹一致，可重复溯源）。

## 与热更新一致性的配合及兼容范围

- 三项新能力都建立在原有“`atomic.Pointer` 指向不可变快照 + 读路径无锁”
  的模型上：单条判定、批量判定、预演各自在开始时取一次快照，整个请求
  看到完整一致的视图，与热更新互不产生半更新状态。
- 预演是**纯只读旁路**：它不替换快照、不触碰版本计数，因此与“更新过程
  中并发请求始终看到一致结果”的保证完全兼容；正式判定永远只引用当前
  生效快照。
- 兼容范围：原 `Evaluate` / `Update` / `LoadManifest` 签名保持不变，
  `Decision` 仅新增 `Version` 字段（JSON 追加字段），旧判定用例无回归。
  批量与预演为新增 API；上下文取消（`CANCELED`）语义在批量与预演中
  通过同一评估路径继续生效。

## 本地示例

仓库自带策略清单与资源清单，无需另写代码即可看到批量判定（含预演）结果：

```sh
go run ./cmd/batch-demo
```

该命令内嵌 `cmd/batch-demo/policies.json` 与 `resources.json`，逐条
打印资源、放行/拒绝、命中与被例外策略、判定依据与版本，并演示一次
“新增拒绝规则”的预演差异，最后确认生效版本未被预演改动。

## 验证方法

```sh
go build ./...                       # 构建
go vet ./...                         # 静态检查
gofmt -l .                           # 格式检查（无输出即干净）
go test ./... -race -count=1 -v      # 带竞态检测的测试
go run ./cmd/batch-demo              # 本地批量判定 + 预演示例
```

测试日志逐条打印本次跑的是哪个资源、命中/被例外了哪些策略、最终依据
（含版本号）。覆盖场景：

| 测试                                  | 场景                                                       |
| ------------------------------------- | ---------------------------------------------------------- |
| `TestDenyOverridesAllow`              | 拒绝覆盖放行，两种书写顺序结论一致                         |
| `TestExceptionHit`                    | 例外命中跳过 / 未命中例外生效 / 完全未命中可区分           |
| `TestCanceledEvaluation`              | 取消的请求立即中止                                         |
| `TestInvalidPolicies`                 | 非法策略原因码可区分，合法策略不受影响                     |
| `TestMalformedManifest`               | 清单整体无法解析返回全局错误                               |
| `TestConcurrentHotUpdate`             | 32 读协程 + 200 轮 V1/V2 热更新，无半更新状态              |
| `TestBatchDeterministic`              | 批量结论与输入同序、下标对应，反复跑结论顺序完全一致       |
| `TestBatchEmpty`                      | 空批次返回空的非 nil 切片                                  |
| `TestBatchDoesNotBlockConcurrentDecisions` | 大批量并行时不拖慢同时在跑的单条判定，结论一致、带版本 |
| `TestPreviewDiffClassification`       | 三种差异方向 + 无变化准确区分，预演不改动当前策略/版本     |
| `TestPreviewBasisChanged`             | 方向不变但命中依据变化归为 BASIS_CHANGED                   |
| `TestPreviewInvalidCandidate`         | 候选非法/冲突逐条报错、合法条目仍参与，不当作一律放行      |
| `TestPreviewEmptyCandidate`           | 空候选 / 全部非法被显式标为 EMPTY_CANDIDATE                |
| `TestPreviewMalformedCandidate`       | 整份解析不了直接失败并保持现状                             |
| `TestPreviewConcurrentWithLiveUpdates` | 预演期间并发正式热更新与判定始终看到完整一致视图           |
| `TestVersionMonotonicAndTraceability` | 版本单调递增、失败更新与预演不推进、判定/预演可溯源        |
| `TestBatchAndPreviewCarryVersion`     | 批量每条结论带版本，预演标清当前版本与候选指纹             |
