# admission-policy-engine-go

本地准入策略评估与热更新引擎：从本地策略清单加载并归一到统一模型，
对资源清单做准入判定；支持策略热更新与并发评估，结论一致、可解释。

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

## 热更新一致性保证

- 当前策略视图保存在 `atomic.Pointer` 指向的**不可变快照**中；
  `Update` 先整体编译新清单，再一次原子替换，不存在部分生效或半更新状态。
- 评估开始时取一次快照，整个请求看到完整一致的视图（新或旧之一）；
  更新期间已开始的请求继续使用旧视图直至完成。
- 读路径无锁，并发读取互不阻塞；`-race` 下验证通过。
- 传入的 `context.Context` 被取消时，评估立即中止并返回
  `reason=CANCELED`。

## 批量判定

`Store.EvaluateBatch(ctx, resources)` 一次传入一批资源做批量判定，
每个资源都能得到放行/拒绝结论、判定依据、命中策略与被例外跳过的策略：

- 整批在评估开始时取**一次快照**，所有资源看到同一份完整策略视图；
  同一批输入反复跑，结论与顺序完全一致（输出顺序 == 输入顺序）。
- 内部以**有界 worker 池**（上限 8）并行：资源之间互不阻塞，
  大批量也不会挤占同时进行的并发单条判定。
- 批量判定只读当前视图，绝不修改生效策略。

资源清单为 JSON 文件，顶层包含 `resources` 数组，用
`LoadResources(data)` 加载。仓库内置可直接运行的本地示例
（`examples/` 下现成清单，无需另写代码）：

```sh
go run ./cmd/batchdemo
# 打印每个资源的 effect/reason/命中策略/判定依据（含版本号）
```

## 变更预演

`Store.Preview(ctx, candidate, resources)` 在**不动当前生效策略**的前提下，
拿候选策略清单对同一批资源先试算一遍，再与当前策略逐一对比：

- 每个资源给出变化类型：`ALLOW_TO_DENY` / `DENY_TO_ALLOW` /
  `BASIS_CHANGED`（放行拒绝不变但命中或例外依据变了）/ `UNCHANGED`，
  并附人类可读的 `Summary`，差异一眼可见。
- 预演全程只读当前视图：正在进行的正式判定继续使用当前生效策略、
  看到完整一致的结果；预演本身绝不修改生效策略、也不推进版本号。
- 候选清单中单条非法策略（字段缺失、取值非法、条目冲突）被剔除并
  逐条记入 `PreviewResult.LoadErrors`，其余合法条目照常参与试算。
- 候选清单没有任何可用策略（为空或全部非法）时返回 `EMPTY_MANIFEST`
  错误，**绝不**按"没策略、一律放行"混过去；整体无法解析时返回
  `MALFORMED_DOC`，预演直接失败并保持现状。

## 版本溯源

- 每次策略真正生效（初始加载及每次成功的 `Update`）都对应一个
  **只增不减**的版本号，从 1 开始单调递增；`Store.Version()` 可查当前版本。
- 每条 `Decision` 都带 `Version` 字段，可溯源本次判定用的是哪个版本；
  批量判定中整批结果共享同一版本。
- 预演结果带 `BaseVersion`（对比的当前版本）与 `CandidateVersion`
  （候选若生效将获得的版本，即当前版本 +1，仅作标识）。
- **失败的更新和单纯的预演都不会让版本往前走。**

## 能力配合与兼容范围

- 批量判定、变更预演与热更新一致性是同一套机制的延伸：三者都建立在
  "不可变快照 + 原子替换"之上，读路径（单条/批量/预演）全程无锁，
  只有 `Update` 的生效动作被串行化，保证版本号与视图严格同序推进。
- 兼容范围：本引擎面向**本地、单进程**的策略评估与预演；
  不跨进程共享视图，不做持久化，清单格式以本文档的 JSON 结构为准。

## 验证方法

```sh
go build ./...        # 构建
go vet ./...          # 静态检查
go test ./... -race -count=1 -v   # 带竞态检测跑全部测试
go run ./cmd/batchdemo            # 本地批量判定示例
```

测试覆盖以下场景，日志中打印输入资源、命中的策略与最终判定依据（含版本号）：

| 测试                          | 场景                                                       |
| ----------------------------- | ---------------------------------------------------------- |
| `TestDenyOverridesAllow`      | 拒绝覆盖放行，两种书写顺序结论一致                         |
| `TestExceptionHit`            | 例外命中跳过 / 未命中例外生效 / 完全未命中可区分           |
| `TestCanceledEvaluation`      | 取消的请求立即中止                                         |
| `TestInvalidPolicies`         | 五类非法策略原因码可区分，合法策略不受影响                 |
| `TestMalformedManifest`       | 清单整体无法解析返回全局错误                               |
| `TestConcurrentHotUpdate`     | 32 读协程 + 200 轮 V1/V2 热更新，无半更新状态              |
| `TestBatchDeterministic`      | 批量判定反复跑结论与顺序完全一致，输出顺序对齐输入         |
| `TestBatchConsistentSnapshot` | 批量 + 热更新 + 并发单条判定并行，每批内部版本一致         |
| `TestPreviewDiff`             | 预演识别放行/拒绝翻转与依据变化，对比双方版本标注正确      |
| `TestPreviewDoesNotMutate`    | 预演期间并发正式判定始终一致，预演不改策略、不推进版本     |
| `TestPreviewInvalidCandidate` | 候选部分非法：坏条目逐条报告，好条目照常参与试算           |
| `TestPreviewUnusableCandidate`| 候选为空 / 全部非法 / 无法解析：明确报错并保持现状         |
| `TestVersionMonotonic`        | 版本只增不减，失败更新与预演不推进版本，判定可溯源         |
| `TestBatchDecisionVersions`   | 批量判定每个结论带版本号，整批取自同一版本                 |
