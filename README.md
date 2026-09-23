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

## 验证方法

```sh
go build ./...        # 构建
go vet ./...          # 静态检查
go test ./... -race -count=1 -v
```

测试覆盖四类场景，日志中打印输入资源、命中的策略与最终判定依据：

| 测试                      | 场景                                             |
| ------------------------- | ------------------------------------------------ |
| `TestDenyOverridesAllow`  | 拒绝覆盖放行，两种书写顺序结论一致               |
| `TestExceptionHit`        | 例外命中跳过 / 未命中例外生效 / 完全未命中可区分 |
| `TestCanceledEvaluation`  | 取消的请求立即中止                               |
| `TestInvalidPolicies`     | 五类非法策略原因码可区分，合法策略不受影响       |
| `TestMalformedManifest`   | 清单整体无法解析返回全局错误                     |
| `TestConcurrentHotUpdate` | 32 读协程 + 200 轮 V1/V2 热更新，无半更新状态    |
