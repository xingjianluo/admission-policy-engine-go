# 本地准入策略评估与热更新引擎

用本地 JSON 策略清单与资源清单模拟 Kubernetes 风格的准入判定，支持严格加载校验、
拒绝覆盖放行、规则例外、原子热更新与并发一致评估。仅依赖 Go 标准库。

## 目录结构

| 路径 | 说明 |
| --- | --- |
| `policy/types.go` | 统一模型：`Policy` / `Rule` / `Selector` / `Resource` / `Effect` |
| `policy/loader.go` | 清单解析、严格校验与归一化，产出稳定可区分的错误原因码 |
| `policy/engine.go` | 匹配、例外、优先级与拒绝覆盖语义；输出完整判定轨迹 |
| `policy/store.go` | copy-on-write 快照 + `atomic.Pointer` 的热更新存储 |
| `policy/engine_test.go` | 拒绝覆盖 / 例外命中 / 非法策略 / 并发热更新 四类测试 |
| `cmd/engine/main.go` | 演示入口：加载清单文件并逐条评估 |
| `examples/` | 示例策略与资源清单 |

## 策略结构

策略清单为单个 JSON 对象，顶层 `policies` 为策略数组：

```json
{
  "policies": [
    {
      "name": "prod-guard",
      "rules": [
        {
          "name": "deny-prod-pods",
          "effect": "deny",
          "priority": 100,
          "match": {"kinds": ["Pod"], "namespaces": ["prod"]},
          "except": [
            {"names": ["whitelist-pod"]},
            {"labels": {"tier": "system"}}
          ]
        }
      ]
    }
  ]
}
```

- **Policy**：`name`（必填，全清单唯一）、`rules`（至少一条，规则名在策略内唯一）。
- **Rule**：
  - `name` 必填；
  - `effect` 必填，仅允许 `"allow"` / `"deny"`；
  - `priority` 为整数，越大越优先（仅用于同效果规则间决定“最终依据”，见下）；
  - `match` 为资源选择器；
  - `except` 为选择器数组，命中任一即从该规则中豁免。
- **Selector**：`kinds` / `namespaces` / `names` / `labels` 四个条件，
  条件之间取 AND，同一字段的多个取值取 OR；`labels` 要求资源标签全部等于指定键值。
  空选择器不匹配任何资源（避免“空例外=排除全部”这类歧义）。
- **Resource**：`kind` / `namespace` / `name` / `labels`。

## 加载校验：不静默跳过任何非法策略

`LoadManifest` 使用严格解码（拒绝未知字段、类型错误）并逐条校验。
每条非法策略单独产生一个 `*LoadError`，携带稳定的原因码，**不影响其余策略加载**：

| 原因码 | 触发场景 |
| --- | --- |
| `INVALID_JSON` | 顶层 JSON 语法错误 |
| `MISSING_FIELD` | 缺少 `policies`、策略/规则 `name`、`effect`，或策略无规则 |
| `INVALID_TYPE` | 字段类型错误（如 `"rules": 123`） |
| `INVALID_VALUE` | `effect` 取值非法、标签键为空等 |
| `CONFLICT` | 策略名重复、同一策略内规则名重复 |
| `EMPTY_MANIFEST` | `policies` 为空数组 |

## 判定语义：优先级、拒绝覆盖与例外

对资源逐条评估所有规则，每条规则都会在 `Decision.Traces` 中留下轨迹
（`matched` / `excepted` / `applied` 三个布尔位）：

1. 资源不满足 `match` → 未命中（`matched=false`）；
2. 满足 `match` 且满足任一 `except` 选择器 → **命中但被例外跳过**
   （`matched=true, excepted=true`），该规则不参与判定；例外只对命中的资源生效；
3. 满足 `match` 且不被例外 → 生效（`applied=true`），按 `effect` 计入。

最终结论（`Decision.Outcome`）：

- 只要存在任一**生效的 deny 规则**即为 `denied`：**拒绝覆盖放行**；
- 否则存在生效的 allow 规则即为 `allowed`；
- 有规则命中但全部被例外跳过，结论为 `allowed`，原因明确说明
  “all matching rules were skipped by exceptions”；
- 没有任何规则命中为 `no_match`（默认放行）。**未命中、被例外跳过、被拒绝三种情况可由
  outcome 与 trace 明确区分。**

**与书写顺序无关**：判定不依赖规则在清单中的顺序。`priority` 仅在同效果的多条规则
都生效时决定最终原因引用哪一条（取最高优先级）；deny 的优先级再高也不会被高优先级
allow 压过，反之低优先级 deny 依然覆盖任意 allow。

## 热更新一致性保证

`Store` 内部以 `atomic.Pointer[Snapshot]` 持有一个**不可变快照**：

- `Update(policies)` 拷贝入参后构建新版本快照，一次性原子发布（copy-on-write），
  不存在“部分规则已替换、部分仍旧”的半更新状态；
- `Evaluate` 在开始时执行**且仅执行一次**原子加载，之后整次评估只使用该快照。
  因此更新进行时，已开始的请求看到的必然是完整的旧版本或完整的新版本，
  `Decision.Version` 标明其依据的快照版本；
- 读取路径无锁，并发评估互不阻塞、互不影响；
- `context.Context`：评估在开始及遍历每条策略前检查取消，
  请求被取消时立即停止并返回 `context.Canceled` / `context.DeadlineExceeded`。

## 验证方法

```bash
# 全部单测（含竞态检测）
go test ./... -race -count=1 -v

# 演示程序
go run ./cmd/engine -policies examples/policies.json -resources examples/resources.json
```

测试覆盖四类场景（`policy/engine_test.go`），且每条用例均用 `t.Logf` 打印
**输入资源、每条规则的命中/例外/生效轨迹与最终判定依据**：

1. `TestDenyOverridesAllow`：allow 与 deny 同时命中，调换书写顺序后结论一致；
2. `TestExceptionSemantics`：按名字、按标签例外，普通资源拒绝，未命中资源 `no_match`；
3. `TestInvalidPolicies`：缺失字段 / 类型错误 / 冲突 / 非法取值产出不同原因码，
   合法策略仍可加载与生效；
4. `TestConcurrentEvaluationAndHotUpdate`：16 goroutine × 200 次评估与持续热更新并发，
   逐条校验结论必须与其快照版本的预期一致（`-race` 下验证无数据竞争）；
   另有 `TestCanceledContext` 验证取消立即返回。
