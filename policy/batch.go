package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
)

// maxBatchWorkers 是批量判定的并发度上限：有界并发保证大批量
// 不会拖慢同时进行的并发单条判定。
const maxBatchWorkers = 8

// BatchResult 是批量判定中单个资源的结论，顺序与输入资源清单一一对应。
type BatchResult struct {
	Resource Resource `json:"resource"`
	Decision Decision `json:"decision"`
}

// EvaluateBatch 对一批资源做批量判定。
// 一致性与确定性：
//   - 整批在评估开始时取一次快照，所有资源看到同一份完整策略视图，
//     同一批输入反复跑，结论与顺序完全一致（输出顺序 == 输入顺序）；
//   - 内部以有界 worker 池并行，资源之间互不阻塞，
//     也不会挤占同时进行的并发单条判定；
//   - 批量判定只读当前视图，绝不修改生效策略。
func (s *Store) EvaluateBatch(ctx context.Context, resources []Resource) []BatchResult {
	return evalBatch(ctx, s.cur.Load(), resources)
}

// evalBatch 在给定快照上批量评估资源：输出顺序与输入一致，
// 内部以有界 worker 池并行。
func evalBatch(ctx context.Context, snap *snapshot, resources []Resource) []BatchResult {
	results := make([]BatchResult, len(resources))
	for i, res := range resources {
		results[i].Resource = res
	}

	workers := min(maxBatchWorkers, runtime.NumCPU(), len(resources))
	if workers == 0 {
		return results
	}

	var wg sync.WaitGroup
	next := make(chan int)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				results[i].Decision = snap.evaluate(ctx, resources[i])
			}
		}()
	}
	for i := range resources {
		next <- i
	}
	close(next)
	wg.Wait()
	return results
}

// resourceManifest 是资源清单文件的顶层结构。
type resourceManifest struct {
	Resources []Resource `json:"resources"`
}

// LoadResources 从 JSON 字节加载资源清单。
// 清单整体无法解析时返回全局错误 MALFORMED_DOC；
// 单条资源缺少 kind/name 时返回带下标的 INVALID_VALUE 错误。
func LoadResources(data []byte) ([]Resource, error) {
	var top resourceManifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&top); err != nil {
		return nil, &LoadError{
			Policy:  "<resources>",
			Code:    ErrMalformedDoc,
			Message: err.Error(),
		}
	}
	for i, r := range top.Resources {
		if r.Kind == "" || r.Name == "" {
			return nil, &LoadError{
				Policy:  fmt.Sprintf("#%d", i),
				Code:    ErrInvalidValue,
				Field:   "resources",
				Message: "resource entries must have non-empty kind and name",
			}
		}
	}
	return top.Resources, nil
}
