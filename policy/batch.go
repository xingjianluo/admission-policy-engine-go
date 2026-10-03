package policy

import (
	"context"
	"runtime"
	"sync"
)

// maxBatchWorkers 限制单个批量判定的并发度，避免资源很多时
// 起海量协程挤占调度、拖慢同时在跑的其它判定。
func maxBatchWorkers() int {
	n := runtime.GOMAXPROCS(0)
	if n < 1 {
		n = 1
	}
	if n > 8 {
		n = 8
	}
	return n
}

// EvaluateBatch 在同一份一致快照上并发判定一批资源。
//
// 语义：
//   - 评估开始时取一次当前快照，整批看到完整一致的同一版本策略；
//   - 各资源在有界 worker 池中独立评估，互不阻塞，也不持有全局读锁，
//     因而不会拖慢同时在跑的并发判定（读路径仍无锁）；
//   - 返回切片与输入严格同序、Index 与下标对应；同一批输入反复跑，
//     结论与顺序完全一致（确定性来自排序后的快照与按下标回填）；
//   - 空批次返回长度为 0 的非 nil 切片。
func (s *Store) EvaluateBatch(ctx context.Context, resources []Resource) []ResourceDecision {
	return evaluateBatchOn(ctx, s.snapshot(), resources)
}

// evaluateBatchOn 在给定快照上并发判定，供批量判定与预演复用。
func evaluateBatchOn(ctx context.Context, snap *snapshot, resources []Resource) []ResourceDecision {
	out := make([]ResourceDecision, len(resources))

	workers := maxBatchWorkers()
	if len(resources) < workers {
		workers = len(resources)
	}
	if workers == 0 {
		return out
	}

	var wg sync.WaitGroup
	jobs := make(chan int)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				// 结论写入各自独立下标，无需加锁；顺序由回填位置决定。
				out[i] = ResourceDecision{
					Index:    i,
					Resource: resources[i],
					Decision: snap.evaluate(ctx, resources[i]),
				}
			}
		}()
	}
	for i := range resources {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return out
}
