package policy

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
)

// batchResources 构造一批覆盖放行/拒绝/例外/未命中四种情形的资源。
func batchResources() []Resource {
	return []Resource{
		{Kind: "Pod", Namespace: "prod", Name: "plain", Labels: map[string]string{"app": "web"}},
		{Kind: "Pod", Namespace: "prod", Name: "debug", Labels: map[string]string{"mode": "debug"}},
		{Kind: "Pod", Namespace: "sandbox", Name: "debug-sb", Labels: map[string]string{"mode": "debug"}},
		{Kind: "Service", Namespace: "prod", Name: "svc"},
	}
}

func logBatchResults(t *testing.T, tag string, results []BatchResult) {
	t.Helper()
	for _, r := range results {
		d := r.Decision
		t.Logf("[%s] resource=%s/%s/%s effect=%s reason=%s matched=%v excepted=%v version=%d basis=%q",
			tag, r.Resource.Kind, r.Resource.Namespace, r.Resource.Name,
			d.Effect, d.Reason, d.MatchedPolicies, d.ExceptedPolicies, d.Version, d.Explanation)
	}
}

// TestBatchDeterministic 验证同一批输入反复跑，结论与顺序完全一致，
// 且输出顺序与输入顺序一一对应。
func TestBatchDeterministic(t *testing.T) {
	store, lerrs, err := NewStoreFromManifest([]byte(manifestV2))
	if err != nil || len(lerrs) != 0 {
		t.Fatalf("init store: err=%v loadErrors=%v", err, lerrs)
	}
	resources := batchResources()

	first := store.EvaluateBatch(context.Background(), resources)
	logBatchResults(t, "run1", first)

	if len(first) != len(resources) {
		t.Fatalf("result count = %d, want %d", len(first), len(resources))
	}
	for i, r := range first {
		if !reflect.DeepEqual(r.Resource, resources[i]) {
			t.Fatalf("result #%d resource = %+v, want %+v (order must match input)",
				i, r.Resource, resources[i])
		}
	}

	for run := 0; run < 5; run++ {
		again := store.EvaluateBatch(context.Background(), resources)
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("run %d differs from first run:\nfirst=%+v\nagain=%+v", run, first, again)
		}
	}

	// 结论符合预期：debug 被拒、sandbox 例外跳过、Service 未命中。
	want := []struct {
		effect Effect
		reason ReasonCode
	}{
		{EffectAllow, ReasonAllowed},
		{EffectDeny, ReasonDenied},
		{EffectAllow, ReasonAllowed},
		{EffectAllow, ReasonNoMatch},
	}
	for i, w := range want {
		if d := first[i].Decision; d.Effect != w.effect || d.Reason != w.reason {
			t.Errorf("resource %s: got %s/%s, want %s/%s",
				resources[i].Name, d.Effect, d.Reason, w.effect, w.reason)
		}
	}
}

// TestBatchConsistentSnapshot 验证批量判定与热更新、并发单条判定同时发生时：
// 每一批内部所有结果都取自同一份完整视图（版本号一致），
// 并发单条判定也不被批量拖入不一致状态。
func TestBatchConsistentSnapshot(t *testing.T) {
	store, lerrs, err := NewStoreFromManifest([]byte(manifestV1))
	if err != nil || len(lerrs) != 0 {
		t.Fatalf("init store: err=%v loadErrors=%v", err, lerrs)
	}
	resources := batchResources()
	res := resources[1] // debug pod：V1 放行、V2 拒绝

	const rounds = 100
	stop := make(chan struct{})
	var wg sync.WaitGroup
	errCh := make(chan string, 1024)

	// 更新按 V1/V2 交替生效：奇数版本为 V1（放行），偶数版本为 V2（拒绝）。
	// 合法结论必须是某个完整视图的确定结果。
	valid := func(d Decision) bool {
		if d.Version%2 == 1 {
			return d.Effect == EffectAllow && d.Reason == ReasonAllowed &&
				reflect.DeepEqual(d.MatchedPolicies, []string{"allow-pods"})
		}
		return d.Effect == EffectDeny && d.Reason == ReasonDenied &&
			reflect.DeepEqual(d.MatchedPolicies, []string{"deny-debug"})
	}

	// 批量判定协程：每批内部版本号必须完全一致，
	// 且每个结论都是该版本完整视图的确定结果。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			results := store.EvaluateBatch(context.Background(), resources)
			v := results[0].Decision.Version
			for _, r := range results {
				if r.Decision.Version != v {
					errCh <- fmt.Sprintf("batch %d: mixed versions %d and %d",
						i, v, r.Decision.Version)
				}
			}
			// debug pod（resources[1]）在 V1/V2 下结论不同，最适合暴露半更新。
			if d := results[1].Decision; !valid(d) {
				errCh <- fmt.Sprintf("batch %d: inconsistent decision %+v", i, d)
			}
		}
	}()

	// 并发单条判定：同样只能看到完整视图。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if d := store.Evaluate(context.Background(), res); !valid(d) {
				errCh <- fmt.Sprintf("evaluate: inconsistent decision %+v", d)
			}
		}
	}()

	// 热更新协程：V2/V1 交替生效，使奇数版本恒为 V1、偶数版本恒为 V2。
	for i := 0; i < rounds; i++ {
		m := manifestV2
		if i%2 == 1 {
			m = manifestV1
		}
		if _, err := store.Update([]byte(m)); err != nil {
			t.Fatalf("update: %v", err)
		}
	}
	close(stop)
	wg.Wait()
	close(errCh)
	for msg := range errCh {
		t.Error(msg)
	}
	t.Logf("final version=%d (updates bumped version monotonically)", store.Version())
}
