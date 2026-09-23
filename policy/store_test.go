package policy

import (
	"context"
	"sync"
	"testing"
)

const (
	manifestV1 = `{"policies": [
		{"name": "allow-pods", "effect": "allow", "priority": 10, "match": {"kinds": ["Pod"]}}
	]}`
	manifestV2 = `{"policies": [
		{"name": "allow-pods", "effect": "allow", "priority": 10, "match": {"kinds": ["Pod"]}},
		{"name": "deny-debug", "effect": "deny", "priority": 20,
		 "match": {"kinds": ["Pod"], "labels": {"mode": "debug"}},
		 "except": [{"namespaces": ["sandbox"]}]}
	]}`
)

// TestConcurrentHotUpdate 验证热更新与并发评估的一致性：
// 每个请求必须看到完整一致的策略视图（V1 或 V2 之一），
// 结论只能是两个完整视图各自的确定结果，不得出现半更新状态。
func TestConcurrentHotUpdate(t *testing.T) {
	store, lerrs, err := NewStoreFromManifest([]byte(manifestV1))
	if err != nil || len(lerrs) != 0 {
		t.Fatalf("init store: err=%v loadErrors=%v", err, lerrs)
	}

	res := Resource{Kind: "Pod", Namespace: "prod", Name: "p1",
		Labels: map[string]string{"mode": "debug"}}

	// 完整视图下唯一合法的两种结论。
	valid := func(d Decision) bool {
		v1 := d.Effect == EffectAllow && d.Reason == ReasonAllowed &&
			len(d.MatchedPolicies) == 1 && d.MatchedPolicies[0] == "allow-pods"
		v2 := d.Effect == EffectDeny && d.Reason == ReasonDenied &&
			len(d.MatchedPolicies) == 1 && d.MatchedPolicies[0] == "deny-debug"
		return v1 || v2
	}

	const readers = 32
	const rounds = 200

	var wg sync.WaitGroup
	stop := make(chan struct{})
	errCh := make(chan Decision, readers*rounds)

	// 并发读取：互不阻塞，各自取一次快照完成整个评估。
	for i := 0; i < readers; i++ {
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
					errCh <- d
				}
			}
		}()
	}

	// 单写者来回热更新 V1 <-> V2。
	for i := 0; i < rounds; i++ {
		m := manifestV1
		if i%2 == 1 {
			m = manifestV2
		}
		if lerrs, err := store.Update([]byte(m)); err != nil || len(lerrs) != 0 {
			t.Fatalf("update round %d: err=%v loadErrors=%v", i, err, lerrs)
		}
	}
	close(stop)
	wg.Wait()
	close(errCh)

	for d := range errCh {
		t.Errorf("inconsistent decision (partial update observed): %+v", d)
	}

	// 日志展示两个完整视图各自的确定结论。
	dV1 := NewStore(mustLoad(t, manifestV1)).Evaluate(context.Background(), res)
	logDecision(t, res, dV1)
	dV2 := NewStore(mustLoad(t, manifestV2)).Evaluate(context.Background(), res)
	logDecision(t, res, dV2)
}

func mustLoad(t *testing.T, manifest string) []Policy {
	t.Helper()
	res, err := LoadManifest([]byte(manifest))
	if err != nil || len(res.Errors) != 0 {
		t.Fatalf("load manifest: err=%v loadErrors=%v", err, res.Errors)
	}
	return res.Policies
}
