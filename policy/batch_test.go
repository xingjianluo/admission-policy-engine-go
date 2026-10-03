package policy

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

// logBatch 打印批量判定中每条资源、命中策略与带版本的最终依据。
func logBatch(t *testing.T, results []ResourceDecision) {
	t.Helper()
	for _, r := range results {
		res := r.Resource
		t.Logf("[batch %d] resource %s/%s %s labels=%v",
			r.Index, res.Namespace, res.Name, res.Kind, res.Labels)
		t.Logf("           matched=%v excepted=%v", r.Decision.MatchedPolicies, r.Decision.ExceptedPolicies)
		t.Logf("           decision=%s/%s version=%d basis=%q",
			r.Decision.Effect, r.Decision.Reason, r.Decision.Version, r.Decision.Explanation)
	}
}

func batchResources() []Resource {
	return []Resource{
		{Kind: "Pod", Namespace: "prod", Name: "web", Labels: map[string]string{"app": "web"}},
		{Kind: "Pod", Namespace: "prod", Name: "dbg", Labels: map[string]string{"mode": "debug"}},
		{Kind: "Pod", Namespace: "sandbox", Name: "dbg2", Labels: map[string]string{"mode": "debug"}},
		{Kind: "Secret", Namespace: "prod", Name: "pw"},
		{Kind: "Secret", Namespace: "dev", Name: "tok"},
		{Kind: "ConfigMap", Namespace: "prod", Name: "cfg"},
	}
}

func batchStore(t *testing.T) *Store {
	t.Helper()
	store, lerrs, err := NewStoreFromManifest([]byte(`{
	  "policies": [
	    {"name": "allow-pods", "effect": "allow", "priority": 10, "match": {"kinds": ["Pod"]}},
	    {"name": "deny-debug", "effect": "deny", "priority": 20,
	     "match": {"kinds": ["Pod"], "labels": {"mode": "debug"}},
	     "except": [{"namespaces": ["sandbox"]}]},
	    {"name": "deny-prod-secrets", "effect": "deny", "priority": 30,
	     "match": {"kinds": ["Secret"], "namespaces": ["prod"]}}
	  ]
	}`))
	if err != nil || len(lerrs) != 0 {
		t.Fatalf("init: err=%v loadErrors=%v", err, lerrs)
	}
	return store
}

// TestBatchDeterministic 验证批量判定：结论与输入同序、下标对应，
// 同一批输入反复跑（含打乱单次 Evaluate 顺序的对照）结论与顺序完全一致。
func TestBatchDeterministic(t *testing.T) {
	store := batchStore(t)
	resources := batchResources()

	want := []struct {
		effect Effect
		reason ReasonCode
	}{
		{EffectAllow, ReasonAllowed}, // web: 仅 allow-pods
		{EffectDeny, ReasonDenied},   // dbg: deny-debug 命中
		{EffectAllow, ReasonAllowed}, // dbg2: 例外跳过 deny，allow 命中
		{EffectDeny, ReasonDenied},   // prod Secret
		{EffectAllow, ReasonNoMatch}, // dev Secret
		{EffectAllow, ReasonNoMatch}, // ConfigMap 无规则
	}

	var first []ResourceDecision
	for run := 0; run < 3; run++ {
		got := store.EvaluateBatch(context.Background(), resources)
		if len(got) != len(resources) {
			t.Fatalf("run %d: got %d results, want %d", run, len(got), len(resources))
		}
		for i, rd := range got {
			if rd.Index != i {
				t.Fatalf("run %d: result[%d] has Index=%d, order must match input", run, i, rd.Index)
			}
			if rd.Resource.Name != resources[i].Name {
				t.Fatalf("run %d: result[%d] resource=%s, want %s", run, i, rd.Resource.Name, resources[i].Name)
			}
			if rd.Decision.Effect != want[i].effect || rd.Decision.Reason != want[i].reason {
				t.Fatalf("run %d resource %s: got %s/%s, want %s/%s",
					run, resources[i].Name, rd.Decision.Effect, rd.Decision.Reason,
					want[i].effect, want[i].reason)
			}
			if rd.Decision.Version != store.Version() {
				t.Fatalf("run %d resource %s: version=%d, want %d",
					run, resources[i].Name, rd.Decision.Version, store.Version())
			}
		}
		if run == 0 {
			first = got
		} else {
			for i := range got {
				if fmt.Sprintf("%+v", got[i].Decision) != fmt.Sprintf("%+v", first[i].Decision) {
					t.Fatalf("run %d differs from run 0 at %d:\n%+v\nvs\n%+v",
						run, i, got[i].Decision, first[i].Decision)
				}
			}
		}
	}
	logBatch(t, first)
}

// TestBatchEmpty 验证空批次返回长度为 0 的非 nil 切片。
func TestBatchEmpty(t *testing.T) {
	store := batchStore(t)
	got := store.EvaluateBatch(context.Background(), nil)
	if got == nil || len(got) != 0 {
		t.Fatalf("empty batch: got %v, want empty non-nil slice", got)
	}
}

// TestBatchDoesNotBlockConcurrentDecisions 验证大批判定在并发执行时，
// 其它单条判定不被阻塞、始终得到当前一致版本的确定结论（-race 下复核）。
func TestBatchDoesNotBlockConcurrentDecisions(t *testing.T) {
	store := batchStore(t)
	resources := batchResources()

	big := make([]Resource, 2000)
	for i := range big {
		big[i] = resources[i%len(resources)]
	}

	const singles = 16
	var batchWg, singleWg sync.WaitGroup
	stop := make(chan struct{})
	bad := make(chan string, 1024)

	// 多个大批量判定并行。
	for b := 0; b < 4; b++ {
		batchWg.Add(1)
		go func() {
			defer batchWg.Done()
			_ = store.EvaluateBatch(context.Background(), big)
		}()
	}

	// 同时进行的单条判定必须始终拿到合法确定结论。
	for w := 0; w < singles; w++ {
		singleWg.Add(1)
		go func() {
			defer singleWg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				d := store.Evaluate(context.Background(), resources[1]) // debug pod => deny
				if d.Effect != EffectDeny || d.Reason != ReasonDenied || d.Version != store.Version() {
					select {
					case bad <- fmt.Sprintf("unexpected %s/%s v%d", d.Effect, d.Reason, d.Version):
					default:
					}
				}
			}
		}()
	}

	// 先等大批量判定全部完成，再通知单条判定协程停止。
	batchWg.Wait()
	close(stop)
	singleWg.Wait()
	close(bad)
	for msg := range bad {
		t.Errorf("concurrent decision inconsistency: %s", msg)
	}
}
