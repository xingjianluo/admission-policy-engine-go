package policy

import (
	"context"
	"testing"
)

// TestVersionMonotonic 验证版本号只增不减：
// 只有真正生效的更新才推进版本；失败的更新与预演都不推进；
// 每次判定结果都能溯源到所用版本。
func TestVersionMonotonic(t *testing.T) {
	store, lerrs, err := NewStoreFromManifest([]byte(manifestV1))
	if err != nil || len(lerrs) != 0 {
		t.Fatalf("init store: err=%v loadErrors=%v", err, lerrs)
	}
	res := Resource{Kind: "Pod", Namespace: "prod", Name: "p1"}

	if got := store.Version(); got != 1 {
		t.Fatalf("initial version = %d, want 1", got)
	}
	d := store.Evaluate(context.Background(), res)
	t.Logf("resource=%s effect=%s reason=%s matched=%v version=%d basis=%q",
		res.Name, d.Effect, d.Reason, d.MatchedPolicies, d.Version, d.Explanation)
	if d.Version != 1 {
		t.Fatalf("decision version = %d, want 1", d.Version)
	}

	// 失败的更新（整体无法解析）：版本不动。
	if _, err := store.Update([]byte("{bad json")); err == nil {
		t.Fatal("malformed update should fail")
	}
	if got := store.Version(); got != 1 {
		t.Fatalf("version after failed update = %d, want 1", got)
	}

	// 生效的更新：版本前进到 2，判定可溯源。
	if _, err := store.Update([]byte(manifestV2)); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := store.Version(); got != 2 {
		t.Fatalf("version after update = %d, want 2", got)
	}
	d = store.Evaluate(context.Background(), res)
	t.Logf("resource=%s effect=%s reason=%s matched=%v version=%d basis=%q",
		res.Name, d.Effect, d.Reason, d.MatchedPolicies, d.Version, d.Explanation)
	if d.Version != 2 {
		t.Fatalf("decision version = %d, want 2", d.Version)
	}

	// 预演：不推进版本，但结果里标清对比双方版本。
	prev, err := store.Preview(context.Background(), []byte(candidateV3), []Resource{res})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if prev.BaseVersion != 2 || prev.CandidateVersion != 3 {
		t.Errorf("preview versions = base %d / candidate %d, want 2 / 3",
			prev.BaseVersion, prev.CandidateVersion)
	}
	if got := store.Version(); got != 2 {
		t.Errorf("version after preview = %d, want 2 (preview must not bump)", got)
	}

	// 失败的预演：版本同样不动。
	if _, err := store.Preview(context.Background(), []byte("not json"), []Resource{res}); err == nil {
		t.Fatal("malformed preview should fail")
	}
	if got := store.Version(); got != 2 {
		t.Errorf("version after failed preview = %d, want 2", got)
	}

	// 再次生效的更新：版本单调前进到 3，绝不回退。
	if _, err := store.Update([]byte(manifestV1)); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := store.Version(); got != 3 {
		t.Fatalf("version after second update = %d, want 3", got)
	}
	d = store.Evaluate(context.Background(), res)
	t.Logf("resource=%s effect=%s reason=%s matched=%v version=%d basis=%q",
		res.Name, d.Effect, d.Reason, d.MatchedPolicies, d.Version, d.Explanation)
	if d.Version != 3 {
		t.Fatalf("decision version = %d, want 3", d.Version)
	}
}

// TestBatchDecisionVersions 验证批量判定中每个资源的结论都带版本号，
// 且整批取自同一版本。
func TestBatchDecisionVersions(t *testing.T) {
	store, _, _ := NewStoreFromManifest([]byte(manifestV2))
	results := store.EvaluateBatch(context.Background(), batchResources())
	for _, r := range results {
		if r.Decision.Version != 1 {
			t.Errorf("resource %s: decision version = %d, want 1",
				r.Resource.Name, r.Decision.Version)
		}
	}
	t.Logf("batch of %d resources all traced to version %d",
		len(results), results[0].Decision.Version)
}
