package policy

import (
	"context"
	"testing"
)

// TestVersionMonotonicAndTraceability 验证：
//   - 初始版本为 1，每次成功生效 +1，只增不减；
//   - 失败的更新（整体解析失败）不推进版本，视图保持原样；
//   - 单纯预演不推进版本；
//   - 判定结果带所用版本，预演结果标清“当前版本 vs 候选版本”。
func TestVersionMonotonicAndTraceability(t *testing.T) {
	store, _, err := NewStoreFromManifest([]byte(manifestV1))
	if err != nil {
		t.Fatal(err)
	}
	if v := store.Version(); v != 1 {
		t.Fatalf("initial version = %d, want 1", v)
	}

	res := Resource{Kind: "Pod", Namespace: "prod", Name: "p1"}

	// 初始判定可溯源到版本 1。
	if d := store.Evaluate(context.Background(), res); d.Version != 1 {
		t.Fatalf("decision version=%d, want 1", d.Version)
	}
	t.Logf("decision on %s/%s uses version=%d", res.Namespace, res.Name, 1)

	// 成功更新推进版本：1 -> 2。
	if _, err := store.Update([]byte(manifestV2)); err != nil {
		t.Fatalf("update V2: %v", err)
	}
	if v := store.Version(); v != 2 {
		t.Fatalf("after successful update version=%d, want 2", v)
	}
	if d := store.Evaluate(context.Background(), res); d.Version != 2 {
		t.Fatalf("decision version=%d, want 2", d.Version)
	}
	t.Logf("after update, decision on %s/%s uses version=%d", res.Namespace, res.Name, 2)

	// 失败的更新（整份解析不了）不推进版本，保持 2。
	if _, err := store.Update([]byte(`{"policies": [`)); err == nil {
		t.Fatal("expected malformed update to fail")
	}
	if v := store.Version(); v != 2 {
		t.Fatalf("failed update must not advance version, got %d", v)
	}
	if d := store.Evaluate(context.Background(), res); d.Version != 2 {
		t.Fatalf("decision after failed update version=%d, want still 2", d.Version)
	}
	t.Logf("after FAILED update, version stays %d and decisions still trace to it", 2)

	// 单纯预演不推进版本，并标清当前版本与候选版本。
	before := store.Version()
	p, err := store.Preview(context.Background(), []byte(manifestV1), []Resource{res})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if p.CurrentVersion != before {
		t.Fatalf("preview CurrentVersion=%d, want %d", p.CurrentVersion, before)
	}
	if p.CandidateVersion == "" || p.CandidateVersion == "candidate-unknown" {
		t.Fatalf("candidate version must be a stable non-empty fingerprint, got %q", p.CandidateVersion)
	}
	if store.Version() != before {
		t.Fatalf("preview must not advance live version, got %d", store.Version())
	}
	t.Logf("preview compares current v%d against candidate %s; live stays v%d",
		p.CurrentVersion, p.CandidateVersion, store.Version())

	// 相同候选内容指纹必须稳定一致（可重复溯源）。
	p2, _ := store.Preview(context.Background(), []byte(manifestV1), []Resource{res})
	if p2.CandidateVersion != p.CandidateVersion {
		t.Fatalf("fingerprint not stable: %s vs %s", p.CandidateVersion, p2.CandidateVersion)
	}

	// 再一次成功更新：版本继续单调递增到 3。
	if _, err := store.Update([]byte(manifestV1)); err != nil {
		t.Fatalf("update V1: %v", err)
	}
	if v := store.Version(); v != 3 {
		t.Fatalf("version=%d, want 3 (monotonic)", v)
	}
}

// TestBatchAndPreviewCarryVersion 验证批量判定每条结论都带版本，
// 预演两侧结论分别可溯源（当前侧带当前版本号）。
func TestBatchAndPreviewCarryVersion(t *testing.T) {
	store := mustStore(t, previewBase)
	resources := previewResources()

	batch := store.EvaluateBatch(context.Background(), resources)
	for _, rd := range batch {
		if rd.Decision.Version != store.Version() {
			t.Fatalf("batch[%d] version=%d, want %d",
				rd.Index, rd.Decision.Version, store.Version())
		}
		t.Logf("batch[%d] %s/%s -> %s/%s @v%d",
			rd.Index, rd.Resource.Namespace, rd.Resource.Name,
			rd.Decision.Effect, rd.Decision.Reason, rd.Decision.Version)
	}

	p, err := store.Preview(context.Background(), []byte(manifestV2), resources)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	for _, ch := range p.Changes {
		if ch.Current.Version != p.CurrentVersion {
			t.Fatalf("change[%d] current version=%d, want %d",
				ch.Index, ch.Current.Version, p.CurrentVersion)
		}
	}
	t.Logf("preview current-side decisions trace to v%d; candidate labeled %s",
		p.CurrentVersion, p.CandidateVersion)
}
