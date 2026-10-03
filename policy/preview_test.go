package policy

import (
	"context"
	"strings"
	"sync"
	"testing"
)

// candidateV3 在 V2 基础上：放宽 debug 拒绝（加 prod 例外）、
// 新增 sandbox 专属放行（改变命中依据）、新增 ConfigMap 拒绝。
const candidateV3 = `{"policies": [
	{"name": "allow-pods", "effect": "allow", "priority": 10, "match": {"kinds": ["Pod"]}},
	{"name": "deny-debug", "effect": "deny", "priority": 20,
	 "match": {"kinds": ["Pod"], "labels": {"mode": "debug"}},
	 "except": [{"namespaces": ["sandbox"]}, {"namespaces": ["prod"]}]},
	{"name": "allow-sandbox", "effect": "allow", "priority": 15, "match": {"namespaces": ["sandbox"]}},
	{"name": "deny-configmaps", "effect": "deny", "priority": 5, "match": {"kinds": ["ConfigMap"]}}
]}`

func logDiffs(t *testing.T, tag string, res *PreviewResult) {
	t.Helper()
	for _, d := range res.Diffs {
		t.Logf("[%s] resource=%s/%s/%s change=%s base=%s/%s(v%d) candidate=%s/%s(v%d) summary=%q",
			tag, d.Resource.Kind, d.Resource.Namespace, d.Resource.Name, d.Change,
			d.Base.Effect, d.Base.Reason, d.Base.Version,
			d.Candidate.Effect, d.Candidate.Reason, d.Candidate.Version, d.Summary)
	}
}

// TestPreviewDiff 验证预演能识别放行/拒绝翻转与依据变化，
// 并正确标注对比双方版本。
func TestPreviewDiff(t *testing.T) {
	store, lerrs, err := NewStoreFromManifest([]byte(manifestV2))
	if err != nil || len(lerrs) != 0 {
		t.Fatalf("init store: err=%v loadErrors=%v", err, lerrs)
	}
	resources := []Resource{
		{Kind: "Pod", Namespace: "prod", Name: "debug", Labels: map[string]string{"mode": "debug"}},
		{Kind: "Pod", Namespace: "sandbox", Name: "debug-sb", Labels: map[string]string{"mode": "debug"}},
		{Kind: "ConfigMap", Namespace: "prod", Name: "cfg"},
		{Kind: "Pod", Namespace: "prod", Name: "plain"},
	}

	res, err := store.Preview(context.Background(), []byte(candidateV3), resources)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	logDiffs(t, "preview", res)

	if res.BaseVersion != 1 || res.CandidateVersion != 2 {
		t.Errorf("versions = base %d / candidate %d, want 1 / 2",
			res.BaseVersion, res.CandidateVersion)
	}
	if len(res.Diffs) != len(resources) {
		t.Fatalf("diff count = %d, want %d", len(res.Diffs), len(resources))
	}

	want := []ChangeKind{
		ChangeDenyToAllow, // prod debug pod 被候选例外放行
		ChangeBasis,       // sandbox 仍放行，但命中依据多了 allow-sandbox
		ChangeAllowToDeny, // ConfigMap 从未命中变为拒绝
		ChangeUnchanged,   // 普通 Pod 不受影响
	}
	for i, w := range want {
		if got := res.Diffs[i].Change; got != w {
			t.Errorf("resource %s: change = %s, want %s (summary=%q)",
				resources[i].Name, got, w, res.Diffs[i].Summary)
		}
	}
	if res.Changed != 3 || res.Unchanged != 1 {
		t.Errorf("changed/unchanged = %d/%d, want 3/1", res.Changed, res.Unchanged)
	}
	// 对比双方的判定各自带正确版本号。
	for _, d := range res.Diffs {
		if d.Base.Version != res.BaseVersion || d.Candidate.Version != res.CandidateVersion {
			t.Errorf("resource %s: decision versions = %d/%d, want %d/%d",
				d.Resource.Name, d.Base.Version, d.Candidate.Version,
				res.BaseVersion, res.CandidateVersion)
		}
	}
}

// TestPreviewDoesNotMutate 验证预演不改动当前生效策略、不推进版本，
// 且预演期间并发正式判定始终看到当前版本的一致结果。
func TestPreviewDoesNotMutate(t *testing.T) {
	store, lerrs, err := NewStoreFromManifest([]byte(manifestV1))
	if err != nil || len(lerrs) != 0 {
		t.Fatalf("init store: err=%v loadErrors=%v", err, lerrs)
	}
	before := store.Policies()
	res := Resource{Kind: "Pod", Namespace: "prod", Name: "debug",
		Labels: map[string]string{"mode": "debug"}}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	errCh := make(chan string, 1024)

	// 并发正式判定：预演期间必须始终看到 V1（version=1、放行）。
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				d := store.Evaluate(context.Background(), res)
				if d.Effect != EffectAllow || d.Version != 1 {
					errCh <- "evaluate during preview saw non-current view: " + d.Explanation
				}
			}
		}()
	}

	// 连续预演多轮（候选会把 debug pod 改为拒绝）。
	for i := 0; i < 50; i++ {
		if _, err := store.Preview(context.Background(), []byte(manifestV2),
			[]Resource{res}); err != nil {
			t.Fatalf("preview: %v", err)
		}
	}
	close(stop)
	wg.Wait()
	close(errCh)
	for msg := range errCh {
		t.Error(msg)
	}

	if got := store.Version(); got != 1 {
		t.Errorf("version after previews = %d, want 1 (preview must not bump version)", got)
	}
	after := store.Policies()
	if len(after) != len(before) || after[0].Name != before[0].Name {
		t.Errorf("policies changed by preview: before=%v after=%v", before, after)
	}
	d := store.Evaluate(context.Background(), res)
	if d.Effect != EffectAllow || d.Version != 1 {
		t.Errorf("evaluate after preview = %s/v%d, want allow/v1", d.Effect, d.Version)
	}
	t.Logf("after 50 previews: version=%d, current policies unchanged (%v)",
		store.Version(), policyNames(after))
}

func policyNames(ps []Policy) []string {
	names := make([]string, len(ps))
	for i, p := range ps {
		names[i] = p.Name
	}
	return names
}

// TestPreviewInvalidCandidate 验证候选清单部分非法时：
// 坏条目逐条报告、好条目照常参与试算，绝不按"没策略、一律放行"处理。
func TestPreviewInvalidCandidate(t *testing.T) {
	store, lerrs, err := NewStoreFromManifest([]byte(manifestV1))
	if err != nil || len(lerrs) != 0 {
		t.Fatalf("init store: err=%v loadErrors=%v", err, lerrs)
	}
	// 一条合法 deny + 一条缺 effect + 一条重名冲突。
	candidate := `{"policies": [
		{"name": "deny-debug", "effect": "deny", "match": {"kinds": ["Pod"], "labels": {"mode": "debug"}}},
		{"name": "broken", "match": {"kinds": ["Pod"]}},
		{"name": "deny-debug", "effect": "allow", "match": {"kinds": ["Pod"]}}
	]}`
	resources := []Resource{
		{Kind: "Pod", Namespace: "prod", Name: "debug", Labels: map[string]string{"mode": "debug"}},
	}

	res, err := store.Preview(context.Background(), []byte(candidate), resources)
	if err != nil {
		t.Fatalf("preview with partial-invalid candidate should still run: %v", err)
	}
	if len(res.LoadErrors) != 2 {
		t.Fatalf("load errors = %v, want 2 (missing effect + duplicate name)", res.LoadErrors)
	}
	for _, le := range res.LoadErrors {
		t.Logf("candidate load error: %v", le)
	}
	// 合法条目照常参与：debug pod 在候选下被拒。
	if got := res.Diffs[0].Change; got != ChangeAllowToDeny {
		t.Errorf("change = %s, want ALLOW_TO_DENY (valid entry must participate)", got)
	}
	if got := res.Diffs[0].Candidate.Reason; got != ReasonDenied {
		t.Errorf("candidate reason = %s, want DENIED (must not fall back to allow-all)", got)
	}
	t.Logf("partial candidate: %s", res.Diffs[0].Summary)
}

// TestPreviewUnusableCandidate 验证候选清单为空、全部非法或整体
// 无法解析时：预演明确报错，当前策略与版本保持现状。
func TestPreviewUnusableCandidate(t *testing.T) {
	store, lerrs, err := NewStoreFromManifest([]byte(manifestV1))
	if err != nil || len(lerrs) != 0 {
		t.Fatalf("init store: err=%v loadErrors=%v", err, lerrs)
	}
	resources := []Resource{{Kind: "Pod", Namespace: "prod", Name: "p1"}}

	cases := []struct {
		name      string
		candidate string
		wantCode  LoadErrorCode
	}{
		{"empty policies", `{"policies": []}`, ErrEmptyManifest},
		{"all entries invalid", `{"policies": [{"name": "x"}]}`, ErrEmptyManifest},
		{"malformed doc", `{"policies": [`, ErrMalformedDoc},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := store.Preview(context.Background(), []byte(tc.candidate), resources)
			if err == nil {
				t.Fatalf("preview should fail for %s", tc.name)
			}
			le, ok := err.(*LoadError)
			if !ok || le.Code != tc.wantCode {
				t.Fatalf("error = %v, want LoadError code %s", err, tc.wantCode)
			}
			t.Logf("candidate rejected: %v", err)
			// 全部非法时，逐条错误也要能看得到。
			if tc.name == "all entries invalid" {
				if res == nil || len(res.LoadErrors) != 1 {
					t.Fatalf("per-entry load errors missing: %+v", res)
				}
				t.Logf("broken entry: %v", res.LoadErrors[0])
			}
			if got := store.Version(); got != 1 {
				t.Errorf("version = %d after failed preview, want 1", got)
			}
			d := store.Evaluate(context.Background(), resources[0])
			if d.Effect != EffectAllow || d.Reason != ReasonAllowed {
				t.Errorf("current policy disturbed: got %s/%s, want allow/ALLOWED",
					d.Effect, d.Reason)
			}
		})
	}
}

// TestPreviewMalformedKeepsCurrent 额外确认：整体解析失败时预演结果为空、
// 当前视图与版本完全不变。
func TestPreviewMalformedKeepsCurrent(t *testing.T) {
	store, _, _ := NewStoreFromManifest([]byte(manifestV2))
	res, err := store.Preview(context.Background(), []byte("not json"),
		[]Resource{{Kind: "Pod", Namespace: "prod", Name: "p1"}})
	if err == nil || !strings.Contains(err.Error(), string(ErrMalformedDoc)) {
		t.Fatalf("err = %v, want MALFORMED_DOC", err)
	}
	if res != nil {
		t.Errorf("result = %+v, want nil on malformed candidate", res)
	}
	if got := store.Version(); got != 1 {
		t.Errorf("version = %d, want 1", got)
	}
}
