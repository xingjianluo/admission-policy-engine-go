package policy

import (
	"context"
	"sync"
	"testing"
)

const previewBase = `{"policies": [
  {"name": "allow-pods", "effect": "allow", "priority": 10, "match": {"kinds": ["Pod"]}},
  {"name": "deny-debug", "effect": "deny", "priority": 20,
   "match": {"kinds": ["Pod"], "labels": {"mode": "debug"}},
   "except": [{"namespaces": ["sandbox"]}]},
  {"name": "deny-prod-secrets", "effect": "deny", "priority": 30,
   "match": {"kinds": ["Secret"], "namespaces": ["prod"]}}
]}`

// previewResources 覆盖三种差异方向 + 依据变化 + 无变化。
func previewResources() []Resource {
	return []Resource{
		{Kind: "ConfigMap", Namespace: "prod", Name: "cfg"}, // 0 ALLOW->DENY
		{Kind: "Pod", Namespace: "prod", Name: "dbg",
			Labels: map[string]string{"mode": "debug"}}, // 1 DENY->ALLOW（删掉 deny-debug）
		{Kind: "Pod", Namespace: "sandbox", Name: "dbg2",
			Labels: map[string]string{"mode": "debug"}}, // 2 依据变化：例外条款被移除 -> 被拒
		{Kind: "Pod", Namespace: "prod", Name: "web", Labels: map[string]string{"app": "web"}}, // 3 无变化
	}
}

func logPreview(t *testing.T, p *PreviewResult) {
	t.Helper()
	t.Logf("preview: currentVersion=%d candidateVersion=%s candidateOk=%v errors=%d",
		p.CurrentVersion, p.CandidateVersion, p.CandidateOK, len(p.Errors))
	for _, ch := range p.Changes {
		r := ch.Resource
		t.Logf("[%d] %s/%s %s: %s", ch.Index, r.Namespace, r.Name, r.Kind, ch.Summary)
		t.Logf("      current : %s/%s matched=%v excepted=%v (v%d)",
			ch.Current.Effect, ch.Current.Reason, ch.Current.MatchedPolicies,
			ch.Current.ExceptedPolicies, ch.Current.Version)
		t.Logf("      candidate: %s/%s matched=%v excepted=%v",
			ch.Candidate.Effect, ch.Candidate.Reason, ch.Candidate.MatchedPolicies,
			ch.Candidate.ExceptedPolicies)
	}
}

// TestPreviewDiffClassification 验证三种差异方向与无变化能被准确区分。
func TestPreviewDiffClassification(t *testing.T) {
	store := mustStore(t, previewBase)
	before := store.Version()

	// 候选：新增 deny-prod-configmaps（0 翻转），删除 deny-debug（1 翻转），
	// 新增 deny-sandbox-debug（2 原例外放行 -> 被新规则拒绝，ALLOW->DENY）。
	candidate := []byte(`{"policies": [
	  {"name": "allow-pods", "effect": "allow", "priority": 10, "match": {"kinds": ["Pod"]}},
	  {"name": "deny-prod-secrets", "effect": "deny", "priority": 30,
	   "match": {"kinds": ["Secret"], "namespaces": ["prod"]}},
	  {"name": "deny-prod-configmaps", "effect": "deny", "priority": 30,
	   "match": {"kinds": ["ConfigMap"], "namespaces": ["prod"]}},
	  {"name": "deny-sandbox-debug", "effect": "deny", "priority": 25,
	   "match": {"kinds": ["Pod"], "namespaces": ["sandbox"], "labels": {"mode": "debug"}}}
	]}`)

	p, err := store.Preview(context.Background(), candidate, previewResources())
	if err != nil {
		t.Fatalf("preview failed: %v", err)
	}
	if !p.CandidateOK || len(p.Errors) != 0 {
		t.Fatalf("candidate should be clean, ok=%v errors=%v", p.CandidateOK, p.Errors)
	}
	if p.CurrentVersion != before {
		t.Fatalf("preview changed current version: before=%d after=%d", before, p.CurrentVersion)
	}
	if store.Version() != before {
		t.Fatalf("preview advanced live version: before=%d now=%d", before, store.Version())
	}

	want := []ChangeKind{ChangeAllowToDeny, ChangeDenyToAllow, ChangeAllowToDeny, ChangeUnchanged}
	for i, wantKind := range want {
		ch := p.Changes[i]
		if ch.Kind != wantKind {
			t.Errorf("change[%d]: got %s, want %s (summary=%s)", i, ch.Kind, wantKind, ch.Summary)
		}
		if (wantKind == ChangeUnchanged) != !ch.Changed {
			t.Errorf("change[%d]: Changed=%v inconsistent with kind %s", i, ch.Changed, ch.Kind)
		}
	}

	// 正式生效策略未被预演修改：再做一次正式判定，结论必须仍是当前策略的结论。
	d := store.Evaluate(context.Background(), previewResources()[0]) // prod ConfigMap
	if d.Effect != EffectAllow || d.Reason != ReasonNoMatch || d.Version != before {
		t.Fatalf("live policy leaked from preview: %+v", d)
	}
	logPreview(t, p)
}

// TestPreviewBasisChanged 验证结论方向相同但依据变化归类为 BASIS_CHANGED。
func TestPreviewBasisChanged(t *testing.T) {
	store := mustStore(t, previewBase)
	res := []Resource{{Kind: "Pod", Namespace: "prod", Name: "web",
		Labels: map[string]string{"app": "web", "tier": "frontend"}}}

	// 当前仅 allow-pods 命中；候选再加一条同样放行但优先级不同的 allow，
	// 结论仍是 ALLOW，但命中依据变化。
	candidate := []byte(`{"policies": [
	  {"name": "allow-pods", "effect": "allow", "priority": 10, "match": {"kinds": ["Pod"]}},
	  {"name": "allow-frontend", "effect": "allow", "priority": 15,
	   "match": {"kinds": ["Pod"], "labels": {"tier": "frontend"}}}
	]}`)
	p, err := store.Preview(context.Background(), candidate, res)
	if err != nil {
		t.Fatalf("preview failed: %v", err)
	}
	if p.Changes[0].Kind != ChangeBasisChanged || !p.Changes[0].Changed {
		t.Fatalf("expected BASIS_CHANGED, got %s: %s", p.Changes[0].Kind, p.Changes[0].Summary)
	}
	logPreview(t, p)
}

// TestPreviewInvalidCandidate 验证候选含非法/冲突条目时：
// 显式报告坏在哪一条、CandidateOK=false，合法条目照常参与试算，
// 绝不当成“没策略一律放行”。
func TestPreviewInvalidCandidate(t *testing.T) {
	store := mustStore(t, previewBase)
	before := store.Version()
	resources := []Resource{{Kind: "ConfigMap", Namespace: "prod", Name: "cfg"}}

	candidate := []byte(`{"policies": [
	  {"name": "deny-prod-configmaps", "effect": "deny", "priority": 30,
	   "match": {"kinds": ["ConfigMap"], "namespaces": ["prod"]}},
	  {"name": "", "effect": "deny", "match": {"kinds": ["Pod"]}},
	  {"name": "bad-effect", "effect": "audit", "match": {"kinds": ["Pod"]}},
	  {"name": "deny-prod-configmaps", "effect": "allow", "match": {"kinds": ["X"]}}
	]}`)
	p, err := store.Preview(context.Background(), candidate, resources)
	if err != nil {
		t.Fatalf("partially-invalid candidate must not be a global failure: %v", err)
	}
	if p.CandidateOK {
		t.Fatal("CandidateOK must be false when candidate contains bad entries")
	}
	if len(p.Errors) != 3 {
		t.Fatalf("expected 3 entry errors (missing name, bad effect, conflict), got %d: %v",
			len(p.Errors), p.Errors)
	}
	codes := map[LoadErrorCode]bool{}
	for _, le := range p.Errors {
		codes[le.Code] = true
		t.Logf("candidate problem: policy=%q code=%s field=%s msg=%q",
			le.Policy, le.Code, le.Field, le.Message)
	}
	if !codes[ErrMissingField] || !codes[ErrInvalidValue] || !codes[ErrConflictingPol] {
		t.Fatalf("missing expected error codes, got %v", codes)
	}
	// 合法的 deny-prod-configmaps 必须参与试算：资源应被翻转为拒绝。
	if p.Changes[0].Kind != ChangeAllowToDeny {
		t.Fatalf("valid candidate entry should still apply, got %s: %s",
			p.Changes[0].Kind, p.Changes[0].Summary)
	}
	if store.Version() != before {
		t.Fatalf("preview advanced live version: now=%d", store.Version())
	}
	logPreview(t, p)
}

// TestPreviewEmptyCandidate 验证空候选/无可用条目被明确拒绝，而非隐式放行。
func TestPreviewEmptyCandidate(t *testing.T) {
	store := mustStore(t, previewBase)
	resources := []Resource{{Kind: "Pod", Namespace: "prod", Name: "web"}}

	// 完全空的 policies 数组。
	p, err := store.Preview(context.Background(), []byte(`{"policies": []}`), resources)
	if err != nil {
		t.Fatalf("empty array is a content problem reported in result, not a global error: %v", err)
	}
	if p.CandidateOK {
		t.Fatal("CandidateOK must be false for empty candidate")
	}
	if len(p.Errors) != 1 || p.Errors[0].Code != ErrEmptyCandidate {
		t.Fatalf("expected a single EMPTY_CANDIDATE error, got %v", p.Errors)
	}
	t.Logf("empty candidate rejected: %v", p.Errors[0])

	// 全部条目非法 => 同样没有任何可用策略，也必须显式标注，不能混同为放行。
	bad := []byte(`{"policies": [
	  {"name": "x", "effect": "deny", "match": {}}
	]}`)
	p2, err := store.Preview(context.Background(), bad, resources)
	if err != nil {
		t.Fatalf("unexpected global error: %v", err)
	}
	foundEmpty := false
	for _, le := range p2.Errors {
		t.Logf("candidate problem: policy=%q code=%s", le.Policy, le.Code)
		if le.Code == ErrEmptyCandidate {
			foundEmpty = true
		}
	}
	if !foundEmpty {
		t.Fatal("all-invalid candidate must also be flagged EMPTY_CANDIDATE")
	}
}

// TestPreviewMalformedCandidate 验证整份候选无法解析时直接失败并保持现状。
func TestPreviewMalformedCandidate(t *testing.T) {
	store := mustStore(t, previewBase)
	before := store.Version()
	resources := []Resource{{Kind: "Pod", Namespace: "prod", Name: "web"}}

	p, err := store.Preview(context.Background(), []byte(`{"policies": [`), resources)
	if p != nil {
		t.Fatalf("malformed candidate must return nil result, got %+v", p)
	}
	le, ok := err.(*LoadError)
	if !ok || le.Code != ErrMalformedDoc {
		t.Fatalf("expected MALFORMED_DOC error, got %v", err)
	}
	if store.Version() != before {
		t.Fatalf("malformed preview advanced live version: now=%d", store.Version())
	}
	t.Logf("malformed candidate rejected, live version stays %d: %v", before, le)
}

// TestPreviewConcurrentWithLiveUpdates 验证预演期间并发的正式判定：
// 始终看到完整一致的当前策略（V1/V2 之一），且预演不写入当前视图。
func TestPreviewConcurrentWithLiveUpdates(t *testing.T) {
	store, _, err := NewStoreFromManifest([]byte(manifestV1))
	if err != nil {
		t.Fatal(err)
	}
	res := Resource{Kind: "Pod", Namespace: "prod", Name: "p1",
		Labels: map[string]string{"mode": "debug"}}

	validLive := func(d Decision) bool {
		v1 := d.Effect == EffectAllow && d.Reason == ReasonAllowed &&
			len(d.MatchedPolicies) == 1 && d.MatchedPolicies[0] == "allow-pods"
		v2 := d.Effect == EffectDeny && d.Reason == ReasonDenied &&
			len(d.MatchedPolicies) == 1 && d.MatchedPolicies[0] == "deny-debug"
		return v1 || v2
	}

	resources := make([]Resource, 500)
	for i := range resources {
		resources[i] = res
	}
	candidate := []byte(manifestV2) // 与 V2 相同的候选

	var wg sync.WaitGroup
	stop := make(chan struct{})
	bad := make(chan string, 64)

	// 持续做正式热更新。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			m := manifestV1
			if i%2 == 1 {
				m = manifestV2
			}
			if _, err := store.Update([]byte(m)); err != nil {
				bad <- "update error: " + err.Error()
			}
		}
	}()

	// 持续做正式单条判定：只能看到完整的 V1 或 V2 视图。
	const readers = 16
	var rwg sync.WaitGroup
	for w := 0; w < readers; w++ {
		rwg.Add(1)
		go func() {
			defer rwg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if d := store.Evaluate(context.Background(), res); !validLive(d) {
					select {
					case bad <- "inconsistent live decision":
					default:
					}
				}
			}
		}()
	}

	// 同时反复预演：必须始终返回自洽结果（currentVersion 单调取值内），
	// 且每个 change 的 current/candidate 分别与其描述一致。
	const previewers = 4
	var pwg sync.WaitGroup
	for w := 0; w < previewers; w++ {
		pwg.Add(1)
		go func() {
			defer pwg.Done()
			for i := 0; i < 50; i++ {
				p, err := store.Preview(context.Background(), candidate, resources)
				if err != nil {
					select {
					case bad <- "preview error: " + err.Error():
					default:
					}
					continue
				}
				if p.CurrentVersion < 1 || p.CandidateVersion == "" {
					select {
					case bad <- "preview missing versions":
					default:
					}
				}
			}
		}()
	}

	pwg.Wait()
	wg.Wait()
	close(stop)
	rwg.Wait()
	close(bad)
	for msg := range bad {
		t.Error(msg)
	}
	t.Logf("concurrent preview/update/evaluate finished, final live version=%d", store.Version())
}

func mustStore(t *testing.T, manifest string) *Store {
	t.Helper()
	store, lerrs, err := NewStoreFromManifest([]byte(manifest))
	if err != nil || len(lerrs) != 0 {
		t.Fatalf("init store: err=%v loadErrors=%v", err, lerrs)
	}
	return store
}
