package policy

import (
	"context"
	"testing"
)

// TestInvalidPolicies 验证字段缺失、类型错误、取值非法与冲突的策略
// 各自得到可区分且稳定的拒绝原因，且不影响其余策略的可用性。
func TestInvalidPolicies(t *testing.T) {
	manifest := `{
	  "policies": [
	    {"name": "good-allow", "effect": "allow", "match": {"kinds": ["Pod"]}},
	    {"effect": "deny", "match": {"kinds": ["Pod"]}},
	    {"name": "bad-type", "effect": "deny", "match": {"kinds": "Pod"}},
	    {"name": "bad-effect", "effect": "audit", "match": {"kinds": ["Pod"]}},
	    {"name": "empty-match", "effect": "deny", "match": {}},
	    {"name": "good-allow", "effect": "deny", "match": {"kinds": ["Secret"]}},
	    {"name": "good-deny", "effect": "deny", "match": {"kinds": ["Pod"], "labels": {"mode": "debug"}}}
	  ]
	}`

	res, err := LoadManifest([]byte(manifest))
	if err != nil {
		t.Fatalf("manifest with some bad policies must still load, got global error: %v", err)
	}

	// 合法策略不受非法策略影响。
	if len(res.Policies) != 2 {
		t.Fatalf("expected 2 valid policies, got %d: %+v", len(res.Policies), res.Policies)
	}
	if len(res.Errors) != 5 {
		t.Fatalf("expected 5 load errors, got %d: %v", len(res.Errors), res.Errors)
	}

	// 逐条核对稳定原因码。
	wantCodes := []LoadErrorCode{
		ErrMissingField,   // 缺 name
		ErrInvalidType,    // kinds 类型错误
		ErrInvalidValue,   // effect 取值非法
		ErrMissingField,   // match 为空
		ErrConflictingPol, // 重名冲突
	}
	for i, want := range wantCodes {
		if res.Errors[i].Code != want {
			t.Errorf("error[%d]: expected code %s, got %s (%v)", i, want, res.Errors[i].Code, res.Errors[i])
		}
		t.Logf("rejected policy %q: code=%s field=%s message=%q",
			res.Errors[i].Policy, res.Errors[i].Code, res.Errors[i].Field, res.Errors[i].Message)
	}

	// 合法策略可正常评估。
	store := NewStore(res.Policies)
	r := Resource{Kind: "Pod", Namespace: "prod", Name: "p1", Labels: map[string]string{"mode": "debug"}}
	d := store.Evaluate(context.Background(), r)
	logDecision(t, r, d)
	if d.Effect != EffectDeny || d.Reason != ReasonDenied {
		t.Fatalf("expected DENY/DENIED from surviving good-deny, got %s/%s", d.Effect, d.Reason)
	}
}

// TestMalformedManifest 验证清单整体无法解析时返回全局错误。
func TestMalformedManifest(t *testing.T) {
	_, err := LoadManifest([]byte(`{"policies": [`))
	if err == nil {
		t.Fatal("expected global error for malformed manifest")
	}
	le, ok := err.(*LoadError)
	if !ok || le.Code != ErrMalformedDoc {
		t.Fatalf("expected LoadError/MALFORMED_DOC, got %v", err)
	}
	t.Logf("malformed manifest rejected: code=%s message=%q", le.Code, le.Message)
}
