package policy

import (
	"context"
	"testing"
)

// logDecision 按要求在单测日志中打印输入资源、命中策略与最终判定依据。
func logDecision(t *testing.T, res Resource, d Decision) {
	t.Helper()
	t.Logf("input resource: kind=%s namespace=%s name=%s labels=%v", res.Kind, res.Namespace, res.Name, res.Labels)
	t.Logf("matched policies: %v, excepted policies: %v", d.MatchedPolicies, d.ExceptedPolicies)
	t.Logf("final decision: effect=%s reason=%s explanation=%q", d.Effect, d.Reason, d.Explanation)
}

// TestDenyOverridesAllow 验证拒绝覆盖放行，且与规则书写顺序无关。
func TestDenyOverridesAllow(t *testing.T) {
	allow := Policy{
		Name:   "allow-prod-pods",
		Effect: EffectAllow,
		Match:  Selector{Kinds: []string{"Pod"}, Namespaces: []string{"prod"}},
	}
	deny := Policy{
		Name:   "deny-privileged",
		Effect: EffectDeny,
		Match:  Selector{Kinds: []string{"Pod"}, Labels: map[string]string{"security": "privileged"}},
	}
	res := Resource{Kind: "Pod", Namespace: "prod", Name: "p1",
		Labels: map[string]string{"security": "privileged"}}

	// 两种书写顺序：allow 在前与 deny 在前，结论必须一致。
	for _, order := range [][]Policy{{allow, deny}, {deny, allow}} {
		d := NewStore(order).Evaluate(context.Background(), res)
		logDecision(t, res, d)
		if d.Effect != EffectDeny || d.Reason != ReasonDenied {
			t.Fatalf("expected DENY/DENIED, got %s/%s", d.Effect, d.Reason)
		}
		if len(d.MatchedPolicies) != 1 || d.MatchedPolicies[0] != "deny-privileged" {
			t.Fatalf("expected only deny policy in matched list, got %v", d.MatchedPolicies)
		}
	}
}

// TestExceptionHit 验证带例外的规则只对命中例外的资源跳过，
// 且"被例外跳过"与"未命中"可按原因区分。
func TestExceptionHit(t *testing.T) {
	deny := Policy{
		Name:   "deny-debug-pods",
		Effect: EffectDeny,
		Match:  Selector{Kinds: []string{"Pod"}, Labels: map[string]string{"mode": "debug"}},
		Except: []Selector{{Namespaces: []string{"sandbox"}}},
	}
	store := NewStore([]Policy{deny})

	// 命中例外：规则被跳过，原因为 EXCEPTED。
	exemptRes := Resource{Kind: "Pod", Namespace: "sandbox", Name: "p2",
		Labels: map[string]string{"mode": "debug"}}
	d := store.Evaluate(context.Background(), exemptRes)
	logDecision(t, exemptRes, d)
	if d.Effect != EffectAllow || d.Reason != ReasonExcepted {
		t.Fatalf("expected ALLOW/EXCEPTED, got %s/%s", d.Effect, d.Reason)
	}
	if len(d.ExceptedPolicies) != 1 || d.ExceptedPolicies[0] != "deny-debug-pods" {
		t.Fatalf("expected excepted policy recorded, got %v", d.ExceptedPolicies)
	}

	// 未命中例外：规则生效，拒绝。
	deniedRes := Resource{Kind: "Pod", Namespace: "prod", Name: "p3",
		Labels: map[string]string{"mode": "debug"}}
	d = store.Evaluate(context.Background(), deniedRes)
	logDecision(t, deniedRes, d)
	if d.Effect != EffectDeny || d.Reason != ReasonDenied {
		t.Fatalf("expected DENY/DENIED, got %s/%s", d.Effect, d.Reason)
	}

	// 完全未命中：原因为 NO_MATCH，与 EXCEPTED 可区分。
	plainRes := Resource{Kind: "Pod", Namespace: "prod", Name: "p4"}
	d = store.Evaluate(context.Background(), plainRes)
	logDecision(t, plainRes, d)
	if d.Effect != EffectAllow || d.Reason != ReasonNoMatch {
		t.Fatalf("expected ALLOW/NO_MATCH, got %s/%s", d.Effect, d.Reason)
	}
}

// TestCanceledEvaluation 验证被取消的请求立即停止评估。
func TestCanceledEvaluation(t *testing.T) {
	store := NewStore([]Policy{{
		Name: "deny-all", Effect: EffectDeny, Match: Selector{Kinds: []string{"Pod"}},
	}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := store.Evaluate(ctx, Resource{Kind: "Pod", Name: "p5"})
	logDecision(t, Resource{Kind: "Pod", Name: "p5"}, d)
	if d.Reason != ReasonCanceled {
		t.Fatalf("expected reason CANCELED, got %s", d.Reason)
	}
}
