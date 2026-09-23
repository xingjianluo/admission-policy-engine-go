package policy

import (
	"context"
	"fmt"
)

// Outcome 是评估的最终结论类别。
type Outcome string

const (
	OutcomeDenied  Outcome = "denied"
	OutcomeAllowed Outcome = "allowed"
	OutcomeNoMatch Outcome = "no_match"
)

// RuleTrace 记录单条规则对资源的判定轨迹。
type RuleTrace struct {
	Policy   string
	Rule     string
	Effect   Effect
	Priority int
	Matched  bool
	Excepted bool
	Applied  bool
}

// Decision 是一次评估的完整结论与依据。
type Decision struct {
	Allowed bool
	Outcome Outcome
	Reason  string
	Traces  []RuleTrace
	Version uint64
}

// matches 判断资源是否满足选择器：所有非空条件取 AND，同一字段的多个取值取 OR。
// 空选择器（无条件）不匹配任何资源，避免“except 空集 = 排除全部”这类歧义配置生效。
func matches(sel Selector, res Resource) bool {
	hasCond := false
	if len(sel.Kinds) > 0 {
		hasCond = true
		if !contains(sel.Kinds, res.Kind) {
			return false
		}
	}
	if len(sel.Namespaces) > 0 {
		hasCond = true
		if !contains(sel.Namespaces, res.Namespace) {
			return false
		}
	}
	if len(sel.Names) > 0 {
		hasCond = true
		if !contains(sel.Names, res.Name) {
			return false
		}
	}
	if len(sel.Labels) > 0 {
		hasCond = true
		for k, v := range sel.Labels {
			if res.Labels[k] != v {
				return false
			}
		}
	}
	return hasCond
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

// evaluate 在给定快照上评估资源。
// 语义：拒绝覆盖放行，且与规则书写顺序无关（按优先级取决定依据）；
// 命中 Match 但被 Except 排除的规则记为 Excepted 且不参与判定；
// 无任何生效规则时为 no_match（默认放行）。
func evaluate(ctx context.Context, snap *Snapshot, res Resource) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	d := Decision{Version: snap.version}

	var (
		allowBest *RuleTrace
		denyBest  *RuleTrace
		anyMatch  bool
	)
	trace := func() *RuleTrace {
		d.Traces = append(d.Traces, RuleTrace{})
		return &d.Traces[len(d.Traces)-1]
	}

	for _, p := range snap.policies {
		if err := ctx.Err(); err != nil {
			return Decision{}, err
		}
		for i := range p.Rules {
			r := &p.Rules[i]
			t := trace()
			t.Policy, t.Rule, t.Effect, t.Priority = p.Name, r.Name, r.Effect, r.Priority
			if !matches(r.Match, res) {
				continue
			}
			t.Matched = true
			anyMatch = true
			for _, ex := range r.Except {
				if matches(ex, res) {
					t.Excepted = true
					break
				}
			}
			if t.Excepted {
				continue
			}
			t.Applied = true
			switch r.Effect {
			case EffectDeny:
				if denyBest == nil || r.Priority > denyBest.Priority {
					denyBest = t
				}
			case EffectAllow:
				if allowBest == nil || r.Priority > allowBest.Priority {
					allowBest = t
				}
			}
		}
	}

	switch {
	case denyBest != nil:
		d.Outcome, d.Allowed = OutcomeDenied, false
		d.Reason = fmt.Sprintf("denied by policy %q rule %q (priority %d)",
			denyBest.Policy, denyBest.Rule, denyBest.Priority)
	case allowBest != nil:
		d.Outcome, d.Allowed = OutcomeAllowed, true
		d.Reason = fmt.Sprintf("allowed by policy %q rule %q (priority %d)",
			allowBest.Policy, allowBest.Rule, allowBest.Priority)
	case anyMatch:
		d.Outcome, d.Allowed = OutcomeAllowed, true
		d.Reason = "all matching rules were skipped by exceptions"
	default:
		d.Outcome, d.Allowed = OutcomeNoMatch, true
		d.Reason = "no policy matched the resource; default allow"
	}
	return d, nil
}
