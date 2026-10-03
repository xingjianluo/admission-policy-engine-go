package policy

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// snapshot 是不可变的已编译策略视图，热更新时整体替换。
type snapshot struct {
	policies []Policy // 已按优先级降序、名称升序排序，保证结论与书写顺序无关
	version  uint64   // 该视图对应的版本号，判定结果原样带出
}

// compile 将策略列表编译为不可变视图：复制并稳定排序，并绑定版本号。
func compile(policies []Policy, version uint64) *snapshot {
	cp := make([]Policy, len(policies))
	copy(cp, policies)
	// 优先级高者先评估；同级按名称排序，保证结论确定、与清单书写顺序无关。
	sort.SliceStable(cp, func(i, j int) bool {
		if cp[i].Priority != cp[j].Priority {
			return cp[i].Priority > cp[j].Priority
		}
		return cp[i].Name < cp[j].Name
	})
	return &snapshot{policies: cp, version: version}
}

// matches 判断选择器是否命中资源：所有非空字段需同时满足。
func matches(sel *Selector, res Resource) bool {
	if len(sel.Kinds) > 0 && !contains(sel.Kinds, res.Kind) {
		return false
	}
	if len(sel.Namespaces) > 0 && !contains(sel.Namespaces, res.Namespace) {
		return false
	}
	for k, v := range sel.Labels {
		if res.Labels[k] != v {
			return false
		}
	}
	return true
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

// evaluate 在单个一致视图上评估资源，并为结论打上该视图的版本号。
// 语义：
//   - 例外只对命中该规则的资源生效，被例外的规则视为未命中；
//   - 拒绝覆盖放行，与规则书写顺序无关；
//   - ctx 被取消时立即中止评估。
func (s *snapshot) evaluate(ctx context.Context, res Resource) Decision {
	d := s.eval(ctx, res)
	d.Version = s.version
	return d
}

// eval 是 evaluate 的核心逻辑，不处理版本号。
func (s *snapshot) eval(ctx context.Context, res Resource) Decision {
	var denied, allowed, excepted []string

	for i := range s.policies {
		// 被取消的请求应立即停止评估。
		if err := ctx.Err(); err != nil {
			return Decision{
				Effect:      EffectDeny,
				Reason:      ReasonCanceled,
				Explanation: fmt.Sprintf("evaluation canceled: %v", err),
			}
		}
		p := &s.policies[i]
		if !matches(&p.Match, res) {
			continue
		}
		if isExcepted(p, res) {
			excepted = append(excepted, p.Name)
			continue
		}
		switch p.Effect {
		case EffectDeny:
			denied = append(denied, p.Name)
		case EffectAllow:
			allowed = append(allowed, p.Name)
		}
	}

	switch {
	case len(denied) > 0:
		// 拒绝覆盖放行：无论放行规则是否命中、书写顺序如何。
		return Decision{
			Effect:           EffectDeny,
			Reason:           ReasonDenied,
			MatchedPolicies:  denied,
			ExceptedPolicies: excepted,
			Explanation:      explain("denied by", denied, allowed, excepted),
		}
	case len(allowed) > 0:
		return Decision{
			Effect:           EffectAllow,
			Reason:           ReasonAllowed,
			MatchedPolicies:  allowed,
			ExceptedPolicies: excepted,
			Explanation:      explain("allowed by", allowed, nil, excepted),
		}
	case len(excepted) > 0:
		// 规则命中但全部被例外跳过：与"未命中"可区分。
		return Decision{
			Effect:           EffectAllow,
			Reason:           ReasonExcepted,
			ExceptedPolicies: excepted,
			Explanation:      fmt.Sprintf("all matched policies skipped by exception: %s", strings.Join(excepted, ", ")),
		}
	default:
		return Decision{
			Effect:      EffectAllow,
			Reason:      ReasonNoMatch,
			Explanation: "no policy matched the resource",
		}
	}
}

// isExcepted 判断资源是否命中规则的任一例外子句。
func isExcepted(p *Policy, res Resource) bool {
	for i := range p.Except {
		if matches(&p.Except[i], res) {
			return true
		}
	}
	return false
}

// explain 生成人类可读的判定依据。
func explain(verb string, matched, overridden, excepted []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s policies [%s]", verb, strings.Join(matched, ", "))
	if len(overridden) > 0 {
		fmt.Fprintf(&b, "; allow policies [%s] overridden by deny", strings.Join(overridden, ", "))
	}
	if len(excepted) > 0 {
		fmt.Fprintf(&b, "; excepted policies [%s] skipped", strings.Join(excepted, ", "))
	}
	return b.String()
}
