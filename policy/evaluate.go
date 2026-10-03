package policy

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// snapshot 是不可变的已编译策略视图，热更新时整体替换。
type snapshot struct {
	version  int64    // 只增不减的版本标识；初始视图为 1，每次成功更新 +1
	policies []Policy // 已按优先级降序、名称升序排序，保证结论与书写顺序无关
}

// compile 将策略列表编译为不可变视图：复制并稳定排序。
func compile(policies []Policy, version int64) *snapshot {
	cp := make([]Policy, len(policies))
	copy(cp, policies)
	// 优先级高者先评估；同级按名称排序，保证结论确定、与清单书写顺序无关。
	sort.SliceStable(cp, func(i, j int) bool {
		if cp[i].Priority != cp[j].Priority {
			return cp[i].Priority > cp[j].Priority
		}
		return cp[i].Name < cp[j].Name
	})
	return &snapshot{version: version, policies: cp}
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

// evaluate 在单个一致视图上评估资源。
// 语义：
//   - 例外只对命中该规则的资源生效，被例外的规则视为未命中；
//   - 拒绝覆盖放行，与规则书写顺序无关；
//   - ctx 被取消时立即中止评估。
func (s *snapshot) evaluate(ctx context.Context, res Resource) Decision {
	var denied, allowed, excepted []string

	for i := range s.policies {
		// 被取消的请求应立即停止评估。
		if err := ctx.Err(); err != nil {
			return Decision{
				Effect:      EffectDeny,
				Reason:      ReasonCanceled,
				Explanation: fmt.Sprintf("evaluation canceled: %v", err),
				Version:     s.version,
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
		d := Decision{
			Effect:           EffectDeny,
			Reason:           ReasonDenied,
			MatchedPolicies:  denied,
			ExceptedPolicies: excepted,
			Explanation:      explain("denied by", denied, allowed, excepted),
		}
		d.Version = s.version
		return d
	case len(allowed) > 0:
		d := Decision{
			Effect:           EffectAllow,
			Reason:           ReasonAllowed,
			MatchedPolicies:  allowed,
			ExceptedPolicies: excepted,
			Explanation:      explain("allowed by", allowed, nil, excepted),
		}
		d.Version = s.version
		return d
	case len(excepted) > 0:
		// 规则命中但全部被例外跳过：与"未命中"可区分。
		d := Decision{
			Effect:           EffectAllow,
			Reason:           ReasonExcepted,
			ExceptedPolicies: excepted,
			Explanation:      fmt.Sprintf("all matched policies skipped by exception: %s", strings.Join(excepted, ", ")),
		}
		d.Version = s.version
		return d
	default:
		return Decision{
			Effect:      EffectAllow,
			Reason:      ReasonNoMatch,
			Explanation: "no policy matched the resource",
			Version:     s.version,
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
