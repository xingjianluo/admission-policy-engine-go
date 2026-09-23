// Package policy 提供本地准入策略的模型、加载、评估与热更新能力。
package policy

// Effect 表示规则命中后的效果。
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Resource 是待评估的准入资源。
type Resource struct {
	Kind      string            `json:"kind"`
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// Selector 描述一组资源的匹配条件；所有非空条件取与（AND）。
type Selector struct {
	Kinds      []string          `json:"kinds,omitempty"`
	Namespaces []string          `json:"namespaces,omitempty"`
	Names      []string          `json:"names,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// Rule 是一条策略规则：命中 Match 且未被 Except 排除时按 Effect 生效。
type Rule struct {
	Name     string     `json:"name"`
	Effect   Effect     `json:"effect"`
	Priority int        `json:"priority"`
	Match    Selector   `json:"match"`
	Except   []Selector `json:"except,omitempty"`
}

// Policy 是一组规则的集合。
type Policy struct {
	Name  string `json:"name"`
	Rules []Rule `json:"rules"`
}

// Manifest 是本地策略清单的顶层结构。
type Manifest struct {
	Policies []Policy `json:"policies"`
}
