// Package policy 实现本地准入策略的加载、归一、评估与热更新。
package policy

// Effect 表示策略效果：放行或拒绝。
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Resource 是待判定的资源清单。
type Resource struct {
	Kind      string            `json:"kind"`
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// Selector 描述一组资源匹配条件；所有非空字段需同时满足（AND）。
type Selector struct {
	Kinds      []string          `json:"kinds,omitempty"`
	Namespaces []string          `json:"namespaces,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// Policy 是归一后的统一策略模型。
type Policy struct {
	Name     string     `json:"name"`
	Effect   Effect     `json:"effect"`
	Priority int        `json:"priority,omitempty"`
	Match    Selector   `json:"match"`
	Except   []Selector `json:"except,omitempty"`
}

// ReasonCode 是可区分且稳定的判定/拒绝原因码。
type ReasonCode string

const (
	ReasonNoMatch       ReasonCode = "NO_MATCH"       // 无任何规则命中
	ReasonAllowed       ReasonCode = "ALLOWED"        // 命中放行规则且无拒绝
	ReasonDenied        ReasonCode = "DENIED"         // 命中拒绝规则（拒绝覆盖放行）
	ReasonExcepted      ReasonCode = "EXCEPTED"       // 规则命中但被例外跳过
	ReasonCanceled      ReasonCode = "CANCELED"       // 请求被取消，评估中止
	ReasonInvalidPolicy ReasonCode = "INVALID_POLICY" // 策略非法（加载期）
)

// Decision 是一次评估的结论，包含可解释的判定依据。
type Decision struct {
	Effect           Effect     `json:"effect"`
	Reason           ReasonCode `json:"reason"`
	MatchedPolicies  []string   `json:"matchedPolicies,omitempty"`
	ExceptedPolicies []string   `json:"exceptedPolicies,omitempty"`
	Explanation      string     `json:"explanation"`
	// Version 是本次判定所用策略视图的版本号，用于版本溯源。
	Version uint64 `json:"version"`
}
