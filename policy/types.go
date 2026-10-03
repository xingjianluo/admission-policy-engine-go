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
	Version          int64      `json:"version"` // 本次评估使用的策略快照版本，只增不减
}

// ResourceDecision 是批量判定中单条资源的定位信息与判定结论。
type ResourceDecision struct {
	Index    int      `json:"index"` // 资源在输入批次中的下标，结论顺序与输入一致
	Resource Resource `json:"resource"`
	Decision Decision `json:"decision"`
}

// ChangeKind 描述候选策略相对当前生效策略，给单条资源结论带来的变化类型。
type ChangeKind string

const (
	ChangeUnchanged    ChangeKind = "UNCHANGED"     // 结论与依据均无变化
	ChangeAllowToDeny  ChangeKind = "ALLOW_TO_DENY" // 原放行，候选下被拒
	ChangeDenyToAllow  ChangeKind = "DENY_TO_ALLOW" // 原拒绝，候选下放行
	ChangeBasisChanged ChangeKind = "BASIS_CHANGED" // 放行/拒绝结论未变，但命中或例外依据变化
)

// ResourceChange 是预演中单条资源在当前策略与候选策略下的结论对比。
type ResourceChange struct {
	Index     int        `json:"index"`
	Resource  Resource   `json:"resource"`
	Current   Decision   `json:"current"`   // 当前生效策略下的结论
	Candidate Decision   `json:"candidate"` // 候选策略下的试算结论
	Changed   bool       `json:"changed"`
	Kind      ChangeKind `json:"kind"`
	Summary   string     `json:"summary"` // 一眼可读的差异摘要
}

// PreviewResult 是一次变更预演的结果：不改动任何当前生效策略。
type PreviewResult struct {
	CurrentVersion   int64            `json:"currentVersion"`   // 预演所基于的当前生效版本
	CandidateVersion string           `json:"candidateVersion"` // 候选内容指纹（不占用正式版本号）
	CandidateOK      bool             `json:"candidateOk"`      // 候选清单是否完整无非法条目
	Errors           []*LoadError     `json:"errors,omitempty"` // 候选清单中逐条定位的问题
	Changes          []ResourceChange `json:"changes"`          // 与输入同序的逐资源对比
}
