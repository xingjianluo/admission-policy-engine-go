package policy

import (
	"context"
	"fmt"
	"slices"
	"strings"
)

// ChangeKind 描述预演中单个资源结论相对当前策略的变化类型。
type ChangeKind string

const (
	ChangeUnchanged   ChangeKind = "UNCHANGED"     // 结论与依据完全一致
	ChangeAllowToDeny ChangeKind = "ALLOW_TO_DENY" // 原来放行，候选下被拒
	ChangeDenyToAllow ChangeKind = "DENY_TO_ALLOW" // 原来拒绝，候选下放行
	ChangeBasis       ChangeKind = "BASIS_CHANGED" // 放行/拒绝不变，但命中或例外依据变了
)

// ResourceDiff 是单个资源在"当前策略 vs 候选策略"下的对比结果。
type ResourceDiff struct {
	Resource  Resource   `json:"resource"`
	Change    ChangeKind `json:"change"`
	Base      Decision   `json:"base"`
	Candidate Decision   `json:"candidate"`
	Summary   string     `json:"summary"`
}

// PreviewResult 是一次变更预演的完整结果。
// BaseVersion 是预演对比的当前生效版本，CandidateVersion 是候选清单
// 若真正生效将获得的版本号（当前版本 +1，仅作标识，预演不推进版本）。
type PreviewResult struct {
	BaseVersion      uint64         `json:"baseVersion"`
	CandidateVersion uint64         `json:"candidateVersion"`
	LoadErrors       []*LoadError   `json:"loadErrors,omitempty"`
	Diffs            []ResourceDiff `json:"diffs"`
	Changed          int            `json:"changed"`
	Unchanged        int            `json:"unchanged"`
}

// Preview 变更预演：在不动当前生效策略的前提下，用候选策略清单
// 对同一批资源试算，并与当前策略的结论逐一对比。
//
// 保证：
//   - 预演全程只读当前视图，绝不修改生效策略，也不推进版本号；
//   - 预演期间正在进行的正式判定继续使用当前生效视图，结果完整一致；
//   - 候选清单中单条非法策略被剔除并逐条记入 LoadErrors，
//     其余合法条目正常参与试算；
//   - 候选清单没有任何可用策略（为空或全部非法）时返回
//     EMPTY_MANIFEST 错误，绝不按"没策略、一律放行"试算；
//   - 候选清单整体无法解析时返回 MALFORMED_DOC 错误，预演失败并保持现状。
//
// 返回的 PreviewResult 即使伴随错误也可能非 nil（用于带回逐条加载错误）。
func (s *Store) Preview(ctx context.Context, candidate []byte, resources []Resource) (*PreviewResult, error) {
	res, err := LoadManifest(candidate)
	if err != nil {
		// 整体无法解析：预演直接失败，当前策略与版本保持现状。
		return nil, err
	}

	base := s.cur.Load()
	out := &PreviewResult{
		BaseVersion:      base.version,
		CandidateVersion: base.version + 1,
		LoadErrors:       res.Errors,
	}

	if len(res.Policies) == 0 {
		// 候选没有任何可用策略：明确报错，绝不按"一律放行"混过去。
		return out, &LoadError{
			Policy:  "<manifest>",
			Code:    ErrEmptyManifest,
			Message: "candidate manifest has no usable policy (empty or all entries invalid)",
		}
	}

	cand := compile(res.Policies, out.CandidateVersion)
	baseResults := evalBatch(ctx, base, resources)
	candResults := evalBatch(ctx, cand, resources)

	for i := range baseResults {
		diff := diffDecisions(baseResults[i], candResults[i])
		out.Diffs = append(out.Diffs, diff)
		if diff.Change == ChangeUnchanged {
			out.Unchanged++
		} else {
			out.Changed++
		}
	}
	return out, nil
}

// diffDecisions 对比同一资源在两套策略下的结论，给出变化类型与摘要。
func diffDecisions(base, cand BatchResult) ResourceDiff {
	b, c := base.Decision, cand.Decision
	d := ResourceDiff{Resource: base.Resource, Base: b, Candidate: c}

	sameBasis := b.Reason == c.Reason &&
		slices.Equal(b.MatchedPolicies, c.MatchedPolicies) &&
		slices.Equal(b.ExceptedPolicies, c.ExceptedPolicies)

	switch {
	case b.Effect == c.Effect && sameBasis:
		d.Change = ChangeUnchanged
		d.Summary = fmt.Sprintf("unchanged: %s (%s)", c.Effect, c.Reason)
	case b.Effect == EffectAllow && c.Effect == EffectDeny:
		d.Change = ChangeAllowToDeny
		d.Summary = fmt.Sprintf("allow -> deny: was %s, now denied by %v",
			basisOf(b), c.MatchedPolicies)
	case b.Effect == EffectDeny && c.Effect == EffectAllow:
		d.Change = ChangeDenyToAllow
		d.Summary = fmt.Sprintf("deny -> allow: was denied by %v, now %s",
			b.MatchedPolicies, basisOf(c))
	default:
		d.Change = ChangeBasis
		d.Summary = fmt.Sprintf("basis changed under %s: was %s, now %s",
			c.Effect, basisOf(b), basisOf(c))
	}
	return d
}

// basisOf 生成一条结论的简短依据描述（原因码 + 命中/例外）。
func basisOf(d Decision) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s", d.Reason)
	if len(d.MatchedPolicies) > 0 {
		fmt.Fprintf(&sb, " matched=%v", d.MatchedPolicies)
	}
	if len(d.ExceptedPolicies) > 0 {
		fmt.Fprintf(&sb, " excepted=%v", d.ExceptedPolicies)
	}
	return sb.String()
}
