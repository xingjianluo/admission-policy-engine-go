package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Preview 用候选清单对同一批资源试算，并与当前生效策略逐条对比。
//
// 保证：
//   - 不读取也不写入 Store.cur：在一份临时编译的候选快照上试算，
//     预演绝不改动当前生效策略，也不推进版本号；
//   - 当前侧结论取一次当前快照，整批看到完整一致的当前版本，
//     预演期间其它协程的正式 Update 不影响本次对比的一致性；
//   - 候选清单整体无法解析（MALFORMED_DOC）时直接返回错误且保持现状；
//   - 候选条目为空、字段不全、互相冲突等：逐条错误记录在结果中，
//     其余合法条目照常参与试算，CandidateOK=false，绝不混同为
//     “没策略、一律放行”（即使合法条目为零也显式标注 EMPTY_CANDIDATE）。
func (s *Store) Preview(ctx context.Context, candidate []byte, resources []Resource) (*PreviewResult, error) {
	// 当前侧取一次快照：版本与策略视图在整轮对比中保持一致。
	curSnap := s.snapshot()

	res, err := LoadManifest(candidate)
	if err != nil {
		// 整份候选内容根本解析不了：直接失败，保持现状。
		return nil, err
	}

	errors := res.Errors
	if len(res.Policies) == 0 {
		// 没有任何可用候选策略是候选清单自身的问题，而不是“无策略放行”。
		errors = append(errors, &LoadError{
			Policy:  "<manifest>",
			Code:    ErrEmptyCandidate,
			Message: "candidate manifest contains no usable policy; refusing to preview as implicit allow-all",
		})
	}

	// 候选快照只存在于本次调用中，使用版本 0 编译占位，
	// 随后用候选指纹标识，不触碰 Store 的版本计数。
	candSnap := compile(res.Policies, 0)

	curResults := evaluateBatchOn(ctx, curSnap, resources)
	candResults := evaluateBatchOn(ctx, candSnap, resources)

	changes := make([]ResourceChange, len(resources))
	for i := range resources {
		cur := curResults[i].Decision
		cand := candResults[i].Decision
		kind, summary := classifyChange(cur, cand)
		changes[i] = ResourceChange{
			Index:     i,
			Resource:  resources[i],
			Current:   cur,
			Candidate: cand,
			Changed:   kind != ChangeUnchanged,
			Kind:      kind,
			Summary:   summary,
		}
	}

	return &PreviewResult{
		CurrentVersion:   curSnap.version,
		CandidateVersion: candidateFingerprint(res.Policies),
		CandidateOK:      len(errors) == 0,
		Errors:           errors,
		Changes:          changes,
	}, nil
}

// candidateFingerprint 对候选策略内容做稳定哈希，作为候选版本标识。
// 快照已排序，故 JSON 编码顺序确定，相同内容得到相同指纹。
func candidateFingerprint(policies []Policy) string {
	b, err := json.Marshal(policies)
	if err != nil {
		// Policy 仅含可编码的基础类型，走到这里属于编程错误。
		return "candidate-unknown"
	}
	sum := sha256.Sum256(b)
	return "candidate-" + hex.EncodeToString(sum[:12])
}

// classifyChange 对比同一资源在两套策略下的结论。
// 放行/拒绝翻转优先归类；结论方向相同但原因码或命中/例外依据变化
// 归为 BASIS_CHANGED；完全相同为 UNCHANGED。
func classifyChange(cur, cand Decision) (ChangeKind, string) {
	switch {
	case cur.Effect == EffectAllow && cand.Effect == EffectDeny:
		return ChangeAllowToDeny, fmt.Sprintf(
			"ALLOW -> DENY: was %s, now denied by %v", cur.Reason, cand.MatchedPolicies)
	case cur.Effect == EffectDeny && cand.Effect == EffectAllow:
		return ChangeDenyToAllow, fmt.Sprintf(
			"DENY -> ALLOW: was denied by %v, now %s", cur.MatchedPolicies, cand.Reason)
	case cur.Reason != cand.Reason ||
		!sameStringSet(cur.MatchedPolicies, cand.MatchedPolicies) ||
		!sameStringSet(cur.ExceptedPolicies, cand.ExceptedPolicies):
		return ChangeBasisChanged, fmt.Sprintf(
			"still %s but basis changed: %s [%v] except %v -> %s [%v] except %v",
			cand.Effect,
			cur.Reason, cur.MatchedPolicies, cur.ExceptedPolicies,
			cand.Reason, cand.MatchedPolicies, cand.ExceptedPolicies)
	default:
		return ChangeUnchanged, fmt.Sprintf(
			"unchanged: %s by %v except %v", cand.Reason, cand.MatchedPolicies, cand.ExceptedPolicies)
	}
}

// sameStringSet 判断两个有序字符串切片是否逐项相同。
// 快照按确定性顺序产出命中列表，直接逐项比较即可，顺序差异也算依据变化。
func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
