package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ErrCode 是可区分且稳定的策略拒绝原因码。
type ErrCode string

const (
	ErrCodeInvalidJSON   ErrCode = "INVALID_JSON"
	ErrCodeMissingField  ErrCode = "MISSING_FIELD"
	ErrCodeInvalidType   ErrCode = "INVALID_TYPE"
	ErrCodeInvalidValue  ErrCode = "INVALID_VALUE"
	ErrCodeConflict      ErrCode = "CONFLICT"
	ErrCodeEmptyManifest ErrCode = "EMPTY_MANIFEST"
)

// LoadError 描述单条策略的加载失败原因。
type LoadError struct {
	PolicyIndex int
	PolicyName  string
	Code        ErrCode
	Message     string
}

func (e *LoadError) Error() string {
	name := e.PolicyName
	if name == "" {
		name = fmt.Sprintf("#%d", e.PolicyIndex)
	}
	return fmt.Sprintf("policy %s: %s: %s", name, e.Code, e.Message)
}

// LoadManifest 解析并归一化本地策略清单。
// 单条非法策略以 *LoadError 形式返回，不影响其余策略的可用性。
func LoadManifest(data []byte) ([]Policy, []error) {
	var raw json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&raw); err != nil {
		return nil, []error{&LoadError{PolicyIndex: -1, Code: ErrCodeInvalidJSON, Message: err.Error()}}
	}

	// 顶层结构：仅允许 {"policies": [...]}，逐条解码以便定位单条错误。
	var top struct {
		Policies []json.RawMessage `json:"policies"`
	}
	strict := json.NewDecoder(bytes.NewReader(raw))
	strict.DisallowUnknownFields()
	if err := strict.Decode(&top); err != nil {
		return nil, []error{&LoadError{PolicyIndex: -1, Code: classifyJSONErr(err), Message: err.Error()}}
	}
	if top.Policies == nil {
		return nil, []error{&LoadError{PolicyIndex: -1, Code: ErrCodeMissingField, Message: "missing required field: policies"}}
	}
	if len(top.Policies) == 0 {
		return nil, []error{&LoadError{PolicyIndex: -1, Code: ErrCodeEmptyManifest, Message: "manifest contains no policies"}}
	}

	var policies []Policy
	var errs []error
	seen := map[string]int{}
	for i, rawPolicy := range top.Policies {
		p, err := decodePolicy(i, rawPolicy)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if first, dup := seen[p.Name]; dup {
			errs = append(errs, &LoadError{
				PolicyIndex: i,
				PolicyName:  p.Name,
				Code:        ErrCodeConflict,
				Message:     fmt.Sprintf("duplicate policy name, first defined at index %d", first),
			})
			continue
		}
		seen[p.Name] = i
		policies = append(policies, p)
	}
	return policies, errs
}

// decodePolicy 严格解码并校验单条策略。
func decodePolicy(index int, raw json.RawMessage) (Policy, error) {
	var p Policy
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Policy{}, &LoadError{PolicyIndex: index, Code: classifyJSONErr(err), Message: err.Error()}
	}
	if strings.TrimSpace(p.Name) == "" {
		return Policy{}, &LoadError{PolicyIndex: index, Code: ErrCodeMissingField, Message: "missing required field: name"}
	}
	if len(p.Rules) == 0 {
		return Policy{}, &LoadError{PolicyIndex: index, PolicyName: p.Name, Code: ErrCodeMissingField, Message: "policy must contain at least one rule"}
	}
	ruleNames := map[string]bool{}
	for j, r := range p.Rules {
		if strings.TrimSpace(r.Name) == "" {
			return Policy{}, &LoadError{PolicyIndex: index, PolicyName: p.Name, Code: ErrCodeMissingField,
				Message: fmt.Sprintf("rule %d: missing required field: name", j)}
		}
		if ruleNames[r.Name] {
			return Policy{}, &LoadError{PolicyIndex: index, PolicyName: p.Name, Code: ErrCodeConflict,
				Message: fmt.Sprintf("duplicate rule name %q within policy", r.Name)}
		}
		ruleNames[r.Name] = true
		switch r.Effect {
		case EffectAllow, EffectDeny:
		case "":
			return Policy{}, &LoadError{PolicyIndex: index, PolicyName: p.Name, Code: ErrCodeMissingField,
				Message: fmt.Sprintf("rule %q: missing required field: effect", r.Name)}
		default:
			return Policy{}, &LoadError{PolicyIndex: index, PolicyName: p.Name, Code: ErrCodeInvalidValue,
				Message: fmt.Sprintf("rule %q: effect must be %q or %q, got %q", r.Name, EffectAllow, EffectDeny, r.Effect)}
		}
		for k := range r.Match.Labels {
			if strings.TrimSpace(k) == "" {
				return Policy{}, &LoadError{PolicyIndex: index, PolicyName: p.Name, Code: ErrCodeInvalidValue,
					Message: fmt.Sprintf("rule %q: match selector contains empty label key", r.Name)}
			}
		}
	}
	return p, nil
}

// classifyJSONErr 把解码错误归类为稳定的原因码。
func classifyJSONErr(err error) ErrCode {
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return ErrCodeInvalidType
	}
	return ErrCodeInvalidJSON
}
