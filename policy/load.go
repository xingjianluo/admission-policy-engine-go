package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// LoadErrorCode 区分策略加载失败的具体原因。
type LoadErrorCode string

const (
	ErrMissingField   LoadErrorCode = "MISSING_FIELD"  // 必填字段缺失
	ErrInvalidType    LoadErrorCode = "INVALID_TYPE"   // 字段类型错误
	ErrInvalidValue   LoadErrorCode = "INVALID_VALUE"  // 字段取值非法
	ErrConflictingPol LoadErrorCode = "CONFLICT"       // 策略间相互冲突
	ErrMalformedDoc   LoadErrorCode = "MALFORMED_DOC"  // 清单整体无法解析
	ErrEmptyManifest  LoadErrorCode = "EMPTY_MANIFEST" // 清单为空或没有任何可用策略
)

// LoadError 描述单条策略的加载失败，原因可区分且稳定。
type LoadError struct {
	Policy  string        `json:"policy"` // 能识别则为策略名，否则为下标占位符
	Code    LoadErrorCode `json:"code"`
	Field   string        `json:"field,omitempty"`
	Message string        `json:"message"`
}

func (e *LoadError) Error() string {
	return fmt.Sprintf("policy %q: %s: %s", e.Policy, e.Code, e.Message)
}

// LoadResult 是清单归一结果：合法策略可用，非法策略逐条给出错误。
type LoadResult struct {
	Policies []Policy     `json:"policies"`
	Errors   []*LoadError `json:"errors,omitempty"`
}

// manifest 是清单文件的顶层结构。
type manifest struct {
	Policies []json.RawMessage `json:"policies"`
}

// LoadManifest 从 JSON 字节加载策略清单并归一到统一模型。
// 单条非法策略不影响其余策略的可用性；所有错误均带稳定原因码。
func LoadManifest(data []byte) (*LoadResult, error) {
	res := &LoadResult{}

	var top manifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&top); err != nil {
		// 清单整体无法解析：没有任何策略可用，属于全局错误。
		return nil, &LoadError{
			Policy:  "<manifest>",
			Code:    ErrMalformedDoc,
			Message: err.Error(),
		}
	}

	seen := map[string]struct{}{}
	for i, raw := range top.Policies {
		tag := fmt.Sprintf("#%d", i)
		p, lerr := parsePolicy(raw, tag)
		if lerr != nil {
			res.Errors = append(res.Errors, lerr)
			continue
		}
		if _, dup := seen[p.Name]; dup {
			res.Errors = append(res.Errors, &LoadError{
				Policy:  p.Name,
				Code:    ErrConflictingPol,
				Field:   "name",
				Message: "duplicate policy name conflicts with an earlier policy",
			})
			continue
		}
		seen[p.Name] = struct{}{}
		res.Policies = append(res.Policies, *p)
	}
	return res, nil
}

// parsePolicy 解析并校验单条策略；任何字段缺失、类型错误或取值非法
// 都转换为带稳定原因码的 LoadError，绝不静默跳过。
func parsePolicy(raw json.RawMessage, tag string) (*Policy, *LoadError) {
	fail := func(code LoadErrorCode, field, msg string) *LoadError {
		return &LoadError{Policy: tag, Code: code, Field: field, Message: msg}
	}

	var p Policy
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fail(ErrInvalidType, "", err.Error())
	}

	if p.Name == "" {
		return nil, fail(ErrMissingField, "name", "policy name is required")
	}
	// 后续错误改用策略名标识，便于定位。
	fail = func(code LoadErrorCode, field, msg string) *LoadError {
		return &LoadError{Policy: p.Name, Code: code, Field: field, Message: msg}
	}

	switch p.Effect {
	case "":
		return nil, fail(ErrMissingField, "effect", "effect is required")
	case EffectAllow, EffectDeny:
	default:
		return nil, fail(ErrInvalidValue, "effect",
			fmt.Sprintf("effect must be %q or %q, got %q", EffectAllow, EffectDeny, p.Effect))
	}

	if len(p.Match.Kinds) == 0 && len(p.Match.Namespaces) == 0 && len(p.Match.Labels) == 0 {
		return nil, fail(ErrMissingField, "match", "match selector must not be empty")
	}
	if lerr := validateSelector(&p.Match, "match", fail); lerr != nil {
		return nil, lerr
	}
	for i := range p.Except {
		if lerr := validateSelector(&p.Except[i], fmt.Sprintf("except[%d]", i), fail); lerr != nil {
			return nil, lerr
		}
	}
	return &p, nil
}

// validateSelector 校验选择器内部取值：不允许空字符串键值等无意义条件。
func validateSelector(s *Selector, field string, fail func(LoadErrorCode, string, string) *LoadError) *LoadError {
	for _, k := range s.Kinds {
		if k == "" {
			return fail(ErrInvalidValue, field+".kinds", "kind entries must be non-empty")
		}
	}
	for _, n := range s.Namespaces {
		if n == "" {
			return fail(ErrInvalidValue, field+".namespaces", "namespace entries must be non-empty")
		}
	}
	for k := range s.Labels {
		if k == "" {
			return fail(ErrInvalidValue, field+".labels", "label keys must be non-empty")
		}
	}
	return nil
}
