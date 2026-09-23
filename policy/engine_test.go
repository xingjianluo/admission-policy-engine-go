package policy

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// logDecision 打印输入资源、命中的策略轨迹与最终判定依据。
func logDecision(t *testing.T, res Resource, d Decision, err error) {
	t.Helper()
	t.Logf("输入资源: kind=%s namespace=%s name=%s labels=%v", res.Kind, res.Namespace, res.Name, res.Labels)
	if err != nil {
		t.Logf("评估错误: %v", err)
		return
	}
	for _, tr := range d.Traces {
		t.Logf("  命中检查: policy=%q rule=%q effect=%s priority=%d matched=%v excepted=%v applied=%v",
			tr.Policy, tr.Rule, tr.Effect, tr.Priority, tr.Matched, tr.Excepted, tr.Applied)
	}
	t.Logf("最终判定: version=%d outcome=%s allowed=%v 依据=%s",
		d.Version, d.Outcome, d.Allowed, d.Reason)
}

func mustLoad(t *testing.T, data string) []Policy {
	t.Helper()
	policies, errs := LoadManifest([]byte(data))
	if len(errs) != 0 {
		t.Fatalf("unexpected load errors: %v", errs)
	}
	return policies
}

// 场景一：拒绝覆盖放行，且与规则书写顺序无关。
func TestDenyOverridesAllow(t *testing.T) {
	manifest := `{
	  "policies": [{
	    "name": "pod-policy",
	    "rules": [
	      {"name":"allow-all","effect":"allow","priority":10,"match":{"kinds":["Pod"]}},
	      {"name":"deny-prod","effect":"deny","priority":5,"match":{"kinds":["Pod"],"namespaces":["prod"]}}
	    ]
	  }]
	}`
	res := Resource{Kind: "Pod", Namespace: "prod", Name: "web"}

	// 顺序一：allow 在前 deny 在后。
	store := NewStore(mustLoad(t, manifest))
	d1, err := store.Evaluate(context.Background(), res)
	if err != nil {
		t.Fatal(err)
	}
	logDecision(t, res, d1, nil)
	if d1.Allowed || d1.Outcome != OutcomeDenied {
		t.Fatalf("期望拒绝，得到 %s/%v", d1.Outcome, d1.Allowed)
	}
	if !strings.Contains(d1.Reason, "deny-prod") {
		t.Fatalf("拒绝依据应指向 deny-prod，得到 %q", d1.Reason)
	}

	// 顺序二：调换两条规则书写顺序，结论必须一致（优先级更高的 allow 仍不能压过 deny）。
	manifestReversed := `{
	  "policies": [{
	    "name": "pod-policy",
	    "rules": [
	      {"name":"deny-prod","effect":"deny","priority":5,"match":{"kinds":["Pod"],"namespaces":["prod"]}},
	      {"name":"allow-all","effect":"allow","priority":10,"match":{"kinds":["Pod"]}}
	    ]
	  }]
	}`
	store2 := NewStore(mustLoad(t, manifestReversed))
	d2, err := store2.Evaluate(context.Background(), res)
	if err != nil {
		t.Fatal(err)
	}
	logDecision(t, res, d2, nil)
	if d2.Allowed || d2.Outcome != OutcomeDenied {
		t.Fatalf("调换顺序后仍期望拒绝，得到 %s/%v", d2.Outcome, d2.Allowed)
	}
	if !strings.Contains(d2.Reason, "deny-prod") {
		t.Fatalf("拒绝依据应指向 deny-prod，得到 %q", d2.Reason)
	}

	// 非 prod 资源只命中放行。
	dev := Resource{Kind: "Pod", Namespace: "dev", Name: "web"}
	d3, _ := store.Evaluate(context.Background(), dev)
	logDecision(t, dev, d3, nil)
	if !d3.Allowed || d3.Outcome != OutcomeAllowed || !strings.Contains(d3.Reason, "allow-all") {
		t.Fatalf("dev 资源期望被 allow-all 放行，得到 %q", d3.Reason)
	}
}

// 场景二：例外命中——带例外的规则只对命中且未被例外排除的资源生效。
func TestExceptionSemantics(t *testing.T) {
	manifest := `{
	  "policies": [{
	    "name": "pod-policy",
	    "rules": [
	      {"name":"deny-prod","effect":"deny","priority":10,
	       "match":{"kinds":["Pod"],"namespaces":["prod"]},
	       "except":[{"names":["whitelist-pod"]},{"labels":{"tier":"system"}}]}
	    ]
	  }]
	}`
	store := NewStore(mustLoad(t, manifest))

	// 1) 被名字例外跳过：应放行，轨迹可区分为 matched=true excepted=true。
	exceptedByName := Resource{Kind: "Pod", Namespace: "prod", Name: "whitelist-pod"}
	d1, _ := store.Evaluate(context.Background(), exceptedByName)
	logDecision(t, exceptedByName, d1, nil)
	if !d1.Allowed {
		t.Fatal("例外资源不应被拒绝")
	}
	if d1.Traces[0].Matched != true || d1.Traces[0].Excepted != true || d1.Traces[0].Applied != false {
		t.Fatalf("期望规则命中但被例外跳过，得到 %+v", d1.Traces[0])
	}

	// 2) 被标签例外跳过。
	exceptedByLabel := Resource{Kind: "Pod", Namespace: "prod", Name: "agent", Labels: map[string]string{"tier": "system"}}
	d2, _ := store.Evaluate(context.Background(), exceptedByLabel)
	logDecision(t, exceptedByLabel, d2, nil)
	if !d2.Allowed || d2.Traces[0].Excepted != true {
		t.Fatal("标签例外资源不应被拒绝")
	}

	// 3) 普通 prod 资源：命中、未被例外、拒绝。
	denied := Resource{Kind: "Pod", Namespace: "prod", Name: "web"}
	d3, _ := store.Evaluate(context.Background(), denied)
	logDecision(t, denied, d3, nil)
	if d3.Outcome != OutcomeDenied || d3.Traces[0].Excepted != false || d3.Traces[0].Applied != true {
		t.Fatalf("普通 prod 资源应被拒绝，得到 %s %q", d3.Outcome, d3.Reason)
	}

	// 4) 未命中任何规则：outcome=no_match，与被例外跳过可区分。
	noMatch := Resource{Kind: "ConfigMap", Namespace: "prod", Name: "cfg"}
	d4, _ := store.Evaluate(context.Background(), noMatch)
	logDecision(t, noMatch, d4, nil)
	if d4.Outcome != OutcomeNoMatch || d4.Traces[0].Matched != false {
		t.Fatalf("未命中资源应为 no_match，得到 %s", d4.Outcome)
	}
}

// 场景三：非法策略——字段缺失、类型错误、名称冲突产生稳定可区分的原因码，
// 且单条非法策略不影响其余策略。
func TestInvalidPolicies(t *testing.T) {
	manifest := `{
	  "policies": [
	    {"rules": []},
	    {"name": "bad-type", "rules": 123},
	    {"name": "dup", "rules": [
	      {"name":"r1","effect":"allow","match":{"kinds":["Pod"]}}
	    ]},
	    {"name": "dup", "rules": [
	      {"name":"r2","effect":"deny","match":{"kinds":["Pod"]}}
	    ]},
	    {"name": "bad-effect", "rules": [
	      {"name":"r1","effect":"maybe","match":{"kinds":["Pod"]}}
	    ]},
	    {"name": "valid", "rules": [
	      {"name":"deny-pods","effect":"deny","priority":1,"match":{"kinds":["Pod"]}}
	    ]}
	  ]
	}`
	policies, errs := LoadManifest([]byte(manifest))

	codes := map[ErrCode]bool{}
	for _, e := range errs {
		le := e.(*LoadError)
		codes[le.Code] = true
		t.Logf("加载拒绝: index=%d name=%q code=%s msg=%s", le.PolicyIndex, le.PolicyName, le.Code, le.Message)
	}
	for _, want := range []ErrCode{ErrCodeMissingField, ErrCodeInvalidType, ErrCodeConflict, ErrCodeInvalidValue} {
		if !codes[want] {
			t.Fatalf("缺少可区分的错误原因码 %s，实际 %v", want, codes)
		}
	}
	if len(policies) != 2 || policies[0].Name != "dup" || policies[1].Name != "valid" {
		t.Fatalf("首个 dup 与 valid 应可用，第二个 dup 应被拒，得到 %+v", policies)
	}

	// 合法策略在缺失其余策略的情况下照常工作。
	store := NewStore(policies)
	res := Resource{Kind: "Pod", Namespace: "prod", Name: "web"}
	d, _ := store.Evaluate(context.Background(), res)
	logDecision(t, res, d, nil)
	if d.Outcome != OutcomeDenied {
		t.Fatalf("合法策略应拒绝 Pod，得到 %s", d.Outcome)
	}

	// 语法错误清单与空清单也给出稳定原因码。
	if _, es := LoadManifest([]byte("{not json")); es[0].(*LoadError).Code != ErrCodeInvalidJSON {
		t.Fatalf("非法 JSON 应返回 INVALID_JSON，得到 %v", es)
	}
	if _, es := LoadManifest([]byte(`{"policies":[]}`)); es[0].(*LoadError).Code != ErrCodeEmptyManifest {
		t.Fatalf("空清单应返回 EMPTY_MANIFEST，得到 %v", es)
	}
}

// 场景四：并发热更新——每个请求的结论只可能对应旧版本或新版本之一，
// 不允许出现半更新状态；并发读取互不阻塞。
func TestConcurrentEvaluationAndHotUpdate(t *testing.T) {
	old := mustLoad(t, `{"policies":[{"name":"p","rules":[
	  {"name":"deny-prod","effect":"deny","priority":10,"match":{"kinds":["Pod"],"namespaces":["prod"]}}
	]}]}`)
	// 新版本：prod Pod 改为放行（只拒绝 dev）。
	new := mustLoad(t, `{"policies":[{"name":"p","rules":[
	  {"name":"deny-dev","effect":"deny","priority":10,"match":{"kinds":["Pod"],"namespaces":["dev"]}},
	  {"name":"allow-prod","effect":"allow","priority":1,"match":{"kinds":["Pod"],"namespaces":["prod"]}}
	]}]}`)

	store := NewStore(old)
	res := Resource{Kind: "Pod", Namespace: "prod", Name: "web"}

	// 每个快照版本对该资源的预期结论，由更新者在发布时登记。
	var expected sync.Map // version(uint64) -> Outcome
	expected.Store(store.Snapshot().Version(), OutcomeDenied)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	// 更新者：在旧/新两套策略之间反复切换。
	// 单更新者场景下版本号可预测（当前+1），先登记预期再发布，
	// 保证评估者读到的任何版本都已有预期结论。
	wg.Add(1)
	go func() {
		defer wg.Done()
		toggle := false
		for {
			select {
			case <-stop:
				return
			default:
			}
			next := store.Snapshot().Version() + 1
			if toggle {
				expected.Store(next, OutcomeDenied)
				store.Update(old)
			} else {
				expected.Store(next, OutcomeAllowed)
				store.Update(new)
			}
			toggle = !toggle
		}
	}()

	// 评估者：大量并发请求，结论必须与其快照版本严格一致。
	const workers = 16
	const iterations = 200
	var ewg sync.WaitGroup
	for w := 0; w < workers; w++ {
		ewg.Add(1)
		go func(id int) {
			defer ewg.Done()
			for i := 0; i < iterations; i++ {
				d, err := store.Evaluate(context.Background(), res)
				if err != nil {
					t.Errorf("评估返回错误: %v", err)
					return
				}
				want, ok := expected.Load(d.Version)
				if !ok {
					t.Errorf("未知快照版本 %d", d.Version)
					return
				}
				if d.Outcome != want.(Outcome) {
					t.Errorf("半更新或结论不一致: version=%d outcome=%s 期望 %s", d.Version, d.Outcome, want)
					return
				}
			}
		}(w)
	}
	ewg.Wait()
	close(stop)
	wg.Wait()

	final, _ := store.Evaluate(context.Background(), res)
	logDecision(t, res, final, nil)
	t.Logf("热更新阶段完成: 共评估 %d 次，最终版本=%d", workers*iterations, store.Snapshot().Version())
}

// 被取消的请求应立即停止评估并返回取消错误。
func TestCanceledContext(t *testing.T) {
	policies := mustLoad(t, `{"policies":[{"name":"p","rules":[
	  {"name":"deny-pods","effect":"deny","priority":1,"match":{"kinds":["Pod"]}}
	]}]}`)
	store := NewStore(policies)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := store.Evaluate(ctx, Resource{Kind: "Pod", Name: "x"})
	if err != context.Canceled {
		t.Fatalf("期望 context.Canceled，得到 %v", err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("取消后评估未立即返回")
	}
}

// 优先级依据：同效果多条规则命中时，最终依据取优先级最高者（与顺序无关）。
func TestPriorityDrivesReason(t *testing.T) {
	for order := 0; order < 2; order++ {
		var rules string
		if order == 0 {
			rules = `{"name":"low","effect":"deny","priority":1,"match":{"kinds":["Pod"]}},
			         {"name":"high","effect":"deny","priority":9,"match":{"kinds":["Pod"]}}`
		} else {
			rules = `{"name":"high","effect":"deny","priority":9,"match":{"kinds":["Pod"]}},
			         {"name":"low","effect":"deny","priority":1,"match":{"kinds":["Pod"]}}`
		}
		manifest := fmt.Sprintf(`{"policies":[{"name":"p","rules":[%s]}]}`, rules)
		store := NewStore(mustLoad(t, manifest))
		res := Resource{Kind: "Pod", Namespace: "p", Name: "x"}
		d, _ := store.Evaluate(context.Background(), res)
		logDecision(t, res, d, nil)
		if !strings.Contains(d.Reason, "high") {
			t.Fatalf("order=%d 期望依据为 high，得到 %q", order, d.Reason)
		}
	}
}
