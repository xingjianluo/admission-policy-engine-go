// 命令 batch-demo 使用仓库自带的策略清单与资源清单，直接跑出批量判定结果，
// 无需另外编写代码：
//
//	go run ./cmd/batch-demo
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"

	"github.com/xingjianluo/admission-policy-engine-go/policy"
)

//go:embed policies.json
var policyManifest []byte

//go:embed resources.json
var resourceManifest []byte

type resourceFile struct {
	Resources []policy.Resource `json:"resources"`
}

func main() {
	store, loadErrs, err := policy.NewStoreFromManifest(policyManifest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load policies failed: %v\n", err)
		os.Exit(1)
	}
	for _, le := range loadErrs {
		fmt.Fprintf(os.Stderr, "skipped invalid policy: %v\n", le)
	}

	var rf resourceFile
	if err := json.Unmarshal(resourceManifest, &rf); err != nil {
		fmt.Fprintf(os.Stderr, "load resources failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("batch admission evaluation (current policy version=%d, %d resources)\n\n",
		store.Version(), len(rf.Resources))

	results := store.EvaluateBatch(context.Background(), rf.Resources)
	for _, r := range results {
		res := r.Resource
		fmt.Printf("[%d] %s/%s %s\n", r.Index, res.Namespace, res.Name, res.Kind)
		fmt.Printf("    effect   : %s (%s)\n", r.Decision.Effect, r.Decision.Reason)
		fmt.Printf("    matched  : %v\n", orDash(r.Decision.MatchedPolicies))
		fmt.Printf("    excepted : %v\n", orDash(r.Decision.ExceptedPolicies))
		fmt.Printf("    basis    : %s\n", r.Decision.Explanation)
		fmt.Printf("    version  : %d\n\n", r.Decision.Version)
	}

	// 再演示一次变更预演：新增一条拒绝 prod 下 ConfigMap 的候选策略，
	// 只试算不生效，当前版本与生效策略都不受影响。
	candidate := []byte(`{"policies": [
		{"name": "allow-pods", "effect": "allow", "priority": 10, "match": {"kinds": ["Pod"]}},
		{"name": "deny-debug-pods", "effect": "deny", "priority": 20,
		 "match": {"kinds": ["Pod"], "labels": {"mode": "debug"}},
		 "except": [{"namespaces": ["sandbox"]}]},
		{"name": "deny-prod-secrets", "effect": "deny", "priority": 30,
		 "match": {"kinds": ["Secret"], "namespaces": ["prod"]}},
		{"name": "deny-prod-configmaps", "effect": "deny", "priority": 30,
		 "match": {"kinds": ["ConfigMap"], "namespaces": ["prod"]}}
	]}`)

	preview, err := store.Preview(context.Background(), candidate, rf.Resources)
	if err != nil {
		fmt.Fprintf(os.Stderr, "preview failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("change preview: current version=%d vs candidate %s (ok=%v)\n",
		preview.CurrentVersion, preview.CandidateVersion, preview.CandidateOK)
	for _, ch := range preview.Changes {
		if !ch.Changed {
			continue
		}
		res := ch.Resource
		fmt.Printf("  CHANGED [%d] %s/%s %s: %s\n", ch.Index, res.Namespace, res.Name, res.Kind, ch.Summary)
	}
	fmt.Printf("\ncurrent policy still at version=%d (preview did not modify live policies)\n",
		store.Version())
}

func orDash(s []string) []string {
	if len(s) == 0 {
		return []string{"-"}
	}
	return s
}
