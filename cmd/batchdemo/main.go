// batchdemo 是批量判定的本地示例：读取策略清单与资源清单，
// 对整批资源做批量判定并打印每个资源的结论、命中策略与判定依据。
//
// 用法（仓库根目录下）：
//
//	go run ./cmd/batchdemo
//	go run ./cmd/batchdemo -policies examples/policies.json -resources examples/resources.json
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/xingjianluo/admission-policy-engine-go/policy"
)

func main() {
	policiesPath := flag.String("policies", "examples/policies.json", "策略清单 JSON 路径")
	resourcesPath := flag.String("resources", "examples/resources.json", "资源清单 JSON 路径")
	flag.Parse()

	polData, err := os.ReadFile(*policiesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read policies: %v\n", err)
		os.Exit(1)
	}
	resData, err := os.ReadFile(*resourcesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read resources: %v\n", err)
		os.Exit(1)
	}

	store, lerrs, err := policy.NewStoreFromManifest(polData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load policies: %v\n", err)
		os.Exit(1)
	}
	for _, le := range lerrs {
		fmt.Printf("policy skipped: %v\n", le)
	}

	resources, err := policy.LoadResources(resData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load resources: %v\n", err)
		os.Exit(1)
	}

	results := store.EvaluateBatch(context.Background(), resources)
	fmt.Printf("policy version: %d, resources: %d\n\n", store.Version(), len(results))
	for _, r := range results {
		d := r.Decision
		fmt.Printf("%s/%s/%s\n", r.Resource.Kind, r.Resource.Namespace, r.Resource.Name)
		fmt.Printf("  effect=%s reason=%s version=%d\n", d.Effect, d.Reason, d.Version)
		fmt.Printf("  matched=%v excepted=%v\n", d.MatchedPolicies, d.ExceptedPolicies)
		fmt.Printf("  basis: %s\n\n", d.Explanation)
	}
}
