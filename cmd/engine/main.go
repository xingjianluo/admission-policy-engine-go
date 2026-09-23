// Command engine 是本地准入策略评估引擎的演示入口：
// 加载策略清单与资源清单，逐条输出判定结论与依据。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/xingjianluo/admission-policy-engine-go/policy"
)

func main() {
	policyFile := flag.String("policies", "policies.json", "策略清单文件")
	resourceFile := flag.String("resources", "resources.json", "资源清单文件")
	flag.Parse()

	data, err := os.ReadFile(*policyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read policies: %v\n", err)
		os.Exit(1)
	}
	policies, loadErrs := policy.LoadManifest(data)
	for _, e := range loadErrs {
		fmt.Fprintf(os.Stderr, "load error: %v\n", e)
	}
	if len(policies) == 0 {
		fmt.Fprintln(os.Stderr, "no usable policies loaded")
		os.Exit(1)
	}

	rdata, err := os.ReadFile(*resourceFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read resources: %v\n", err)
		os.Exit(1)
	}
	var resources []policy.Resource
	if err := json.Unmarshal(rdata, &resources); err != nil {
		fmt.Fprintf(os.Stderr, "parse resources: %v\n", err)
		os.Exit(1)
	}

	store := policy.NewStore(policies)
	for _, res := range resources {
		d, err := store.Evaluate(context.Background(), res)
		if err != nil {
			fmt.Fprintf(os.Stderr, "evaluate %s/%s: %v\n", res.Namespace, res.Name, err)
			os.Exit(1)
		}
		fmt.Printf("%s %s/%s: allowed=%v reason=%s\n",
			res.Kind, res.Namespace, res.Name, d.Allowed, d.Reason)
	}
}
