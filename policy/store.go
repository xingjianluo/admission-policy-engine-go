package policy

import (
	"context"
	"sync"
	"sync/atomic"
)

// Store 支持策略热更新与并发评估。
// 一致性保证：当前视图保存在 atomic.Pointer 中，评估开始时取一次快照，
// 整个请求看到完整一致的策略视图（新或旧之一）；更新先整体编译再原子替换，
// 不存在部分生效或半更新状态；读路径无锁，并发读取互不阻塞。
// 版本溯源：版本号只增不减，仅在更新真正生效时前进；
// 失败的更新与预演都不会让版本往前走。
type Store struct {
	cur     atomic.Pointer[snapshot]
	version atomic.Uint64
	mu      sync.Mutex // 仅串行化 Update，读路径（Evaluate/批量/预演）无锁
}

// NewStore 用初始策略集构建 Store，初始版本为 1。
func NewStore(initial []Policy) *Store {
	s := &Store{}
	s.version.Store(1)
	s.cur.Store(compile(initial, 1))
	return s
}

// NewStoreFromManifest 从清单字节构建 Store，返回非法策略错误。
func NewStoreFromManifest(data []byte) (*Store, []*LoadError, error) {
	res, err := LoadManifest(data)
	if err != nil {
		return nil, nil, err
	}
	return NewStore(res.Policies), res.Errors, nil
}

// Update 热更新：整体编译新清单后原子替换，已开始的请求仍看到旧视图。
// 单条非法策略被剔除并逐条返回错误，合法策略全部生效；
// 清单整体无法解析时返回全局错误且当前视图与版本号都保持不变。
// 更新生效时版本号单调递增；失败的更新不推进版本。
func (s *Store) Update(data []byte) ([]*LoadError, error) {
	res, err := LoadManifest(data)
	if err != nil {
		return nil, err
	}
	// 串行化生效动作，保证版本号与视图严格同序推进。
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.version.Add(1)
	s.cur.Store(compile(res.Policies, next))
	return res.Errors, nil
}

// Version 返回当前生效策略视图的版本号。
func (s *Store) Version() uint64 {
	return s.version.Load()
}

// Evaluate 在当前一致视图上评估资源；ctx 被取消时立即中止。
func (s *Store) Evaluate(ctx context.Context, res Resource) Decision {
	return s.cur.Load().evaluate(ctx, res)
}

// Policies 返回当前生效策略的副本（用于测试与调试）。
func (s *Store) Policies() []Policy {
	cur := s.cur.Load()
	out := make([]Policy, len(cur.policies))
	copy(out, cur.policies)
	return out
}
