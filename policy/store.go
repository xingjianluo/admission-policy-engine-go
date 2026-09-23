package policy

import (
	"context"
	"sync/atomic"
)

// Store 支持策略热更新与并发评估。
// 一致性保证：当前视图保存在 atomic.Pointer 中，评估开始时取一次快照，
// 整个请求看到完整一致的策略视图（新或旧之一）；更新先整体编译再原子替换，
// 不存在部分生效或半更新状态；读路径无锁，并发读取互不阻塞。
type Store struct {
	cur atomic.Pointer[snapshot]
}

// NewStore 用初始策略集构建 Store。
func NewStore(initial []Policy) *Store {
	s := &Store{}
	s.cur.Store(compile(initial))
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
// 清单整体无法解析时返回全局错误且当前视图保持不变。
func (s *Store) Update(data []byte) ([]*LoadError, error) {
	res, err := LoadManifest(data)
	if err != nil {
		return nil, err
	}
	s.cur.Store(compile(res.Policies))
	return res.Errors, nil
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
