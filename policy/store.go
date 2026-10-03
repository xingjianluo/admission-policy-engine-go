package policy

import (
	"context"
	"sync"
	"sync/atomic"
)

// initialVersion 是首次生效策略集的版本号；每次成功更新 +1。
const initialVersion int64 = 1

// Store 支持策略热更新与并发评估。
// 一致性保证：当前视图保存在 atomic.Pointer 中，评估开始时取一次快照，
// 整个请求看到完整一致的策略视图（新或旧之一）；更新先整体编译再原子替换，
// 不存在部分生效或半更新状态；读路径无锁，并发读取互不阻塞。
type Store struct {
	cur     atomic.Pointer[snapshot]
	writeMu sync.Mutex // 串行化更新，保证版本号严格单调递增
	nextVer atomic.Int64
}

// NewStore 用初始策略集构建 Store（初始版本为 1）。
func NewStore(initial []Policy) *Store {
	s := &Store{}
	s.nextVer.Store(initialVersion)
	s.cur.Store(compile(initial, initialVersion))
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
// 仅当清单整体可解析时版本号才 +1；清单整体无法解析时版本不变、视图保持原样。
// 单条非法策略被剔除并逐条返回错误，合法策略全部生效。
func (s *Store) Update(data []byte) ([]*LoadError, error) {
	res, err := LoadManifest(data)
	if err != nil {
		return nil, err
	}
	s.writeMu.Lock()
	ver := s.nextVer.Add(1)
	s.cur.Store(compile(res.Policies, ver))
	s.writeMu.Unlock()
	return res.Errors, nil
}

// Evaluate 在当前一致视图上评估资源；ctx 被取消时立即中止。
func (s *Store) Evaluate(ctx context.Context, res Resource) Decision {
	return s.cur.Load().evaluate(ctx, res)
}

// Version 返回当前生效策略集的版本号（只增不减）。
func (s *Store) Version() int64 {
	return s.cur.Load().version
}

// snapshot 返回当前快照（包内复用，供批量判定与预演取一致视图）。
func (s *Store) snapshot() *snapshot {
	return s.cur.Load()
}

// Policies 返回当前生效策略的副本（用于测试与调试）。
func (s *Store) Policies() []Policy {
	cur := s.cur.Load()
	out := make([]Policy, len(cur.policies))
	copy(out, cur.policies)
	return out
}
