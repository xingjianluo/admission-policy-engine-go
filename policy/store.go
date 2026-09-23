package policy

import (
	"context"
	"sync/atomic"
)

// Snapshot 是某一版本策略集合的不可变视图。
type Snapshot struct {
	version  uint64
	policies []Policy
}

// Version 返回快照版本号。
func (s *Snapshot) Version() uint64 { return s.version }

// Policies 返回快照中的策略副本切片（切片头拷贝，元素不可变）。
func (s *Snapshot) Policies() []Policy {
	out := make([]Policy, len(s.policies))
	copy(out, s.policies)
	return out
}

// Store 支持原子热更新的策略存储。
// 更新整体替换快照（copy-on-write + atomic.Pointer），
// 读取只做一次原子加载，互不阻塞；评估期间持有的快照不会被中途改写。
type Store struct {
	p atomic.Pointer[Snapshot]
}

// NewStore 以给定策略创建存储，初始版本为 1。
func NewStore(policies []Policy) *Store {
	s := &Store{}
	s.Update(policies)
	return s
}

// Update 原子替换全部策略，版本号递增并返回新快照。
// policies 会被拷贝，调用方后续修改入参切片不影响已发布快照。
func (s *Store) Update(policies []Policy) *Snapshot {
	prev := s.p.Load()
	var v uint64 = 1
	if prev != nil {
		v = prev.version + 1
	}
	cp := make([]Policy, len(policies))
	copy(cp, policies)
	snap := &Snapshot{version: v, policies: cp}
	s.p.Store(snap)
	return snap
}

// Snapshot 返回当前一致的策略视图。
func (s *Store) Snapshot() *Snapshot { return s.p.Load() }

// Evaluate 在当前快照上评估资源。
// 快照在评估开始时一次性读取，更新期间已开始的请求看到完整的新或旧视图，
// 不会出现部分生效；ctx 取消时立即停止并返回 ctx.Err()。
func (s *Store) Evaluate(ctx context.Context, res Resource) (Decision, error) {
	snap := s.p.Load()
	return evaluate(ctx, snap, res)
}
