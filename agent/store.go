package agent

import (
	"context"
	"sync"

	"pentigent/db"
)

// 复用 db 包的类型
type Exploration = db.Exploration
type Node = db.Node
type Task = db.Task
type Activity = db.Activity
type Asset = db.Asset
type Finding = db.Finding
type PendingIntercept = db.PendingIntercept

// Store 探索层/任务层操作接口：agent 与 db 之间的边界
type Store interface {
	// 探索图
	CreateExploration(ctx context.Context, taskID int64, goal string) (int64, error)
	GetExploration(ctx context.Context, id int64) (*Exploration, error)
	GetTodolist(ctx context.Context, explorationID int64) ([]string, error)
	SetTodolist(ctx context.Context, explorationID int64, list []string) error
	SetExplorationStatus(ctx context.Context, id int64, status string) error
	CreateGoal(ctx context.Context, explorationID int64, title, desc string) (int64, error)
	AddIntent(ctx context.Context, explorationID int64, title, desc string) (int64, error)
	CreateFact(ctx context.Context, explorationID int64, summary, status string, content map[string]any) (int64, error)
	CreateFindingNode(ctx context.Context, explorationID int64, title, severity string, evidence map[string]any) (int64, error)
	ProveGoals(ctx context.Context, explorationID int64, goalIDs []int64) error
	SetNodeStatus(ctx context.Context, id int64, status string) error
	ClaimNextIntent(ctx context.Context, explorationID int64, workerID string) (*Node, error)
	AddEdge(ctx context.Context, explorationID, fromID, toID int64, relation string) error
	Anchor(ctx context.Context, explorationID, nodeID, assetID int64) error
	HasOpenIntent(ctx context.Context, explorationID int64) (bool, error)

	// 任务层
	GetTask(ctx context.Context, id int64) (*Task, error)
	SetTaskStatus(ctx context.Context, id int64, status, errMsg string) error
	LogActivity(ctx context.Context, a Activity) (int64, error)

	// 资产
	InsertAsset(ctx context.Context, companyID int64, a Asset) (int64, bool, error)
	SearchWorkerTraces(ctx context.Context, taskID int64, q string, limit int) ([]Activity, error)
	GetWorkerTrace(ctx context.Context, intentID int64, limit int) ([]Activity, error)
	ReportFinding(ctx context.Context, f Finding) (int64, bool, error)

	// 审批
	EnqueueIntercept(ctx context.Context, p PendingIntercept) (int64, error)
	GetPendingStatus(ctx context.Context, id int64) (string, error)
}

// ---- Provider 全局单例（engine 启动时注入）----

var (
	providerMu  sync.RWMutex
	currentProv Provider
)

func SetCurrentProvider(p Provider) {
	providerMu.Lock()
	defer providerMu.Unlock()
	currentProv = p
}

func CurrentProvider() Provider {
	providerMu.RLock()
	defer providerMu.RUnlock()
	if currentProv == nil {
		return NewMockProvider()
	}
	return currentProv
}