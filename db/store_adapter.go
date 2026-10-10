package db

import (
	"context"
)

// ---- agent.Store 边界适配层 ----
// 让 db.DB 直接满足 agent.Store 接口

func (d *DB) CreateGoal(ctx context.Context, explorationID int64, title, desc string) (int64, error) {
	content := map[string]any{"description": desc}
	return d.CreateNode(ctx, explorationID, "goal", "open", title, content)
}

func (d *DB) AddIntent(ctx context.Context, explorationID int64, title, desc string) (int64, error) {
	content := map[string]any{"description": desc}
	return d.CreateNode(ctx, explorationID, "intent", "open", title, content)
}

func (d *DB) CreateFact(ctx context.Context, explorationID int64, summary, status string, content map[string]any) (int64, error) {
	return d.CreateNode(ctx, explorationID, "fact", status, summary, content)
}

func (d *DB) CreateFindingNode(ctx context.Context, explorationID int64, title, severity string, evidence map[string]any) (int64, error) {
	content := map[string]any{"severity": severity, "evidence": evidence}
	return d.CreateNode(ctx, explorationID, "finding", "confirmed", title, content)
}

func (d *DB) ProveGoals(ctx context.Context, explorationID int64, goalIDs []int64) error {
	// 若给了具体 goal ids，标记它们；否则标记该探索下所有 open goal
	if len(goalIDs) == 0 {
		nodes, err := d.ListNodes(ctx, explorationID, "goal", "open")
		if err != nil {
			return err
		}
		for _, n := range nodes {
			if err := d.SetNodeStatus(ctx, n.ID, "met"); err != nil {
				return err
			}
		}
		return nil
	}
	for _, id := range goalIDs {
		if err := d.SetNodeStatus(ctx, id, "met"); err != nil {
			return err
		}
	}
	return nil
}