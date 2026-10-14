package database

import (
	"database/sql"
	"fmt"
	"strings"
)

// GetBatchQueueTestingSpecificationProjectID resolves legacy queues without changing frozen queues.
// Callers must check access to the returned project before loading its specification.
func (db *DB) GetBatchQueueTestingSpecificationProjectID(queueID, defaultProjectID string) (string, error) {
	var projectID string
	err := db.QueryRow(`SELECT CASE WHEN EXISTS(SELECT 1 FROM batch_testing_specifications WHERE queue_id=q.id AND task_id='')
		THEN COALESCE(q.project_id,'') ELSE COALESCE(NULLIF(TRIM(q.project_id),''),?) END FROM batch_task_queues q WHERE q.id=?`, strings.TrimSpace(defaultProjectID), queueID).Scan(&projectID)
	return projectID, err
}

func (db *DB) GetBatchTaskTestingSpecification(queueID, taskID string, defaultProjectIDs ...string) (*TestingSpecificationSnapshot, error) {
	var snapshot TestingSpecificationSnapshot
	err := db.QueryRow(`SELECT name,content,source,hash FROM batch_testing_specifications
		WHERE queue_id=? AND task_id IN (?, '') AND EXISTS (SELECT 1 FROM batch_tasks WHERE queue_id=? AND id=?)
		ORDER BY CASE WHEN task_id=? THEN 0 ELSE 1 END LIMIT 1`, queueID, taskID, queueID, taskID, taskID).
		Scan(&snapshot.Name, &snapshot.Content, &snapshot.Source, &snapshot.Hash)
	if err != sql.ErrNoRows {
		if err != nil {
			return nil, err
		}
		return &snapshot, nil
	}
	// Existing queues are snapshotted once, before their next task executes.
	var projectID string
	if err := db.QueryRow(`SELECT COALESCE(q.project_id,'') FROM batch_task_queues q JOIN batch_tasks t ON t.queue_id=q.id WHERE q.id=? AND t.id=?`, queueID, taskID).Scan(&projectID); err != nil {
		return nil, fmt.Errorf("批量任务不存在: %w", err)
	}
	if projectID == "" && len(defaultProjectIDs) > 0 {
		projectID = strings.TrimSpace(defaultProjectIDs[0])
	}
	var spec *TestingSpecification
	if projectID != "" {
		p, err := db.GetProject(projectID)
		if err != nil {
			return nil, err
		}
		spec = p.TestingSpecification
	}
	snapshot = specificationSnapshot(spec, "project")
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// Persist project and rules together so later tasks survive configuration changes.
	if _, err := tx.Exec(`UPDATE batch_task_queues SET project_id=? WHERE id=? AND NOT EXISTS(SELECT 1 FROM batch_testing_specifications WHERE queue_id=? AND task_id='')`, projectID, queueID, queueID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec("INSERT OR IGNORE INTO batch_testing_specifications(queue_id,task_id,name,content,source,hash) VALUES (?,?,?,?,?,?)", queueID, "", snapshot.Name, snapshot.Content, snapshot.Source, snapshot.Hash); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return db.GetBatchTaskTestingSpecification(queueID, taskID)
}
