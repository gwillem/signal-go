package store

import (
	"database/sql"
	"time"
)

// Group represents a Signal group stored locally.
type Group struct {
	GroupID    string    // hex-encoded GroupIdentifier (32 bytes)
	MasterKey  []byte    // 32-byte master key
	Name       string    // cached group name (may be empty)
	Revision   int       // last known revision
	MemberACIs []string  // cached member ACIs (may be empty)
	UpdatedAt  time.Time // when this record was last updated
}

// SaveGroup stores or updates a group record.
func (s *Store) SaveGroup(g *Group) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO groups (group_id, master_key, name, revision, updated_at)
		 VALUES (?, ?, ?, ?, ?)`,
		g.GroupID, g.MasterKey, g.Name, g.Revision, time.Now().Unix(),
	)
	return err
}

// GetGroup retrieves a group by its group ID (hex-encoded GroupIdentifier).
func (s *Store) GetGroup(groupID string) (*Group, error) {
	var g Group
	var updatedAt int64
	err := s.db.QueryRow(
		"SELECT group_id, master_key, name, revision, updated_at FROM groups WHERE group_id = ?",
		groupID,
	).Scan(&g.GroupID, &g.MasterKey, &g.Name, &g.Revision, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	g.UpdatedAt = time.Unix(updatedAt, 0)
	return &g, nil
}

// GetGroupByMasterKey retrieves a group by its master key.
func (s *Store) GetGroupByMasterKey(masterKey []byte) (*Group, error) {
	var g Group
	var updatedAt int64
	err := s.db.QueryRow(
		"SELECT group_id, master_key, name, revision, updated_at FROM groups WHERE master_key = ?",
		masterKey,
	).Scan(&g.GroupID, &g.MasterKey, &g.Name, &g.Revision, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	g.UpdatedAt = time.Unix(updatedAt, 0)
	return &g, nil
}

// GetAllGroups retrieves all stored groups.
func (s *Store) GetAllGroups() ([]*Group, error) {
	rows, err := s.db.Query(
		"SELECT group_id, master_key, name, revision, updated_at FROM groups ORDER BY name, group_id",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []*Group
	for rows.Next() {
		var g Group
		var updatedAt int64
		if err := rows.Scan(&g.GroupID, &g.MasterKey, &g.Name, &g.Revision, &updatedAt); err != nil {
			return nil, err
		}
		g.UpdatedAt = time.Unix(updatedAt, 0)
		groups = append(groups, &g)
	}
	return groups, rows.Err()
}

// UpdateGroupName updates just the name of a group.
func (s *Store) UpdateGroupName(groupID, name string) error {
	_, err := s.db.Exec(
		"UPDATE groups SET name = ?, updated_at = ? WHERE group_id = ?",
		name, time.Now().Unix(), groupID,
	)
	return err
}
