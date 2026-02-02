package store

import "fmt"

// Contact represents a Signal contact with ACI-to-phone-number mapping.
type Contact struct {
	ACI    string
	Number string
	Name   string
}

// SaveContact upserts a single contact.
func (s *Store) SaveContact(c *Contact) error {
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO contact (aci, number, name) VALUES (?, ?, ?)",
		c.ACI, c.Number, c.Name,
	)
	if err != nil {
		return fmt.Errorf("store: save contact: %w", err)
	}
	return nil
}

// GetContactByACI returns the contact for the given ACI UUID, or nil if not found.
func (s *Store) GetContactByACI(aci string) (*Contact, error) {
	var c Contact
	err := s.db.QueryRow(
		"SELECT aci, number, name FROM contact WHERE aci = ?", aci,
	).Scan(&c.ACI, &c.Number, &c.Name)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, nil
		}
		return nil, fmt.Errorf("store: get contact: %w", err)
	}
	return &c, nil
}

// SaveContacts upserts multiple contacts in a single transaction.
func (s *Store) SaveContacts(contacts []*Contact) error {
	if len(contacts) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT OR REPLACE INTO contact (aci, number, name) VALUES (?, ?, ?)")
	if err != nil {
		return fmt.Errorf("store: prepare: %w", err)
	}
	defer stmt.Close()

	for _, c := range contacts {
		if _, err := stmt.Exec(c.ACI, c.Number, c.Name); err != nil {
			return fmt.Errorf("store: save contact %q: %w", c.ACI, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}
