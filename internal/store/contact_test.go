package store

import (
	"path/filepath"
	"testing"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSaveAndGetContact(t *testing.T) {
	s := testStore(t)

	c := &Contact{
		ACI:    "abc-123",
		Number: "+15551234567",
		Name:   "Alice",
	}
	if err := s.SaveContact(c); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetContactByACI("abc-123")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected contact, got nil")
	}
	if got.Number != "+15551234567" {
		t.Errorf("number = %q, want %q", got.Number, "+15551234567")
	}
	if got.Name != "Alice" {
		t.Errorf("name = %q, want %q", got.Name, "Alice")
	}
}

func TestGetContactByACI_NotFound(t *testing.T) {
	s := testStore(t)

	got, err := s.GetContactByACI("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

func TestSaveContact_Upsert(t *testing.T) {
	s := testStore(t)

	c := &Contact{ACI: "abc-123", Number: "+15551234567", Name: "Alice"}
	if err := s.SaveContact(c); err != nil {
		t.Fatal(err)
	}

	c2 := &Contact{ACI: "abc-123", Number: "+15559999999", Name: "Alice New"}
	if err := s.SaveContact(c2); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetContactByACI("abc-123")
	if err != nil {
		t.Fatal(err)
	}
	if got.Number != "+15559999999" {
		t.Errorf("number = %q, want %q", got.Number, "+15559999999")
	}
	if got.Name != "Alice New" {
		t.Errorf("name = %q, want %q", got.Name, "Alice New")
	}
}

func TestSaveContacts_Bulk(t *testing.T) {
	s := testStore(t)

	contacts := []*Contact{
		{ACI: "aaa", Number: "+1111", Name: "One"},
		{ACI: "bbb", Number: "+2222", Name: "Two"},
		{ACI: "ccc", Number: "+3333", Name: "Three"},
	}
	if err := s.SaveContacts(contacts); err != nil {
		t.Fatal(err)
	}

	for _, want := range contacts {
		got, err := s.GetContactByACI(want.ACI)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil {
			t.Fatalf("contact %q not found", want.ACI)
		}
		if got.Number != want.Number {
			t.Errorf("contact %q number = %q, want %q", want.ACI, got.Number, want.Number)
		}
		if got.Name != want.Name {
			t.Errorf("contact %q name = %q, want %q", want.ACI, got.Name, want.Name)
		}
	}
}

func TestSaveContacts_Empty(t *testing.T) {
	s := testStore(t)
	if err := s.SaveContacts(nil); err != nil {
		t.Fatal(err)
	}
}

func TestGetContactByNumber_Found(t *testing.T) {
	s := testStore(t)

	s.SaveContact(&Contact{ACI: "abc-123", Number: "+15551234567", Name: "Alice"})

	got, err := s.GetContactByNumber("+15551234567")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected contact, got nil")
	}
	if got.ACI != "abc-123" {
		t.Errorf("ACI = %q, want %q", got.ACI, "abc-123")
	}
	if got.Name != "Alice" {
		t.Errorf("Name = %q, want %q", got.Name, "Alice")
	}
}

func TestGetContactByNumber_NotFound(t *testing.T) {
	s := testStore(t)

	got, err := s.GetContactByNumber("+15550000000")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

func TestGetContactByNumber_MultipleContacts(t *testing.T) {
	s := testStore(t)

	s.SaveContact(&Contact{ACI: "aaa", Number: "+1111", Name: "One"})
	s.SaveContact(&Contact{ACI: "bbb", Number: "+2222", Name: "Two"})
	s.SaveContact(&Contact{ACI: "ccc", Number: "+3333", Name: "Three"})

	got, err := s.GetContactByNumber("+2222")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected contact, got nil")
	}
	if got.ACI != "bbb" {
		t.Errorf("ACI = %q, want %q", got.ACI, "bbb")
	}
}

func TestLookupACI_Found(t *testing.T) {
	s := testStore(t)

	s.SaveContact(&Contact{ACI: "abc-123", Number: "+15551234567", Name: "Alice"})

	aci := s.LookupACI("+15551234567")
	if aci != "abc-123" {
		t.Errorf("LookupACI = %q, want %q", aci, "abc-123")
	}
}

func TestLookupACI_NotFound(t *testing.T) {
	s := testStore(t)

	aci := s.LookupACI("+15550000000")
	if aci != "" {
		t.Errorf("LookupACI = %q, want empty", aci)
	}
}

