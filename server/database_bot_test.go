package main

import (
	"fmt"
	"testing"
)

func TestWrapKeyStoreIndexesProfilePasswords(t *testing.T) {
	store := newWrapKeyStore()
	passwords := make([]string, 100)
	for i := range passwords {
		passwords[i] = fmt.Sprintf("test-password-%03d", i)
	}
	if err := store.SetPasswords("", passwords); err != nil {
		t.Fatalf("SetPasswords() error = %v", err)
	}
	if got := store.Count(); got != len(passwords) {
		t.Fatalf("Count() = %d, want %d", got, len(passwords))
	}
	for _, password := range passwords {
		got, exists := store.ProfilePassword(profileKeyID(password))
		if !exists || got != password {
			t.Errorf("ProfilePassword(profileKeyID(%q)) = %q, %t", password, got, exists)
		}
	}

	added := "additional-password"
	if err := store.AddPassword(added); err != nil {
		t.Fatalf("AddPassword() error = %v", err)
	}
	if got, exists := store.ProfilePassword(profileKeyID(added)); !exists || got != added {
		t.Fatalf("added profile password lookup = %q, %t", got, exists)
	}
	store.RemovePassword(added)
	if _, exists := store.ProfilePassword(profileKeyID(added)); exists {
		t.Fatal("removed profile password remains indexed")
	}
}
