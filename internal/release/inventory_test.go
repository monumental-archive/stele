package release_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/release"
)

// TestInventoryRoles: the two exceptions are rows, and every other
// class — declared or not — plans its inventory.
func TestInventoryRoles(t *testing.T) {
	t.Parallel()

	for class, want := range map[string]release.InventoryRole{
		"go-binary":            release.InventoryCarriedByBinaries,
		"oci-image":            release.InventoryNone,
		"rust-binary":          release.InventoryPlanned,
		"rust-crate":           release.InventoryPlanned,
		"pgrx-extension":       release.InventoryPlanned,
		"pgrx-extension-image": release.InventoryPlanned,
		"wasm-npm":             release.InventoryPlanned,
	} {
		if got := release.InventoryRoleOf(class); got != want {
			t.Errorf("InventoryRoleOf(%q) = %d, want %d", class, got, want)
		}
	}
}

// TestRowsWithoutSubjects: a row carrying inventory facts alone is no
// subject definition — `derive subjects` refuses it as unknown, and
// the subject class list is #393's, unchanged.
func TestRowsWithoutSubjects(t *testing.T) {
	t.Parallel()

	for _, class := range []string{"rust-crate", "oci-image"} {
		if _, ok := release.AssetClassNamed(class); ok {
			t.Errorf("AssetClassNamed(%q) found a subject definition the row does not carry", class)
		}
	}

	const subjects = "go-binary,pgrx-extension,pgrx-extension-image,rust-binary"
	if got := strings.Join(release.SubjectClasses(), ","); got != subjects {
		t.Errorf("SubjectClasses = %q", got)
	}

	ext := release.ExtensionClasses()
	if len(ext) != 1 || !ext["pgrx-extension"] {
		t.Errorf("ExtensionClasses = %v, want pgrx-extension alone", ext)
	}
}
