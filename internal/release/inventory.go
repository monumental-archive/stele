// What a class's release owes as inventory (stele#396), read from the
// class's row in the release contract's one list (subjects.go). Most
// classes plan theirs: the build leg states which package each
// artifact is, and the prove leg derives the closures. Two do not:
// a class whose shipped binaries carry their own module list, and a
// class (an image of those binaries) that adds no inventory of its own.

package release

// InventoryRole is what a class's release owes as inventory.
type InventoryRole int

// The roles. The zero value is the common case: planned.
const (
	// InventoryPlanned: the build leg emits a plan, and each planned
	// document is derived from it.
	InventoryPlanned InventoryRole = iota
	// InventoryCarriedByBinaries: the shipped binaries carry their own
	// module list, read out of the bytes.
	InventoryCarriedByBinaries
	// InventoryNone: the class adds no inventory of its own.
	InventoryNone
)

// InventoryRoleOf returns the role the class's row declares. A class
// with no row plans its inventory: the default every class but the two
// exceptions has, so an undeclared class owes a plan rather than
// silently owing nothing.
func InventoryRoleOf(class string) InventoryRole {
	if c, ok := classRow(class); ok {
		return c.inventory
	}

	return InventoryPlanned
}
