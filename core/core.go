package core

type ItemKind int

const (
	ItemKindFile ItemKind = iota
	ItemKindDir
)

type ItemRef interface {
	Name() string
	Kind() ItemKind
}

type Vault[Ref any] interface {
	Root() Ref
	List(where Ref) ([]Ref, error)
	Ref(where Ref, name string) (Ref, error)
	Create(where Ref, name string, kind ItemKind) (Ref, error)
	Read(file Ref) ([]byte, error)
	Write(file Ref, data []byte) error
	Delete(item Ref) error
}

// Empty/fake ("unit") ItemRef implementor for testing that a type implements Vault, like so:
//
//	var x Vault[UnitItemRef] = &MyVault[UnitItemRef]{}
//
// This type is otherwise unlikely to be useful.
type UnitItemRef struct{}

func (UnitItemRef) Name() string {
	return ""
}

func (UnitItemRef) Kind() ItemKind {
	return ItemKindFile
}
