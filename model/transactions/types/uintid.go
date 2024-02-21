package types

// UIntIDI is an interface for types that can be converted to a uint.
type UIntIDI interface {
	ToUIntID() uint32
}

type UIntID uint32

func (f *UIntID) ToUIntID() uint32 {
	return uint32(*f)
}

// SetUIntID is a helper function that allocates a new uint value
// to store v and returns a pointer to it.
func SetUIntID(v uint32) *UIntID {
	p := new(uint32)
	*p = v
	return (*UIntID)(p)
}
