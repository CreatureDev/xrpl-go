package types

// UIntI is an interface for types that can be converted to a uint.
type UIntI interface {
	ToUInt() uint32
}

type UInt uint32

func (f *UInt) ToUInt() uint32 {
	return uint32(*f)
}

// SetUInt is a helper function that allocates a new uint value
// to store v and returns a pointer to it.
func SetUInt(v uint32) *UInt {
	p := new(uint32)
	*p = v
	return (*UInt)(p)
}
