package main

// ScanType - what kind of scan to do
type ScanType int

const (
	ScanExact ScanType = iota
	ScanUnknown
	ScanBiggerThan
	ScanSmallerThan
	ScanBiggerThanOrEqual
	ScanSmallerThanOrEqual
	ScanChanged
	ScanUnchanged
	ScanIncreased
	ScanDecreased
	ScanIncreasedBy
	ScanDecreasedBy
	ScanBetween
	ScanNotEqual
)

// DataType
type DataType int

const (
	TypeInt8 DataType = iota
	TypeInt16
	TypeInt32
	TypeInt64
	TypeUInt8
	TypeUInt16
	TypeUInt32
	TypeUInt64
	TypeFloat32
	TypeFloat64
	TypeBytes
	TypeString
)

func dataTypeSize(dt DataType) int {
	switch dt {
	case TypeInt8, TypeUInt8:
		return 1
	case TypeInt16, TypeUInt16:
		return 2
	case TypeInt32, TypeUInt32, TypeFloat32:
		return 4
	case TypeInt64, TypeUInt64, TypeFloat64:
		return 8
	default:
		return 4
	}
}

func dataTypeName(dt DataType) string {
	names := []string{
		"Int8", "Int16", "Int32", "Int64",
		"UInt8", "UInt16", "UInt32", "UInt64",
		"Float32", "Float64", "Bytes", "String",
	}
	if int(dt) < len(names) {
		return names[dt]
	}
	return "Unknown"
}

// ScanResult holds a single match
type ScanResult struct {
	Address uintptr
	Value   []byte // raw bytes
}

// ScanParams passed to scanner
type ScanParams struct {
	DT         DataType
	ST         ScanType
	Value      []byte // primary value
	Value2     []byte // secondary (for between / increasedBy etc)
	Delta      []byte // for increased/decreased by exact amount
	Tolerance  float64
	Writable   bool
	Executable bool
	RangeLo    uintptr // if set, only scan addresses >= RangeLo
	RangeHi    uintptr // if set, only scan addresses < RangeHi
}

// FrozenEntry - address being frozen to a value
type FrozenEntry struct {
	Address uintptr
	Value   []byte
	Label   string
	Active  bool
}
