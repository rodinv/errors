package errors

// Builder constructs errors.
type Builder struct {
	// Used when collecting a stack when a NeedStack is true.
	// Skips the specified number of frames.
	Skip int
	// Used to determine the depth of the call stack.
	Depth int
	// Used to set the ReasonType for error by default
	ReasonType ReasonType
	// Collects stack whenever Builder handles an error.
	NeedStack bool
	// If true ReasonType for error will be overwritten.
	OverwriteReason bool
}

// DefaultCallersDepth used by default if stacking depth is not specified in Builder.
const DefaultCallersDepth = 1 << 4

var global = Builder{Depth: DefaultCallersDepth}

// WithSkip returns Builder with the number of frames to skip
// increased by n.
func (b Builder) WithSkip(n int) Builder {
	b.Skip += n
	return b
}

// WithoutStack returns Builder without making a stack.
func (b Builder) WithoutStack() Builder {
	b.NeedStack = false
	return b
}

// SetGlobal sets b to global Builder. Unsafe for concurrent
// use. Use it in main func. Do not use this in the init func,
// as this can have a side effect on stacking when wrapping
// globals.
func SetGlobal(b Builder) {
	if b.Depth <= 0 {
		b.Depth = DefaultCallersDepth
	}

	global = b
}

// MessageChecker checks the error message for correctness
// and can cause panic if the error text is not correct.
type MessageChecker func(msg string)

// messageChecker if present, called when an error is generated.
var messageChecker MessageChecker

// SetMessageChecker sets a global MessageChecker to check
// the correctness of error messages. Unsafe for concurrent
// use. Use it in main func. Do not use this in the init
// func, as this can have a side effect when creating globals.
func SetMessageChecker(m MessageChecker) {
	messageChecker = m
}

// FormatChecker checks the error message for correctness
// and can cause panic if the error text is not correct.
type FormatChecker func(format string, args ...interface{})

// formatChecker if present, called when an error is generated.
var formatChecker FormatChecker

// SetFormatChecker sets a global FormatChecker to check
// the correctness of error messages. Unsafe for concurrent
// use. Use it in main func. Do not use this in the init func,
// as this can have a side effect when creating globals.
func SetFormatChecker(f FormatChecker) {
	formatChecker = f
}
