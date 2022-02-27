package errors_test

import "runtime"

// caller must be on line 6.
var caller, _, _, _ = runtime.Caller(0)
