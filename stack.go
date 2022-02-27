package errors

import (
	"fmt"
	"path/filepath"
	"runtime"
	"unsafe"
)

// WithStack collects a stack of calls.
//  err = errors.WithStack(err)
func WithStack(err error) error {
	return global.WithSkip(1).WithStack(err)
}
func (b Builder) WithStack(err error) error {
	r := b.extractFrom(err)
	if r == nil {
		return nil
	}

	if len(r.callers) > 0 {
		return r
	}

	if b.Depth <= 0 {
		b.Depth = DefaultCallersDepth
	}

	r.callers = make([]uintptr, b.Depth)
	r.callers = r.callers[:runtime.Callers(b.Skip+2, r.callers)]

	return r
}

// WithStackCustom collects a stack of calls with a given depth and skipping
// skip frames. Collects the stack of calls even if the Builder's NeedStack
// is not specified.
//  err = errors.WithStackCustom(err, 0, 5)
func WithStackCustom(err error, skip, depth int) error {
	if skip < 0 {
		skip = 0
	}

	return global.WithStackCustom(err, skip+1, depth)
}
func (b Builder) WithStackCustom(err error, skip, depth int) error {
	r := b.extractFrom(err)
	if r == nil {
		return nil
	}

	if depth <= 0 {
		return r
	}

	if skip < 0 {
		skip = 0
	}

	if len(r.callers) > 0 {
		return r
	}

	r.callers = make([]uintptr, depth)
	r.callers = r.callers[:runtime.Callers(skip+2, r.callers)]

	return r
}

// Callers returns a list of call stacks.
//  var target *errors.Error
//  if errors.As(err, &target) {
//   frames := runtime.CallersFrames(target.Callers())
//   var frame runtime.Frame
//   for more := true; more; {
//     frame, more = frames.Next()
//     // usage of frame.
//   }
//  }
func (e *Error) Callers() []uintptr {
	callers := make([]uintptr, len(e.callers))
	copy(callers, e.callers)

	return callers
}

// StackTrace returns copy of callers as StackTrace.
func (e *Error) StackTrace() StackTrace {
	stack := make(StackTrace, len(e.callers))
	copy(stack, *(*StackTrace)(unsafe.Pointer(&e.callers)))
	return stack
}

// CallersIfNeed returns stack of calls if NeedStack is specified.
func (b Builder) CallersIfNeed() []uintptr {
	if !b.NeedStack {
		return nil
	}

	if b.Depth <= 0 {
		b.Depth = DefaultCallersDepth
	}

	callers := make([]uintptr, b.Depth)
	return callers[:runtime.Callers(b.Skip+3, callers)]
}

/*

	For compatibility with https://github.com/pkg/errors.

*/

// Frame represents a program counter inside a stack frame.
// For historical reasons if Frame is interpreted as a uintptr
// its value represents the program counter + 1.
type Frame uintptr

// StackTrace is stack of Frames from innermost (newest) to outermost (oldest).
type StackTrace []Frame

// ToStrings returns the stack trace in readable form:
// {package-name}/{file-name}:{file-line} {func-name}
func (s StackTrace) ToStrings() (stack []string) {
	if len(s) == 0 {
		return nil
	}

	stack = make([]string, 0, len(s))

	var (
		callers = *(*[]uintptr)(unsafe.Pointer(&s))

		pkg, file, funcName string

		frame  runtime.Frame
		frames = runtime.CallersFrames(callers)
	)

	for more := true; more; {
		frame, more = frames.Next()

		_, file = filepath.Split(frame.File)
		pkg, funcName = filepath.Split(frame.Func.Name())
		stack = append(
			stack,
			fmt.Sprintf(
				"%s%s:%d %s",
				pkg,
				file,
				frame.Line,
				funcName,
			),
		)
	}

	return stack
}
