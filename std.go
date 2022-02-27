package errors

import (
	std "errors"
	"fmt"
)

// Is reports whether any error in err's chain matches target.
//
// The chain consists of err itself followed by the sequence of errors obtained by
// repeatedly calling Unwrap.
//
// An error is considered to match a target if it is equal to that target or if
// it implements a method Is(error) bool such that Is(target) returns true.
//
// An error type might provide an Is method, so it can be treated as equivalent
// to an existing error. For example, if MyError defines
//
//	func (m MyError) Is(target error) bool { return target == fs.ErrExist }
//
// then Is(MyError{}, fs.ErrExist) returns true. See syscall.Errno.Is for
// an example in the standard library.
func Is(err, target error) bool {
	return std.Is(err, target)
}

// As finds the first error in err's chain that matches target, and if so, sets
// target to that error value and returns true. Otherwise, it returns false.
//
// The chain consists of err itself followed by the sequence of errors obtained by
// repeatedly calling Unwrap.
//
// An error matches target if the error's concrete value is assignable to the value
// pointed to by target, or if the error has a method As(interface{}) bool such that
// As(target) returns true. In the latter case, the As method is responsible for
// setting target.
//
// An error type might provide an As method, so it can be treated as if it were a
// different error type.
//
// As panics if target is not a non-nil pointer to either a type that implements
// error, or to any interface type.
func As(err error, target interface{}) bool {
	//goland:noinspection GoErrorsAs
	return std.As(err, target)
}

// Unwrap returns the result of calling the Unwrap method on err, if err's
// type contains an Unwrap method returning error.
// Otherwise, Unwrap returns nil.
func Unwrap(err error) error {
	return std.Unwrap(err)
}

// Is implements Is(error) bool interface.
func (e *Error) Is(target error) bool {
	for _, err := range e.errs {
		if std.Is(err, target) {
			return true
		}
	}

	multiErr, ok := target.(MultiError)
	if !ok {
		return false
	}

	for _, target := range multiErr.Errors() {
		if e.Is(target) {
			return true
		}
	}

	return false
}

// As implements As(interface{}) bool interface.
func (e *Error) As(target interface{}) bool {
	for _, err := range e.errs {
		if As(err, target) {
			return true
		}
	}

	return false
}

// Unwrap implements Unwrap() error interface.
func (e *Error) Unwrap() error {
	if len(e.errs) == 0 {
		return nil
	}

	return e.errs[0]
}

// New returns an error that formats as the given text.
// Each call to New returns a distinct error value even if the text is identical.
func New(msg string) error { return global.WithSkip(1).New(msg) }
func (b Builder) New(msg string) error {
	if messageChecker != nil {
		messageChecker(msg)
	}

	return &Error{
		errs:        []error{std.New(msg)},
		formats:     []FormatArgs{{Format: msg}},
		callers:     b.CallersIfNeed(),
		ReasonType:  b.ReasonType,
		ExtraFields: ExtraFields{},
	}
}

// Errorf formats according to a format specifier and returns the string as a
// value that satisfies error.
// Don't use errorf to wrap errors.
func Errorf(format string, args ...interface{}) error {
	return global.WithSkip(1).Errorf(format, args...)
}
func (b Builder) Errorf(format string, args ...interface{}) error {
	if messageChecker != nil {
		messageChecker(format)
	}
	if formatChecker != nil {
		formatChecker(format, args...)
	}

	return &Error{
		errs:        []error{fmt.Errorf(format, args...)},
		formats:     []FormatArgs{{Format: format, Args: args}},
		callers:     b.CallersIfNeed(),
		ReasonType:  b.ReasonType,
		ExtraFields: ExtraFields{},
	}
}
