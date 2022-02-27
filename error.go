package errors

import (
	"bytes"
	"encoding/json"
	std "errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// ExtraField name of the extra error field.
type ExtraField string

// ExtraFields set of the extra error fields.
type ExtraFields map[ExtraField]interface{}

var _ error = &Error{}

// Error implements error interface.
type Error struct {
	// errs list of combined errors. Used for Is and As methods.
	errs []error
	// formats list of formats and arguments to display error text.
	// Used for Error and WithPrinter methods. len(errs) == len(formats).
	formats []FormatArgs
	// callers stack of function calls.
	callers []uintptr

	ReasonType ReasonType
	ExtraFields
}

var (
	delimiter = []byte("; ")
	bufPool   = sync.Pool{
		New: func() interface{} {
			return &bytes.Buffer{}
		},
	}
)

// Error implements error interface.
func (e *Error) Error() (s string) {
	buf, _ := bufPool.Get().(*bytes.Buffer)
	defer bufPool.Put(buf)

	buf.Reset()
	for i, f := range e.formats {
		if i > 0 {
			buf.Write(delimiter)
		}

		_, _ = f.WriteTo(buf)
	}

	return buf.String()
}

// Wrap wraps an error with a given message.
//  err = errors.Wrap(err, "reading config")
// If you need to collect a stack when wrapping, set the Builder's parameter
// NeedStack (see Builder).
// If you need to panic when using bad error handling style, set Builder
// parameter PanicAboutBadStyle (see Builder).
func Wrap(err error, msg string) error {
	return global.WithSkip(1).Wrap(err, msg)
}
func (b Builder) Wrap(err error, msg string) error {
	if messageChecker != nil {
		messageChecker(msg)
	}

	r := b.extractFrom(err)
	if r == nil {
		return nil
	}

	r.formats[0] = FormatArgs{
		Format: "%v: %v",
		Args: []interface{}{
			FormatArgs{Format: msg},
			r.formats[0],
		},
	}

	if b.NeedStack {
		r.callers = b.CallersIfNeed()
	}

	return r
}

// WithMessage for compatibility with https://github.com/pkg/errors.
func WithMessage(err error, msg string) error {
	return global.WithoutStack().Wrap(err, msg)
}

// WithMessagef for compatibility with https://github.com/pkg/errors.
func WithMessagef(err error, msg string, args ...interface{}) error {
	return global.WithoutStack().Wrapf(err, msg, args...)
}

// Wrapf wraps an error with a given message and arguments, like Printf functions.
//  err = errors.Wrapf(
//    err, "reading config %q", path,
//  )
// If you need to collect a stack when wrapping, set the Builder's parameter
// NeedStack (see Builder).
// If you need to panic when using bad error handling style, set Builder parameter
// PanicAboutBadStyle (see Builder).
func Wrapf(err error, msg string, args ...interface{}) error {
	return global.WithSkip(1).Wrapf(err, msg, args...)
}
func (b Builder) Wrapf(err error, format string, args ...interface{}) error {
	if messageChecker != nil {
		messageChecker(format)
	}
	if formatChecker != nil {
		formatChecker(format, args...)
	}

	r := b.extractFrom(err)
	if r == nil {
		return nil
	}

	r.formats[0] = FormatArgs{
		Format: "%v: %v",
		Args: []interface{}{
			FormatArgs{Format: format, Args: args},
			r.formats[0],
		},
	}

	if b.NeedStack {
		r.callers = b.CallersIfNeed()
	}

	return r
}

// WithExtraFields sets extra error fields to err.
//  err = WithExtraFields(
//   err, ExtraFields{
//    "SQLQuery": query,
//    "SQLArgs": args,
//   },
//  )
func WithExtraFields(err error, fields ExtraFields) error {
	return global.WithSkip(1).WithExtraFields(err, fields)
}
func (b Builder) WithExtraFields(err error, fields ExtraFields) error {
	r := b.extractFrom(err)
	if r == nil {
		return nil
	}

	for field, value := range fields {
		r.ExtraFields[field] = value
	}

	if len(r.callers) == 0 {
		r.callers = b.CallersIfNeed()
	}

	return r
}

// GetValue returns the value of the extra field from
// the error, if present.
func GetValue(err error, key ExtraField) (interface{}, bool) {
	var target *Error
	if !std.As(err, &target) {
		return nil, false
	}

	field, exist := target.ExtraFields[key]
	return field, exist
}

// Cause compatibility with https://github.com/pkg/errors Cause()
//  causeErr = Cause(err)
//  if causeErr != nil {
//   // cause handling ...
//  }
func Cause(err error) error {
	type causer interface {
		Cause() error
	}

	for err != nil {
		cause, ok := err.(causer)
		if !ok {
			break
		}

		err = cause.Cause()
	}

	return err
}

// Cause implements causer interface for compatibility with
// https://github.com/pkg/errors Cause()
//  causeErr = Cause(err)
//  if causeErr != nil {
//   // cause handling ...
//  }
func (e *Error) Cause() error {
	if len(e.errs) == 0 {
		return nil
	}

	return Cause(e.errs[0])
}

// extractFrom returns an Error pointer containing
// a copy of the data from err. Special cases:
// return nil if:
//  - err == nil
//  - errors.As(err, *Error) && len(Error.errs) == 0
// return new pointer to Error if:
//  - !errors.As(err, *Error)
// return new pointer to copy of Error if:
//  - errors.As(err, *Error) && len(Error.errs) > 0.
func (b Builder) extractFrom(err error) (r *Error) {
	if err == nil {
		return nil
	}

	if std.As(err, &r) {
		if len(r.errs) == 0 {
			return nil
		}

		// Avoiding data races.
		extraFields := make(ExtraFields, len(r.ExtraFields))
		for key, v := range r.ExtraFields {
			extraFields[key] = v
		}

		formats := make([]FormatArgs, len(r.formats))
		copy(formats, r.formats)

		r = &Error{
			errs:        r.errs,
			formats:     formats,
			callers:     r.callers,
			ReasonType:  r.ReasonType,
			ExtraFields: extraFields,
		}

		if b.OverwriteReason {
			r.ReasonType = b.ReasonType
		}

		return r
	}

	errs := []error{err}
	if m, ok := err.(MultiError); ok {
		errs = m.Errors()
	}

	formats := make([]FormatArgs, len(errs))

	var n int
	for _, err := range errs {
		if err == nil {
			continue
		}

		errs[n], formats[n] = err, FormatArgs{
			Format: "%v",
			Args:   []interface{}{err},
		}

		n++
	}

	errs, formats = errs[:n], formats[:n]
	if len(errs) == 0 {
		return nil
	}

	return &Error{
		errs:        errs,
		formats:     formats,
		ExtraFields: map[ExtraField]interface{}{},
		ReasonType:  b.ReasonType,
	}
}

var (
	// flags available flags for fmt.Formatter.
	flags = [...]int{
		'#', '+', ' ', '-', '0',
	}
)

// Formatter controls how fmt.State and rune
// are interpreted, and may call fmt.Sprint(f)
// or fmt.Fprint(f) etc. to generate its output.
type Formatter func(e *Error, f fmt.State, verb rune)

// customFormatter if present, called when the
// method (*Error) Error() is called.
var customFormatter Formatter

// SetCustomFormatter sets a global Formatter for
// custom error display. Unsafe for concurrent use.
func SetCustomFormatter(f Formatter) {
	customFormatter = f
}

// Format implements fmt.Formatter.
func (e *Error) Format(f fmt.State, verb rune) {
	if customFormatter != nil {
		customFormatter(e, f, verb)
		return
	}

	var format strings.Builder
	format.Grow(20)
	format.WriteByte('%')

	var useJSON, useIndent bool
	for _, flag := range flags {
		if verb == 'v' && !useJSON {
			switch flag {
			case '#', '+':
				useJSON = f.Flag(flag)
				continue
			}
		}

		if useJSON && flag == ' ' {
			useIndent = f.Flag(flag)
			continue
		}

		if f.Flag(flag) {
			format.WriteByte(byte(flag))
		}
	}

	// Remove alignment for json indented.
	if !useIndent {
		width, ok := f.Width()
		if ok {
			format.WriteString(strconv.Itoa(width))
		}

		prec, ok := f.Precision()
		if ok {
			format.WriteByte('.')
			format.WriteString(strconv.Itoa(prec))
		}
	}

	format.WriteRune(verb)
	if !useJSON {
		_, _ = fmt.Fprintf(f, format.String(), e.Error())
		return
	}

	buf, _ := bufPool.Get().(*bytes.Buffer)
	defer bufPool.Put(buf)

	buf.Reset()
	encoder := json.NewEncoder(buf)
	if useIndent {
		encoder.SetIndent("", " ")
	}

	v := make(map[string]interface{}, 3)
	v["Error"] = e.Error()
	if len(e.ExtraFields) > 0 {
		v["Extra"] = e.ExtraFields
	}
	if len(e.callers) > 0 && f.Flag('#') {
		v["Stack"] = e.StackTrace().ToStrings()
	}

	_ = encoder.Encode(v)

	// Remove carriage return.
	buf.Truncate(buf.Len() - 1)
	_, _ = fmt.Fprintf(f, format.String(), buf.String())
}
