package errors

import (
	std "errors"
	"io"
	"io/ioutil"
)

// MultiError interface for compatibility with errors from the library
// https://github.com/uber-go/multierr.
type MultiError interface {
	Errors() []error
}

// Errors returns a copy of the list of combined errors.
func (e *Error) Errors() []error {
	// e.errs must be immutable.
	errs := make([]error, len(e.errs))
	copy(errs, e.errs)

	return errs
}

// Errors returns a list of errors if combined. Compatible with
// https://github.com/uber-go/multierr.
//  for _, err := errors.Errors(err) {
//   fmt.Println(err)
//  }
func Errors(err error) (errs []error) {
	return global.Errors(err)
}
func (b Builder) Errors(err error) (errs []error) {
	r := b.extractFrom(err)
	if r == nil {
		return nil
	}

	return r.errs
}

// Combine combines several errors into one.
//  errors.Combine(err1, err2)
func Combine(errs ...error) error {
	return global.WithSkip(1).Combine(errs...)
}
func (b Builder) Combine(errs ...error) error {
	var n int
	for _, err := range errs {
		if err != nil {
			errs[n], n = err, n+1
		}
	}

	errs = errs[:n]
	if len(errs) == 0 {
		return nil
	}

	var (
		r = Error{
			errs:        make([]error, 0, len(errs)),
			formats:     make([]FormatArgs, 0, len(errs)),
			ReasonType:  b.ReasonType,
			ExtraFields: ExtraFields{},
		}
		nested *Error

		multiError MultiError
		ok         bool
	)

	for _, err := range errs {
		if std.As(err, &nested) {
			if !b.OverwriteReason &&
				r.ReasonType == ReasonInternal &&
				nested.ReasonType != ReasonInternal {
				r.ReasonType = nested.ReasonType
			}

			for field, v := range nested.ExtraFields {
				r.ExtraFields[field] = v
			}

			// Take a stack of nested errors, if necessary.
			if len(r.callers) == 0 && len(nested.callers) > 0 {
				r.callers = nested.callers
			}

			r.errs, r.formats =
				append(r.errs, nested.errs...),
				append(r.formats, nested.formats...)
			continue
		}

		if multiError, ok = err.(MultiError); !ok {
			r.errs, r.formats =
				append(r.errs, err),
				append(
					r.formats, FormatArgs{
						Format: "%v",
						Args:   []interface{}{err},
					},
				)
			continue
		}

		// Compatibility with https://github.com/uber-go/multierr.
		for _, err = range multiError.Errors() {
			if err == nil {
				continue
			}

			r.errs, r.formats =
				append(r.errs, err),
				append(
					r.formats, FormatArgs{
						Format: "%v",
						Args:   []interface{}{err},
					},
				)
		}
	}

	// Take a stack if needed.
	if len(r.callers) == 0 {
		r.callers = b.CallersIfNeed()
	}

	return &r
}

// Append combines two errors into one.
//  errors.Append(err1, err2)
func Append(left, right error) error {
	return global.WithSkip(1).Append(left, right)
}
func (b Builder) Append(left, right error) error {
	return b.WithSkip(1).Combine(left, right)
}

// AppendInto puts err at into and returns true if err != nil, must be into != nil.
//  if errors.AppendInto(&err, rows.Close) {
//   return err
//  }
//nolint:gocritic
func AppendInto(into *error, err error) (errored bool) {
	return global.WithSkip(1).AppendInto(into, err)
}

//nolint:gocritic
func (b Builder) AppendInto(into *error, err error) (errored bool) {
	if into != nil && err != nil {
		*into = b.WithSkip(1).Combine(*into, err)
	}

	return err != nil
}

// CloseAndAppendInto closes c and puts err at into and returns true
// if c.Close() != nil, must be into != nil.
//  if errors.CloseAndAppendInto(&err, resp.Body) {
//   return err
//  }
//nolint:gocritic
func CloseAndAppendInto(into *error, c io.Closer) (errored bool) {
	if c == nil {
		return false
	}

	// This will free up the reader in some cases, for example, for
	// the body of the http response. See
	// https://github.com/golang/go/blob/release-branch.go1.16/src/net/http/transport.go#L2204
	if r, ok := c.(io.Reader); ok {
		_, err := io.Copy(ioutil.Discard, r)
		errored = global.WithSkip(1).AppendInto(
			into, WithStackCustom(
				global.WithSkip(1).Wrapf(err, "reading %#T", r),
				1,
				2,
			),
		)
	}

	return errored || global.WithSkip(1).AppendInto(
		into, WithStackCustom(
			global.WithSkip(1).Wrapf(c.Close(), "closing %#T", c),
			1,
			2,
		),
	)
}
