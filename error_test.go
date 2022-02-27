package errors_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
	"golang.org/x/text/feature/plural"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
	"golang.org/x/text/message/catalog"

	"github.com/pkg/errors"
)

type multierr []error

func (m multierr) Error() string {
	return m[0].Error()
}

func (m multierr) Errors() []error {
	return m
}

func ExampleWrap() {
	fmt.Println(errors.Wrap(io.EOF, "123"))
	fmt.Println(errors.Wrap(nil, "123"))
	fmt.Println(errors.Wrap(errors.Wrap(io.EOF, "123"), "123"))

	// multierr - any errors.MultiError interface.
	fmt.Println(errors.Wrap(multierr{}, "123"))
	fmt.Println(errors.Wrap(multierr{nil}, "123"))

	// Output:
	// 123: EOF
	// <nil>
	// 123: 123: EOF
	// <nil>
	// <nil>
}

func ExampleWrapf() {
	fmt.Println(errors.Wrapf(nil, "%d", 123))
	fmt.Println(errors.Wrapf(io.EOF, "%d", 123))

	// Output:
	// <nil>
	// 123: EOF
}

func ExampleIs() {
	fmt.Println(
		errors.Is(
			errors.Wrapf(nil, "%d", 123),
			io.EOF,
		),
	)
	fmt.Println(
		errors.Is(
			errors.Wrapf(sql.ErrNoRows, "%d", 123),
			io.EOF,
		),
	)
	fmt.Println(
		errors.Is(
			errors.Wrapf(io.EOF, "%d", 123),
			io.EOF,
		),
	)
	someErr := errors.New("123")
	fmt.Println(
		errors.Is(
			errors.Wrap(someErr, "123"),
			someErr,
		),
	)
	someErr = errors.Errorf("%d", 123)
	fmt.Println(
		errors.Is(
			errors.Wrap(someErr, "123"),
			someErr,
		),
	)

	multiErr := errors.Append(sql.ErrNoRows, someErr)
	fmt.Println(
		errors.Is(
			errors.Wrap(multiErr, "123"),
			someErr,
		),
	)
	fmt.Println(
		errors.Is(
			errors.Wrap(multiErr, "123"),
			sql.ErrNoRows,
		),
	)
	fmt.Println(
		errors.Is(
			errors.Wrap(multiErr, "123"),
			errors.Combine(io.EOF, sql.ErrNoRows),
		),
	)
	fmt.Println(
		errors.Is(
			errors.Wrap(multiErr, "123"),
			multierr{io.EOF, sql.ErrNoRows},
		),
	)
	fmt.Println(
		errors.Is(
			errors.Wrap(multiErr, "123"),
			errors.Combine(io.EOF),
		),
	)
	fmt.Println(
		errors.Is(
			errors.Wrap(multiErr, "123"),
			multierr{io.EOF},
		),
	)

	// Output:
	// false
	// false
	// true
	// true
	// true
	// true
	// true
	// true
	// true
	// false
	// false
}

func ExampleCombine() {
	fmt.Println(
		errors.Combine(
			io.EOF,
			io.EOF,
			nil,
		),
	)

	fmt.Println(errors.Combine())

	// Output:
	// EOF; EOF
	// <nil>
}

func ExampleAppend() {
	fmt.Println(
		errors.Append(
			io.EOF,
			io.EOF,
		),
	)
	fmt.Println(
		errors.Append(
			nil,
			nil,
		),
	)

	// Output:
	// EOF; EOF
	// <nil>
}

func ExampleError_WithPrinter() {
	tag := language.Russian
	_ = message.Set(tag, "reading config %q", catalog.String("чтение конфига %[1]q"))
	_ = message.Set(tag, "module initialization", catalog.String("инициализация модуля"))
	_ = message.Set(
		tag,
		"unexpected number of arguments, expected %d",
		catalog.Var(
			"expected", plural.Selectf(
				1, "%d",
				plural.One, "ожидался",
				plural.Other, "ожидалось",
			),
		),
		catalog.String("неожиданное количество аргументов, ${expected} %d"),
	)

	printer := message.NewPrinter(tag)

	var target *errors.Error

	err := errors.Errorf("unexpected number of arguments, expected %d", 1)
	errors.As(err, &target)

	s := target.WithPrinter(printer)
	fmt.Println(s)

	err = errors.Errorf("unexpected number of arguments, expected %d", 2)
	errors.As(err, &target)

	s = target.WithPrinter(printer)
	fmt.Println(s)

	err = errors.Combine(
		errors.Wrapf(
			io.EOF,
			"reading config %q",
			"path/to/config.json",
		),
		errors.Wrap(io.EOF, "module initialization"),
	)
	errors.As(err, &target)

	s = target.WithPrinter(printer)
	fmt.Println(s)

	// Output:
	// неожиданное количество аргументов, ожидался 1
	// неожиданное количество аргументов, ожидалось 2
	// чтение конфига "path/to/config.json": EOF; инициализация модуля: EOF
}

func ExampleAppendInto() {
	var err error
	fmt.Println(
		errors.AppendInto(
			&err,
			nil,
		),
		err,
	)
	fmt.Println(
		errors.AppendInto(
			&err,
			io.EOF,
		),
		err,
	)

	// Output:
	// false <nil>
	// true EOF
}

func ExampleCloseAndAppendInto() {
	var err error
	fmt.Println(
		errors.CloseAndAppendInto(
			&err,
			nil,
		),
		err,
	)

	fmt.Println(
		errors.CloseAndAppendInto(
			&err,
			ioutil.NopCloser(bytes.NewReader(nil)),
		),
		err,
	)

	// Output:
	// false <nil>
	// false <nil>
}

func ExampleErrors() {
	err := errors.Combine(
		io.EOF,
		nil,
		io.EOF,
	)
	fmt.Println(errors.Errors(err))
	fmt.Println(errors.Errors(&errors.Error{}))

	// Output:
	// [EOF EOF]
	// []
}
func ExampleError_Errors() {
	err := errors.Combine(
		io.EOF,
		nil,
		io.EOF,
	)

	var target *errors.Error
	errors.As(err, &target)
	fmt.Println(target.Errors())

	// Output:
	// [EOF EOF]
}

func ExampleWithExtraFields() {
	extraFields := errors.ExtraFields{
		"1": 1,
	}

	fmt.Println(
		errors.WithExtraFields(nil, extraFields),
	)
	fmt.Println(
		errors.WithExtraFields(io.EOF, extraFields),
	)

	// Output:
	// <nil>
	// EOF
}

func ExampleWithMessage() {
	fmt.Println(errors.WithMessage(nil, "123"))
	fmt.Println(errors.WithMessage(io.EOF, "123"))

	// Output:
	// <nil>
	// 123: EOF
}

func ExampleWithMessagef() {
	fmt.Println(errors.WithMessagef(nil, "%d", 123))
	fmt.Println(errors.WithMessagef(io.EOF, "%d", 123))

	// Output:
	// <nil>
	// 123: EOF
}

func TestReasonType(t *testing.T) {
	var actual *errors.Error

	for _, test := range []struct {
		err      error
		expected errors.ReasonType
	}{
		{
			err:      errors.CauseAccessDenied(&errors.Error{}),
			expected: errors.ReasonInternal,
		},
		{
			err:      errors.Wrap(io.EOF, "123"),
			expected: errors.ReasonInternal,
		},
		{
			err:      errors.CauseAccessDenied(io.EOF),
			expected: errors.ReasonAccessDenied,
		},
		{
			err:      errors.CauseNotFound(io.EOF),
			expected: errors.ReasonNotFound,
		},
		{
			err:      errors.CauseBadRequest(io.EOF),
			expected: errors.ReasonBadRequest,
		},
	} {
		isIt := errors.As(test.err, &actual)
		if test.err == nil {
			continue
		}

		require.True(t, isIt)
		require.Equal(t, test.expected, actual.ReasonType)
	}

}

func TestAs(t *testing.T) {
	var (
		eerr    *errors.Error
		naerr   *net.AddrError
		ndnserr *net.DNSError
	)

	tests := []struct {
		err     error
		target  interface{}
		itIs    bool
		resultF func() string
		result  string
	}{
		{
			err:    errors.Wrap(nil, "123"),
			target: &eerr,
		},
		{
			err:     errors.Wrap(io.EOF, "123"),
			target:  &eerr,
			itIs:    true,
			resultF: func() string { return eerr.Error() },
			result:  "123: EOF",
		},
		{
			err: errors.Wrap(
				&net.AddrError{
					Err:  "1",
					Addr: "1",
				},
				"123",
			),
			target:  &eerr,
			itIs:    true,
			resultF: func() string { return eerr.Error() },
			result:  "123: address 1: 1",
		},
		{
			err: &net.AddrError{
				Err:  "1",
				Addr: "1",
			},
			target:  &naerr,
			itIs:    true,
			resultF: func() string { return naerr.Error() },
			result:  "address 1: 1",
		},
		{
			err: &net.AddrError{
				Err:  "123",
				Addr: "123",
			},
			target: &ndnserr,
			itIs:   false,
		},
		{
			err: &net.AddrError{
				Err:  "123",
				Addr: "123",
			},
			target: &eerr,
			itIs:   false,
		},
		{
			err: errors.Append(
				io.EOF, &net.AddrError{
					Err:  "1",
					Addr: "1",
				},
			),
			target:  &eerr,
			itIs:    true,
			resultF: func() string { return eerr.Error() },
			result:  "EOF; address 1: 1",
		},
		{
			err: errors.Append(
				io.EOF, &net.AddrError{
					Err:  "1",
					Addr: "1",
				},
			),
			target:  &naerr,
			itIs:    true,
			resultF: func() string { return naerr.Error() },
			result:  "address 1: 1",
		},
		{
			err: errors.Append(
				io.EOF, &net.AddrError{
					Err:  "1",
					Addr: "1",
				},
			),
			target: &ndnserr,
			itIs:   false,
		},
		{
			err: errors.Wrap(
				errors.Combine(
					nil, io.EOF, &net.AddrError{
						Err:  "1",
						Addr: "1",
					},
				),
				"123",
			),
			target:  &naerr,
			itIs:    true,
			resultF: func() string { return naerr.Error() },
			result:  "address 1: 1",
		},
		{
			err: errors.Wrap(
				errors.Combine(
					nil, io.EOF, &net.AddrError{
						Err:  "1",
						Addr: "1",
					},
				),
				"123",
			),
			target:  &eerr,
			itIs:    true,
			resultF: func() string { return eerr.Error() },
			result:  "123: EOF; address 1: 1",
		},
		{
			err: errors.WithStackCustom(
				errors.Combine(
					errors.WithStackCustom(
						&net.AddrError{
							Err:  "1",
							Addr: "1",
						},
						-1,
						1,
					),
					errors.Combine(
						nil, io.EOF, &net.AddrError{
							Err:  "1",
							Addr: "1",
						},
					),
					errors.Combine(
						nil, io.EOF, &net.AddrError{
							Err:  "1",
							Addr: "1",
						},
					),
					multierr{
						nil, io.EOF, &net.AddrError{
							Err:  "1",
							Addr: "1",
						},
					},
					errors.WithStackCustom(io.EOF, 0, 2),
					errors.WithStack(nil),
					errors.WithStack(errors.WithStack(io.EOF)),
				),
				0,
				3,
			),
			target:  &eerr,
			itIs:    true,
			resultF: func() string { return eerr.Error() },
			result:  "address 1: 1; EOF; address 1: 1; EOF; address 1: 1; EOF; address 1: 1; EOF; EOF",
		},
	}
	for i, test := range tests[:12] {
		if errors.As(test.err, test.target) != test.itIs {
			t.Errorf("%d) must be %v", i+1, test.itIs)
			continue
		}

		if !test.itIs {
			continue
		}

		msg := test.resultF()
		if msg != test.result {
			t.Errorf("%d) msg expect: %q, actual: %q", i+1, test.result, msg)
		}
	}
}

func TestWithExtraFields(t *testing.T) {
	expected := errors.ExtraFields{
		"1": 1,
	}

	var err *errors.Error
	isIt := errors.As(
		errors.WithExtraFields(io.EOF, expected),
		&err,
	)

	require.True(t, isIt)
	require.Equal(t, expected, err.ExtraFields)
}

func TestUnwrap(t *testing.T) {
	expected := errors.Wrap(io.EOF, "123")
	require.NotEqual(t, expected, errors.Unwrap(expected))

	expected = &errors.Error{}
	require.Empty(t, errors.Unwrap(expected))
}

func TestCause(t *testing.T) {
	expected := errors.Wrap(io.EOF, "123")
	require.NotEqual(t, expected, errors.Cause(expected))

	expected = &errors.Error{}
	require.Empty(t, errors.Cause(expected))
}

func TestError_Callers(t *testing.T) {
	b := errors.Builder{NeedStack: true}

	var target *errors.Error
	isIt := errors.As(b.Wrap(io.EOF, "123"), &target)
	require.True(t, isIt)
	require.NotEmpty(t, target.Callers())

	isIt = errors.As(b.Wrapf(io.EOF, "123"), &target)
	require.True(t, isIt)
	require.NotEmpty(t, target.Callers())
}

//goland:noinspection GoPrintFunctions
func TestStyle(t *testing.T) {
	errors.SetMessageChecker(
		func(msg string) {
			if msg == "" {
				panic("Error text not specified")
			}

			words := strings.Fields(msg)
			if len(words) == 0 {
				panic("Error text not specified")
			}

			firstWord := words[0]
			r, _ := utf8.DecodeRuneInString(firstWord)
			if unicode.IsUpper(r) {
				if len(firstWord) == 1 || firstWord != strings.ToTitle(firstWord) {
					panic("Error text should not start with a capital letter")
				}
			}

			r, _ = utf8.DecodeLastRuneInString(msg)
			if unicode.IsPunct(r) || unicode.IsSpace(r) {
				panic("Error text must not end with a punctuation mark")
			}
		},
	)

	errors.SetFormatChecker(
		func(_ string, args ...interface{}) {
			for _, arg := range args {
				if _, ok := arg.(error); ok {
					panic("Use errors.Wrap[f] instead errors.Errorf")
				}
			}
		},
	)

	require.Panics(t, func() {
		_ = errors.New("")
	})
	require.Panics(t, func() {
		_ = errors.Wrap(io.EOF, "")
	})
	require.Panics(t, func() {
		_ = errors.Wrap(io.EOF, " ")
	})
	require.Panics(t, func() {
		_ = errors.Wrap(io.EOF, "error!")
	})
	require.Panics(t, func() {
		_ = errors.Wrap(io.EOF, "error ")
	})
	require.Panics(t, func() {
		_ = errors.Wrap(io.EOF, "Error")
	})
	require.NotPanics(t, func() {
		_ = errors.Wrap(io.EOF, "EOF")
	})
	require.Panics(t, func() {
		_ = errors.Wrap(io.EOF, "I am a teapot")
	})
	require.Panics(t, func() {
		_ = errors.Errorf("error: %w", io.EOF)
	})
	require.Panics(t, func() {
		_ = errors.Wrapf(io.EOF, "error: %w", io.EOF)
	})
}

func TestCallersDepth(t *testing.T) {
	var b errors.Builder
	err := b.WithStack(io.EOF)
	require.Error(t, err)

	var target *errors.Error
	require.True(t, errors.As(err, &target))
	require.NotEmpty(t, target.Callers())

	err = b.WithStackCustom(io.EOF, -1, 2)
	require.Error(t, err)

	require.True(t, errors.As(err, &target))
	require.NotEmpty(t, target.Callers())

	err = b.WithStackCustom(io.EOF, 0, -1)
	require.Error(t, err)

	require.True(t, errors.As(err, &target))
	require.Empty(t, target.Callers())
}

func TestSetGlobal(t *testing.T) {
	errors.SetGlobal(errors.Builder{})
}

func TestReasonTypeInCombinedErrors(t *testing.T) {
	err := errors.CauseBadRequest(errors.New("123"))
	err = errors.Combine(err, nil)

	var actual *errors.Error
	require.True(t, errors.As(err, &actual))
	require.Equal(t, errors.ReasonBadRequest, actual.ReasonType)
}

func TestExtraFieldsInCombinedErrors(t *testing.T) {
	expectedFields := errors.ExtraFields{
		"123": 123,
	}

	err := errors.WithExtraFields(
		errors.New("123"),
		expectedFields,
	)
	err = errors.Combine(err, nil)

	var actual *errors.Error
	require.True(t, errors.As(err, &actual))
	require.Equal(t, expectedFields, actual.ExtraFields)
}

func TestWithInternal(t *testing.T) {
	err := errors.Internal().New("internal")

	var target *errors.Error
	require.ErrorAs(t, err, &target)
	require.Equal(t, errors.ReasonInternal, target.ReasonType)

	err = errors.Internal().Errorf("internal")
	require.ErrorAs(t, err, &target)
	require.Equal(t, errors.ReasonInternal, target.ReasonType)

	someErr := errors.CauseBadRequest(errors.New("123"))
	err = errors.Internal().Wrap(someErr, "internal")
	require.ErrorAs(t, err, &target)
	require.Equal(t, errors.ReasonInternal, target.ReasonType)

	err = errors.Internal().Combine(someErr)
	require.ErrorAs(t, err, &target)
	require.Equal(t, errors.ReasonInternal, target.ReasonType)
}

func TestWithNotFound(t *testing.T) {
	err := errors.NotFound().New("internal")

	var target *errors.Error
	require.ErrorAs(t, err, &target)
	require.Equal(t, errors.ReasonNotFound, target.ReasonType)

	err = errors.NotFound().Errorf("internal")
	require.ErrorAs(t, err, &target)
	require.Equal(t, errors.ReasonNotFound, target.ReasonType)

	someErr := errors.CauseBadRequest(errors.New("123"))
	err = errors.NotFound().Wrap(someErr, "internal")
	require.ErrorAs(t, err, &target)
	require.Equal(t, errors.ReasonNotFound, target.ReasonType)

	err = errors.NotFound().Combine(someErr)
	require.ErrorAs(t, err, &target)
	require.Equal(t, errors.ReasonNotFound, target.ReasonType)
}

func TestWithBadRequest(t *testing.T) {
	err := errors.BadRequest().New("internal")

	var target *errors.Error
	require.ErrorAs(t, err, &target)
	require.Equal(t, errors.ReasonBadRequest, target.ReasonType)

	err = errors.BadRequest().Errorf("internal")
	require.ErrorAs(t, err, &target)
	require.Equal(t, errors.ReasonBadRequest, target.ReasonType)

	someErr := errors.CauseNotFound(errors.New("123"))
	err = errors.BadRequest().Wrap(someErr, "internal")
	require.ErrorAs(t, err, &target)
	require.Equal(t, errors.ReasonBadRequest, target.ReasonType)

	err = errors.BadRequest().Combine(someErr)
	require.ErrorAs(t, err, &target)
	require.Equal(t, errors.ReasonBadRequest, target.ReasonType)
}

func TestWithAccessDenied(t *testing.T) {
	err := errors.AccessDenied().New("internal")

	var target *errors.Error
	require.ErrorAs(t, err, &target)
	require.Equal(t, errors.ReasonAccessDenied, target.ReasonType)

	err = errors.AccessDenied().Errorf("internal")
	require.ErrorAs(t, err, &target)
	require.Equal(t, errors.ReasonAccessDenied, target.ReasonType)

	someErr := errors.CauseBadRequest(errors.New("123"))
	err = errors.AccessDenied().Wrap(someErr, "internal")
	require.ErrorAs(t, err, &target)
	require.Equal(t, errors.ReasonAccessDenied, target.ReasonType)

	err = errors.AccessDenied().Combine(someErr)
	require.ErrorAs(t, err, &target)
	require.Equal(t, errors.ReasonAccessDenied, target.ReasonType)
}

func TestError_Format(t *testing.T) {
	err := errors.WithExtraFields(
		errors.WithStack(
			errors.New("123"),
		),
		errors.ExtraFields{
			"ExtraField1": 123,
		},
	)

	var r strings.Reader
	decoder := json.NewDecoder(&r)

	//goland:noinspection GoNilness
	for _, test := range []struct {
		format        string
		withJSON      bool
		withIndent    bool
		containFields map[string]struct{}
	}{
		{
			format: "%v",
		},
		{
			format: "%05.3v",
		},
		{
			format: "% 5.3v",
		},
		{
			format: "%-5.3v",
		},
		{
			format: "%s",
		},
		{
			format: "%q",
		},
		{
			format: "%+q",
		},
		{
			format: "%#q",
		},
		{
			format: "%x",
		},
		{
			format: "%#x",
		},
		{
			format: "%X",
		},
		{
			format: "%#X",
		},
		{
			format:   "%+v",
			withJSON: true,
			containFields: map[string]struct{}{
				"Error": {},
				"Extra": {},
			},
		},
		{
			format:     "%+ v",
			withJSON:   true,
			withIndent: true,
			containFields: map[string]struct{}{
				"Error": {},
				"Extra": {},
			},
		},
		{
			format:   "%#v",
			withJSON: true,
			containFields: map[string]struct{}{
				"Error": {},
				"Extra": {},
				"Stack": {},
			},
		},
		{
			format:     "% #v",
			withJSON:   true,
			withIndent: true,
			containFields: map[string]struct{}{
				"Error": {},
				"Extra": {},
				"Stack": {},
			},
		},
	} {
		test := test
		t.Run(
			test.format,
			func(t *testing.T) {
				actual := fmt.Sprintf(test.format, err)
				if !test.withJSON {
					expected := fmt.Sprintf(test.format, err.Error())
					require.Equal(t, expected, actual, actual)
					return
				}

				var target map[string]interface{}
				r.Reset(actual)
				err := decoder.Decode(&target)
				require.NoError(t, err)

				for field := range test.containFields {
					require.Contains(t, target, field)
				}

				if test.withIndent {
					require.Contains(t, actual, "\n", actual)
				}
			},
		)
	}
}

func ExampleStackTrace_ToStrings() {
	fmt.Println(errors.StackTrace{}.ToStrings())
	fmt.Println(errors.StackTrace{errors.Frame(caller)}.ToStrings())

	// Output:
	// []
	// [github.com/pkg/do_not_edit_test.go:6 errors_test.init]
}

var errSomeGlobal = errors.WithExtraFields(
	errors.New("some error"),
	errors.ExtraFields{
		"key1": "val1",
	},
)

func TestRace(t *testing.T) {
	t.Parallel()
	go func() {
		_ = errors.Wrap(errSomeGlobal, "123")
	}()
	go func() {
		_ = errors.Wrap(errSomeGlobal, "123")
	}()
}

func TestSetCustomFormatter(t *testing.T) {
	errors.SetCustomFormatter(
		func(
			e *errors.Error,
			f fmt.State,
			verb rune,
		) {
			if verb != 'v' || !(f.Flag('+') || f.Flag('#')) {
				_, _ = io.WriteString(f, e.Error())
				return
			}

			v := make(map[string]interface{}, 3)
			v["Error"] = e.Error()
			if len(e.ExtraFields) > 0 {
				v["Extra"] = e.ExtraFields
			}

			stack := e.StackTrace().ToStrings()
			if len(stack) > 0 {
				v["Stack"] = stack
			}

			enc := json.NewEncoder(f)
			enc.SetIndent("", " ")
			_ = enc.Encode(v)
		},
	)

	err := errors.WithStack(
		errors.WithExtraFields(
			errors.New("123"),
			errors.ExtraFields{
				"123": 123,
			},
		),
	)

	for _, test := range []struct {
		format string
		isJSON bool
	}{
		{
			format: "%s",
			isJSON: false,
		},
		{
			format: "%+s",
			isJSON: false,
		},
		{
			format: "%#s",
			isJSON: false,
		},
		{
			format: "%v",
			isJSON: false,
		},
		{
			format: "%+v",
			isJSON: true,
		},
		{
			format: "%#v",
			isJSON: true,
		},
	} {
		format := test.format
		t.Run(
			format,
			func(t *testing.T) {
				actual := fmt.Sprintf(format, err)
				if !test.isJSON {
					require.Equal(t, err.Error(), actual)
					return
				}

				var v map[string]interface{}
				err := json.Unmarshal([]byte(actual), &v)
				require.NoError(t, err, "some msg %s", actual)
				require.NotEmpty(t, v)
			},
		)
	}
}

func TestGetValue(t *testing.T) {
	fields := errors.ExtraFields{
		"SomeField": 123,
	}

	for _, test := range []struct {
		error
		hasKey bool
	}{
		{
			error:  nil,
			hasKey: false,
		},
		{
			error:  errors.New("123"),
			hasKey: false,
		},
		{
			error:  errors.WithExtraFields(errors.New("123"), fields),
			hasKey: true,
		},
	} {
		for key, want := range fields {
			got, exist := errors.GetValue(test.error, key)
			require.Equal(t, test.hasKey, exist)

			if exist {
				require.Equal(t, want, got)
			}
		}
	}
}
