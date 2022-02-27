package errors

import (
	"bytes"
	"fmt"
	"io"

	"golang.org/x/text/message"
)

// WithPrinter returns the string rendered by Printer. Can be used to
// translate errors.
//  tag := language.Russian
//  _ = message.Set(tag, "module initialization", catalog.String("инициализация модуля"))
//  err = errors.Wrap(io.EOF, "module initialization")
//
//  var target *errors.Error
//  errors.As(err, &target)
//
//  printer := message.NewPrinter(tag)
//  s, _ := target.WithPrinter(printer)
//  fmt.Println(s)
func (e *Error) WithPrinter(p *message.Printer) string {
	buf, _ := bufPool.Get().(*bytes.Buffer)
	defer bufPool.Put(buf)

	buf.Reset()
	for i, format := range e.formats {
		if i > 0 {
			buf.Write(delimiter)
		}

		buf.WriteString(format.WithPrinter(p))
	}

	return buf.String()
}

// FormatArgs contains format and arguments for Printf functions.
type FormatArgs struct {
	Format string
	Args   []interface{}
}

// String implements fmt.Stringer.
func (fa FormatArgs) String() string {
	return fmt.Sprintf(fa.Format, fa.Args...)
}

// WriteTo implements io.WriterTo.
func (fa FormatArgs) WriteTo(w io.Writer) (int64, error) {
	n, err := fmt.Fprintf(w, fa.Format, fa.Args...)
	return int64(n), err
}

// WithPrinter returns the string rendered by Printer. Can be used to translate FormatArgs.
func (fa FormatArgs) WithPrinter(p *message.Printer) string {
	// fa.Args must be immutable.
	args := make([]interface{}, len(fa.Args))
	copy(args, fa.Args)

	var (
		f  FormatArgs
		ok bool
	)

	for i, arg := range args {
		if f, ok = arg.(FormatArgs); ok {
			args[i] = f.WithPrinter(p)
		}
	}

	return p.Sprintf(fa.Format, args...)
}
