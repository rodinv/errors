# Package errors

This package contains the capabilities of two packages for error handling:
https://github.com/uber-go/multierr and https://github.com/pkg/errors, and expands the ability to set
additional error fields and localize the text of errors in any language.

## Adding context to errors using wrapping

Adding context to errors is important to improve the readability of errors.

You should strive to handle errors received from external services, adding a context for why you accessed this service
when you received the error.

Using the errors.Errorf interface is easy to get wrong and not wrap the error:

```go
func ReadConfig(path string) error{
    file, err := os.Open(path)
    if err != nil {
    	return errors.Errorf("opening config file: %v", err) // Oops, the error is not wrapped. 
    }
}
```

Use `errors.Wrap` and `errors.Wrapf` instead:

```go
func ReadConfig(path string) error{
    file, err := os.Open(path)
    if err != nil {
    	return errors.Wrap(err, "opening config file")
    }
}
```

## Comparison of errors

Comparing errors, like comparing any other interfaces, is not always safe. For example, when the implementation type of
both interfaces cannot be compared, then panic will occur (`[]error{} == []error{}` for example).

In addition, comparing errors leads to a false negative result if the error is wrapped or combined with another error.

```go
func GetUser(id int64) (interface{}, error)
    q := `select * from users where id = $1`
	_, err = sqlx.Get(q, disclosureID)
	// Will work correctly.
	if err == sql.ErrNoRows {
		return errors.Errorf(
			"user %d doesn't exist",
			id,
		)
	}
}
```

If later, part of the code has to be replaced with a call to another function that wraps the error inside, then the
code will stop working.

```go
func GetUser(id int64) (interface{}, error)
    q := `select * from users where id = $1`
    _, err = dbutils.Get(q, disclosureID)
    // Oops, doesn't work.
    if err == sql.ErrNoRows {
        return errors.Errorf(
        	"user %d doesn't exist",
        	id,
        )
    }
}
```

**Always use `errors.Is` to compare two errors**

```go
func GetUser(id int64) (interface{}, error)
    q := `select * from users where id = $1`
    _, err = dbutils.Get(q, disclosureID)
    // Will always work.
    if errors.Is(err, sql.ErrNoRows) {
        return errors.Errorf(
        	"user %d doesn't exist",
        	id,
        )
    }
}
```

## The same goes for casting the error to the implementation type

Avoid converting the interface, because if the error is wrapped, the conversion will fail.

```go
if myErr, ok := err.(*MyErr); ok {
	// using the implementation
}
```

**Always use `errors.As` to converting the error**

```go
var myErr *MyErr
if errors.As(err, &myErr) {
	// using the implementation
}
```

## Combining multiple errors into one

You should always handle all errors, even if an error is received to exit the function. For these purposes, it is
suitable to combine errors into one using one of the more suitable functions.

### Usage `errors.Append`
```go
tx, err := db.BeginTx(ctx, nil)
if err != nil{
	return err
}

_, err = tx.Exec(query)
if err != nil {
    return errors.Append(err, tx.Rollback())
}

return tx.Commit()
```

### Usage `errors.AppendInto`

```go
tx, err := db.BeginTx(ctx, nil)
if err != nil{
	return err
}

defer func() {
    if err != nil{
        errors.AppendInto(&err, tx.Rollback())
        return
    }
    
    errors.AppendInto(&err, tx.Commit())
}()

_, err = tx.Exec(query)
if err != nil {
    return err
}
```

### Usage `errors.CloseAndAppendInto`

```go
rows, err := tx.Query(query)
if err != nil {
	return err
}

defer errors.CloseAndAppendInto(&err, rows)
```

## Translation of errors into another language

```go
tag := language.Russian

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

err := errors.Errorf("unexpected number of arguments, expected %d", 1)

var target *errors.Error
if errors.As(err, &target) {
    s := target.WithPrinter(printer)
    fmt.Println(s) // неожиданное количество аргументов, ожидался 1
}

err = errors.Errorf("unexpected number of arguments, expected %d", 2)
if errors.As(err, &target) {
	s = target.WithPrinter(printer)
	fmt.Println(s) // неожиданное количество аргументов, ожидалось 2
}

_ = message.Set(tag, "reading config %q", catalog.String("чтение конфига %[1]q"))
_ = message.Set(tag, "module initialization", catalog.String("инициализация модуля"))
	
err = errors.Combine(
	errors.Wrapf(
		io.EOF,
		"reading config %q",
		"path/to/config.json",
	),
	errors.Wrap(io.EOF, "module initialization"),
)

if errors.As(err, &target) {
    s = target.WithPrinter(printer)
    fmt.Println(s) // чтение конфига "path/to/config.json": EOF; инициализация модуля: EOF
}
```