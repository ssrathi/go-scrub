[![Builds](https://github.com/grandeto/go-scrub/workflows/Build/badge.svg?branch=master)](https://github.com/grandeto/go-scrub/actions?query=branch%3Amaster+workflow%3ABuild)
[![Go Report Card](https://goreportcard.com/badge/github.com/grandeto/go-scrub)](https://goreportcard.com/report/github.com/grandeto/go-scrub)
[![GoDoc](https://godoc.org/github.com/grandeto/go-scrub?status.svg)](https://godoc.org/github.com/grandeto/go-scrub)

# go-scrub

A scrubbing utility in Golang to mask sensitive fields from a struct prior to logging.

Since the scrubbing utility function needs to work on any Golang struct where its fields and members are known only at runtime, we can leverage ["reflect"](https://pkg.go.dev/reflect), a powerful package from the Golang standard library, to scrub sensitive fields at any level of a deeply nested structure recursively.

## Installation
```
go get github.com/grandeto/go-scrub@latest
```

## Usage
```go
import "github.com/grandeto/go-scrub"

// Have a struct with some sensitive fields.
type testScrub struct {
    Username string
    Password string
    Codes    []string
}

type fieldScrubOpts struct {
    maskingSymbol string
    partScrubConf *PartScrubConf
}

func newFieldScrubOpts(
    maskingSymbol string,
    partScrubConf *PartScrubConf,
) *fieldScrubOpts {
    return &fieldScrubOpts{
        maskingSymbol,
        partScrubConf,
    }
}

func (f *fieldScrubOpts) GetMaskingSymbol() string {
    return f.maskingSymbol
}

func (f *fieldScrubOpts) PartMaskEnabled() bool {
    if f.partScrubConf == nil {
        return false
    }

    return f.partScrubConf.PartMaskEnabled
}

func (f *fieldScrubOpts) PartMaskMinFldLen() int {
    if f.partScrubConf == nil {
        return 0
    }

    return f.partScrubConf.PartMaskMinFldLen
}

func (f *fieldScrubOpts) PartMaskMaxFldLen() int {
    if f.partScrubConf == nil {
        return 0
    }

    return f.partScrubConf.PartMaskMaxFldLen
}

func (f *fieldScrubOpts) PartMaskVisibleFrontLen() int {
    if f.partScrubConf == nil {
        return 0
    }

    return f.partScrubConf.VisibleFrontLen
}

func (f *fieldScrubOpts) PartMaskVisibleBackOnlyIfFldLenGreaterThan() int {
    if f.partScrubConf == nil {
        return 0
    }

    return f.partScrubConf.VisibleBackOnlyIfFldLenGreaterThan
}

func (f *fieldScrubOpts) PartMaskVisibleBackLen() int {
    if f.partScrubConf == nil {
        return 0
    }

    return f.partScrubConf.VisibleBackLen
}

// Create a struct with some sensitive data.
T := &testScrub{
    Username: "administrator",
    Password: "my_secret_passphrase",
    Codes:    []string{"pass1", "pass2", "pass3"},
}

// Create empty instance of testScrub
emptyT := &testScrub{}

// Create a set of field names to scrub (default is 'password').
fieldsToScrub := map[string]FieldScrubOptioner{
    "password":  newFieldScrubOpts("*", nil),
    "codes":      newFieldScrubOpts(".", nil),
}

scrub.MaskLenVary = true

// Call the util API to get a JSON formatted string with scrubbed field values.
out := scrub.Scrub(emptyT, T, fieldsToScrub, scrub.JSONScrub)

// Log the scrubbed string without worrying about prying eyes!
log.Println(out)
// OUTPUT: {username:administrator Password:******************** Codes:[..... ..... .....]}
```

- NOTE: Please reffer to `scrub_test.go` for all supported scenarios

## Contributing

Contributions are most welcome! Please create a new issue and link your PR to it.
