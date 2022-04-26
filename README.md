[![Builds](https://github.com/ssrathi/go-scrub/workflows/Build/badge.svg?branch=master)](https://github.com/ssrathi/go-scrub/actions?query=branch%3Amaster+workflow%3ABuild)
[![Go Report Card](https://goreportcard.com/badge/github.com/ssrathi/go-scrub)](https://goreportcard.com/report/github.com/ssrathi/go-scrub)
[![GoDoc](https://godoc.org/github.com/ssrathi/go-scrub?status.svg)](https://godoc.org/github.com/ssrathi/go-scrub)

# go-scrub

A scrubbing utility in Golang to hide sensitive fields from a struct prior to logging.

Since the scrubbing utility function needs to work on any Golang struct where its fields and members are known only at runtime, we can leverage ["reflect"](https://pkg.go.dev/reflect), a powerful package from the Golang standard library, to scrub sensitive fields at any level of a deeply nested structure recursively.

Blog post with a detailed explanation: https://www.nutanix.dev/2022/04/22/golang-the-art-of-reflection/

## Installation
```
go install github.com/ssrathi/go-scrub@latest
```

## Usage
```go
  import "github.com/ssrathi/go-scrub"

  // Have a struct with some sensitive fields.
  type testScrub struct {
    Username string
    Password string
    Codes    []string
  }

  // Create a struct with some sensitive data.
  T := testScrub{
     Username: "administrator",
     Password: "my_secret_passphrase",
     Codes:    []string{"pass1", "pass2", "pass3"},
  }

  // Create a set of field names to scrub (default is 'password').
  fieldsToScrub := map[string]bool{
    "password": true,
    "codes": true,
  }

  // Call the util API to get a JSON formatted string with scrubbed field values.
  out := scrub.Scrub(&T, fieldsToScrub)

  // Log the scrubbed string without worrying about prying eyes!
  log.Println(out)
  OUTPUT: {"Username":"administrator","Password":"********","Codes":["********","********","********"]}
```

## Contributing

Contributions are most welcome! Please create a new issue and link your PR to it.
