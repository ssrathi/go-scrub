[![Builds](https://github.com/ssrathi/go-scrub/workflows/Build/badge.svg?branch=master)](https://github.com/ssrathi/go-scrub/actions?query=branch%3Amaster+workflow%3ABuild)
[![Go Report Card](https://goreportcard.com/badge/github.com/ssrathi/go-scrub)](https://goreportcard.com/report/github.com/ssrathi/go-scrub)
[![GoDoc](https://godoc.org/github.com/ssrathi/go-scrub?status.svg)](https://godoc.org/github.com/ssrathi/go-scrub)

# go-scrub

A scrubbing utility in Golang to hide sensitive fields from a struct prior to logging.

## Installation
```
go get github.com/ssrathi/go-scrub
```

## Usage
```
  T := testScrub{
     username: "administrator",
     Password: "my_secret_passphrase",
     Codes:    []string{"pass1", "pass2", "pass3"},
  }

  fieldsToScrub := map[string]bool{
    "password": true,
    "codes": true,
  }

  out := Scrub(&T, fieldsToScrub, "test-redact")
  log.Println(out)
  OUTPUT: {username:administrator Password:******** Codes:[******** ******** ********]}
```

## Contributing

Contributions are most welcome! Please create a new issue and link your PR to it.
