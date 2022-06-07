/*
 * Copyright (c) 2022 Nutanix Inc. All rights reserved.
 *
 * Author: Shyamsunder Rathi - shyam.rathi@nutanix.com
 * MIT License
 */

// Package scrub implements a scrubbing utility to hide sensitive fields from a struct.
//
// This utility can be used to purge sensitive fields from a deeply nested struct
// at any level. This is useful for scenarios such as logging structures which may
// contain user passwords, secret keys, passphrases, etc.
//
// Notes & Caveates
//
// Only exported fields of a struct can be scrubbed (fields starting with a
// capital letter). Reflect package cannot modify unexported (private) fields.
// Also, The input struct must be passed by its address, otherwise the values
// of its fields cannot be changed.
//
// Example
//
//    type testScrub struct {
//    	 Username string
//    	 Password string
//    	 Codes    []string
//    }
//
//    T := &testScrub{
//       Username: "administrator",
//       Password: "my_secret_passphrase",
//       Codes:    []string{"pass1", "pass2", "pass3"},
//    }
//
//    emptyT := &testScrub{}
//
//    fieldsToScrub := map[string]map[string]string{
//       "password": make(map[string]string),
//       "codes": make(map[string]string),
//    }
//
//    func ScrubSetup() {
//       fieldsToScrub["password"]["symbol"] = "*"
//       fieldsToScrub["codes"]["symbol"] = "."
//       scrub.MaskLenVary = true
//    }
//
//    ScrubSetup()
//
//    out := scrub.Scrub(emptyT, T, fieldsToScrub, JSONScrub)
//    log.Println(out)
//    OUTPUT: {username:administrator Password:******************** Codes:[..... ..... .....]}
package scrub

import (
	"encoding/json"
	"encoding/xml"
	"reflect"
	"strings"
)

var (
	// DefaultToScrub contains default field names to scrub.
	// NOTE: these fields should be all lowercase. Comparison is case insensitive.
	DefaultToScrub = map[string]map[string]string{
		"password": make(map[string]string),
	}
	// MaskLenVary specifies mask length equals DefaultMaskLen or mask length equals to value length
	MaskLenVary    = false
	// DefaultMaskLen specifies default mask length
	DefaultMaskLen = 8
)

// DataType specifies supported formats
type DataType string

const (
	// XMLScrub - support of xml format
	XMLScrub  DataType = "xml"
	// JSONScrub - support of json format
	JSONScrub DataType = "json"
)

// Scrub scrubs all the specified string fields in the 'target' struct
// at any level recursively and returns a DataType formatted string of the scrubbed struct.
//
// A pointer to a new empty instance of the 'target' struct is needed
// to act as a 'cloning' of the 'target' to avoid race conditions
func Scrub(cloning interface{}, target interface{}, fieldsToScrub  map[string]map[string]string, dataType DataType) string {
	if invalidInput(cloning, target) {
		switch dataType {
		case JSONScrub:
			// Return json representation of 'nil' input
			return "null"
		case XMLScrub:
			// Return xml representation of 'nil' input
			return ""
		default:
			// Return json representation of 'nil' input
			return "null"
		}
	}

	// Clone target struct to avoid race conditions
	switch dataType {
	case JSONScrub:
		b, err := json.Marshal(target);

		if err != nil {
			return "null"
		}

		if err = json.Unmarshal(b, cloning); err != nil {
			return "null"
		}


	case XMLScrub:
		b, err := xml.MarshalIndent(target, "  ", "    ")

		if err != nil {
			return ""
		}

		if err = xml.Unmarshal(b, cloning); err != nil {
			return ""
		}

	default:
		return "null"
	}

	// Set default fields to scrub
	if fieldsToScrub == nil {
		fieldsToScrub = DefaultToScrub
		fieldsToScrub["password"]["symbol"] = "*"
	}

	// Call a recursive function to find and scrub fields in input at any level.
	scrubInternal(cloning, "", fieldsToScrub)

	// Get the marshalled string from the scrubb string and return the scrubbed string.
	switch dataType {
	case JSONScrub:
		b, err := json.Marshal(cloning)

		if err != nil {
			return "null"
		}

		return string(b)
	case XMLScrub:
		b, err := xml.MarshalIndent(cloning, "  ", "    ")

		if err != nil {
			return ""
		}

		return string(b)
	default:
		return ""
	}
}

// scrubInternal scrubs all the specified string fields in the 'target' struct
// at any level recursively and returns a DataType formatted string of the scrubbed struct.
//
// It loops over the given 'target' struct recursively, looking for 'string'
// field names specified in 'fieldsToScrub'. If found, it scrubs the value
// with the given symbol defined in 'fieldsToScrub'
// Depending on the MaskLenVary option scrub length can be fixed or vary.
//
// This is an internal API. It should not be used directly by any caller.
func scrubInternal(target interface{}, fieldName string, fieldsToScrub  map[string]map[string]string) {

	// if target is not pointer, then immediately return
	// modifying struct's field requires addressable object
	addrValue := reflect.ValueOf(target)
	if addrValue.Kind() != reflect.Ptr {
		return
	}

	targetValue := addrValue.Elem()
	if !targetValue.IsValid() {
		return
	}

	targetType := targetValue.Type()

	// If the field/struct is passed by pointer, then first dereference it to get the
	// underlying value (the pointer must not be pointing to a nil value).
	if targetType.Kind() == reflect.Ptr && !targetValue.IsNil() {
		targetValue = targetValue.Elem()
		if !targetValue.IsValid() {
			return
		}

		targetType = targetValue.Type()
	}

	if targetType.Kind() == reflect.Struct {
		// If target is a struct then recurse on each of its field.
		for i := 0; i < targetType.NumField(); i++ {
			fType := targetType.Field(i)
			fValue := targetValue.Field(i)
			if !fValue.IsValid() {
				continue
			}

			if !fValue.CanAddr() {
				// Cannot take pointer of this field, so can't scrub it.
				continue
			}

			if !fValue.Addr().CanInterface() {
				// This is an unexported or private field (begins with lowercase).
				// We can't take an interface on that or scrub it.
				// UnsafeAddr(), which is unsafe.Pointer, can be used to workaround it,
				// but that is not recommended in Golang.
				continue
			}

			scrubInternal(fValue.Addr().Interface(), fType.Name, fieldsToScrub)
		}
		return
	}

	if targetType.Kind() == reflect.Array || targetType.Kind() == reflect.Slice {
		// If target is an array/slice, then recurse on each of its element.
		for i := 0; i < targetValue.Len(); i++ {
			arrValue := targetValue.Index(i)
			if !arrValue.IsValid() {
				continue
			}

			if !arrValue.CanAddr() {
				// Cannot take pointer of this field, so can't scrub it.
				continue
			}

			if !arrValue.Addr().CanInterface() {
				// This is an unexported or private field (begins with lowercase).
				// We can't take an interface on that or scrub it.
				// UnsafeAddr(), which is unsafe.Pointer, can be used to workaround it,
				// but that is not recommended in Golang.
				continue
			}

			scrubInternal(arrValue.Addr().Interface(), fieldName, fieldsToScrub)
		}

		return
	}

	// If 'fieldName' is not set, then the API was not called on a struct.
	// Since it is not possible to find the variable name of a non-struct field,
	// we can't compare it with 'fieldsToScrub'.
	if fieldName == "" {
		return
	}

	if opts, ok := fieldsToScrub[strings.ToLower(fieldName)]; ok {
		// Scrub this string value. Other types are not scrubbed.
		if targetValue.CanSet() && targetValue.Kind() == reflect.String && !targetValue.IsZero() {
			var symbol string

			if v, ok := opts["symbol"]; ok {
				symbol = v
			} else {
				// Fallback to default symbol *
				symbol = "*"
			}

			var mask string
			if MaskLenVary {
				// Mask symbols' length equals to value length
				mask = strings.Repeat(symbol, targetValue.Len())
			} else {
				// Use default mask symbols' length
				mask = strings.Repeat(symbol, DefaultMaskLen)
			}

			targetValue.SetString(mask)
		}
	}
}

// Validate target pointers
func invalidInput(cloning interface{}, target interface{}) bool {
	return cloning == nil || target == nil || reflect.ValueOf(cloning).IsZero() || reflect.ValueOf(target).IsZero()
}
