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
//    T := testScrub{
//       Username: "administrator",
//       Password: "my_secret_passphrase",
//       Codes:    []string{"pass1", "pass2", "pass3"},
//    }
//
//    fieldsToScrub := map[string]bool{"password": true, "codes": true}
//
//    out := Scrub(&T, fieldsToScrub)
//    log.Println(out)
//    OUTPUT: {username:administrator Password:******** Codes:[******** ******** ********]}
package scrub

import (
	"encoding/json"
	"reflect"
	"strings"
)

// DefaultToScrub contains default field names to scrub.
// NOTE: these fields should be all lowercase. Comparison is case insensitive.
var DefaultToScrub = map[string]bool{
	"password": true,
}

// Scrub scrubs all the specified string fields in the 'input' struct
// at any level recursively and returns a JSON-formatted string of the
// scrubbed struct.
func Scrub(input interface{}, fieldsToScrub map[string]bool) string {
	if input == nil {
		// Return json representation of 'nil' input
		return "null"
	}

	if fieldsToScrub == nil {
		fieldsToScrub = DefaultToScrub
	}

	// Call a recursive function to find and scrub fields in input at any level.
	savedValues := make([]string, 0)
	scrubInternal(input, "", fieldsToScrub, &savedValues, true /* mask */)

	// Get a JSON marshalled string from the scrubb string to return.
	var b []byte
	b, _ = json.Marshal(input)

	// Restore all the scrubbed values back to the original values in the struct.
	scrubInternal(input, "", fieldsToScrub, &savedValues, false /* unmask */)

	// Return the scrubbed string
	return string(b)
}

// scrubInternal scrubs all the specified string fields in the 'input' struct
// at any level recursively and returns a JSON formatted string of the scrubbed struct.
// It restores the struct back to the original values before returning.
//
// It loops over the given 'target' struct recursively, looking for 'string'
// field names specified in 'fieldsToScrub'. If found, it saves the value in
// 'savedValues' and scrubs the value with '********'.
// If 'mask' is set to false, then it reverses the operation by replacing all masked
// fields with the original value saved in 'savedValues'.
//
// A typical usage is to call this API with an empty 'savedValues' with 'mask' as true to
// scrub all sensitive values in the struct. Afterwards, call it back with the filled
// 'savedValues' with 'mask' as false to restore the original struct.
//
// NOTE: 'savedValues' must be preserved by the caller to restore the original struct
// and must not be modified.
//
// This is an internal API. It should not be used directly by any caller.
func scrubInternal(target interface{}, fieldName string, fieldsToScrub map[string]bool,
	savedValues *[]string, mask bool) {

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

			scrubInternal(fValue.Addr().Interface(), fType.Name, fieldsToScrub,
				savedValues, mask)
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

			scrubInternal(arrValue.Addr().Interface(), fieldName, fieldsToScrub,
				savedValues, mask)
		}

		return
	}

	// If 'fieldName' is not set, then the API was not called on a struct.
	// Since it is not possible to find the variable name of a non-struct field,
	// we can't compare it with 'fieldsToScrub'.
	if fieldName == "" {
		return
	}

	if _, ok := fieldsToScrub[strings.ToLower(fieldName)]; ok {
		// Scrub this string value. Other types are not scrubbed.
		if targetValue.CanSet() && targetValue.Kind() == reflect.String && !targetValue.IsZero() {
			if mask {
				// Save the value, so that it can be restored later.
				*savedValues = append(*savedValues, targetValue.String())
				targetValue.SetString("********")
			} else {
				// Restore from the saved value.
				targetValue.SetString((*savedValues)[0])
				*savedValues = (*savedValues)[1:]
			}
		}
	}
}
