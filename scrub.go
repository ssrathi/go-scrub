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
// Example:
//
//		import "github.com/grandeto/go-scrub"
//
//		// Have a struct with some sensitive fields.
//		type testScrub struct {
//			Username string
//			Password string
//			Codes    []string
//		}
//
//		type fieldScrubOpts struct {
//			maskingSymbol string
//			partScrubConf *PartScrubConf
//		}
//
//		func newFieldScrubOpts(
//			maskingSymbol string,
//			partScrubConf *PartScrubConf,
//		) *fieldScrubOpts {
//			return &fieldScrubOpts{
//				maskingSymbol,
//				partScrubConf,
//			}
//		}
//
//		func (f *fieldScrubOpts) GetMaskingSymbol() string {
//			return f.maskingSymbol
//		}
//
//		func (f *fieldScrubOpts) PartMaskEnabled() bool {
//			if f.partScrubConf == nil {
//				return false
//			}
//
//			return f.partScrubConf.PartMaskEnabled
//		}
//
//		func (f *fieldScrubOpts) PartMaskMinFldLen() int {
//			if f.partScrubConf == nil {
//				return 0
//			}
//
//			return f.partScrubConf.PartMaskMinFldLen
//		}
//
//		func (f *fieldScrubOpts) PartMaskMaxFldLen() int {
//			if f.partScrubConf == nil {
//				return 0
//			}
//
//			return f.partScrubConf.PartMaskMaxFldLen
//		}
//
//		func (f *fieldScrubOpts) PartMaskVisibleFrontLen() int {
//			if f.partScrubConf == nil {
//				return 0
//			}
//
//			return f.partScrubConf.VisibleFrontLen
//		}
//
//		func (f *fieldScrubOpts) PartMaskVisibleBackOnlyIfFldLenGreaterThan() int {
//			if f.partScrubConf == nil {
//				return 0
//			}
//
//			return f.partScrubConf.VisibleBackOnlyIfFldLenGreaterThan
//		}
//
//		func (f *fieldScrubOpts) PartMaskVisibleBackLen() int {
//			if f.partScrubConf == nil {
//				return 0
//			}
//
//			return f.partScrubConf.VisibleBackLen
//		}
//
//		// Create a struct with some sensitive data.
//		T := &testScrub{
//			Username: "administrator",
//			Password: "my_secret_passphrase",
//			Codes:    []string{"pass1", "pass2", "pass3"},
//		}
//
//		// Create empty instance of testScrub
//		emptyT := &testScrub{}
//
//		// Create a set of field names to scrub (default is 'password').
//		fieldsToScrub := map[string]FieldScrubOptioner{
//			"password":  newFieldScrubOpts("*", nil),
//			"codes":      newFieldScrubOpts(".", nil),
//		}
//
//		scrub.MaskLenVary = true
//
//		// Call the util API to get a JSON formatted string with scrubbed field values.
//		out := scrub.Scrub(emptyT, T, fieldsToScrub, scrub.JSONScrub)
//
//		// Log the scrubbed string without worrying about prying eyes!
//		log.Println(out)
//		// OUTPUT: {username:administrator Password:******************** Codes:[..... ..... .....]}
//
//		// NOTE: Please reffer to `scrub_test.go` for all supported scenarios
package scrub

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"reflect"
	"strings"
)

// DataType specifies supported formats
type DataType string

const (
	// XMLScrub - support of xml format
	XMLScrub DataType = "xml"
	// JSONScrub - support of json format
	JSONScrub DataType = "json"
	// defaultMaskLen specifies default mask length
	defaultMaskLen int = 8
	// defaultMaskSymbol specifies default mask symbol
	defaultMaskSymbol string = "*"
)

var (
	// defaultToScrub contains default field names to scrub.
	// NOTE: these fields should be all lowercase. Comparison is case insensitive.
	defaultToScrub map[string]FieldScrubOptioner = map[string]FieldScrubOptioner{
		"password": &defaultFieldScrubOpts{},
	}
	// MaskLenVary specifies mask length equals DefaultMaskLen or mask length equals to value length
	MaskLenVary bool = false
)

// FieldScrubOptioner provides an interface for custom masking field options
type FieldScrubOptioner interface {
	GetMaskingSymbol() string
	PartMaskEnabled() bool
	PartMaskMinFldLen() int
	PartMaskMaxFldLen() int
	PartMaskVisibleFrontLen() int
	PartMaskVisibleBackOnlyIfFldLenGreaterThan() int
	PartMaskVisibleBackLen() int
}

type defaultFieldScrubOpts struct{}

func (dfo *defaultFieldScrubOpts) GetMaskingSymbol() string {
	return defaultMaskSymbol
}

func (dfo *defaultFieldScrubOpts) PartMaskEnabled() bool {
	return false
}

func (dfo *defaultFieldScrubOpts) PartMaskMinFldLen() int {
	return 0
}

func (dfo *defaultFieldScrubOpts) PartMaskMaxFldLen() int {
	return 0
}

func (dfo *defaultFieldScrubOpts) PartMaskVisibleFrontLen() int {
	return 0
}

func (dfo *defaultFieldScrubOpts) PartMaskVisibleBackOnlyIfFldLenGreaterThan() int {
	return 0
}

func (dfo *defaultFieldScrubOpts) PartMaskVisibleBackLen() int {
	return 0
}

// PartScrubConf provides options for partitial field masking
type PartScrubConf struct {
	PartMaskEnabled                    bool
	PartMaskMinFldLen                  int
	PartMaskMaxFldLen                  int
	VisibleFrontLen                    int
	VisibleBackOnlyIfFldLenGreaterThan int
	VisibleBackLen                     int
}

// NewPartScrubConf is PartScrubConf constructor
func NewPartScrubConf(
	partMaskEnabled bool,
	partMaskMinFldLen int,
	partMaskMaxFldLen int,
	visibleFrontLen int,
	visibleBackOnlyIfFldLenGreaterThan int,
	visibleBackLen int,
) *PartScrubConf {
	return &PartScrubConf{
		partMaskEnabled,
		partMaskMinFldLen,
		partMaskMaxFldLen,
		visibleFrontLen,
		visibleBackOnlyIfFldLenGreaterThan,
		visibleBackLen,
	}
}

// Scrub scrubs all the specified string fields in the 'target' struct
// at any level recursively and returns a DataType formatted string of the scrubbed struct.
//
// A pointer to a new empty instance of the 'target' struct is needed
// to act as a 'cloning' of the 'target' to avoid race conditions
func Scrub(cloning interface{}, target interface{}, fieldsToScrub map[string]FieldScrubOptioner, dataType DataType) string {
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
		b, err := json.Marshal(target)

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
		fieldsToScrub = defaultToScrub
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

// scrubInternal scrubs all the specified string fields and map fields of type map[string]interface{}
// in the 'target' struct at any level recursively and returns a DataType formatted string of the
// scrubbed struct.
//
// It loops over the given 'target' struct recursively, looking for 'string'
// field names and keys in maps of type map[string]interface{} specified in 'fieldsToScrub'.
// If found, it scrubs the value with the given symbol defined in 'fieldsToScrub'
// Depending on the MaskLenVary option scrub length can be fixed or vary.
//
// This is an internal API. It should not be used directly by any caller.
func scrubInternal(target interface{}, fieldName string, fieldsToScrub map[string]FieldScrubOptioner) {

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

	if targetType.Kind() == reflect.Map {
		// If target is a map, then recurse on each of its keys.
		scrubInternalMap(targetValue, fieldsToScrub)

		return
	}

	// If 'fieldName' is not set, then the API was not called on a struct.
	// Since it is not possible to find the variable name of a non-struct field,
	// we can't compare it with 'fieldsToScrub'.
	if fieldName == "" {
		return
	}

	if mask, ok := doMasking(targetValue, fieldName, fieldsToScrub, true); ok {
		targetValue.SetString(mask)
	}
}

// scrubInternalMap iterate recursively over maps and scrubs the value with the given symbol
// defined in 'fieldsToScrub'
// NOTE: Currently only string values in maps of type map[string]interface{} are scrubbed
func scrubInternalMap(targetMap reflect.Value, fieldsToScrub map[string]FieldScrubOptioner) reflect.Value {
	for _, k := range targetMap.MapKeys() {
		v := targetMap.MapIndex(k)

		if v.Type().Kind() != reflect.Interface {
			continue
		}

		if v.Elem().Kind() == reflect.String {
			if mask, ok := doMasking(v.Elem(), k.String(), fieldsToScrub, false); ok {
				targetMap.SetMapIndex(reflect.ValueOf(k.String()), reflect.ValueOf(mask))
			}
		}

		if v.Elem().Kind() == reflect.Array || v.Elem().Kind() == reflect.Slice {
			for i := 0; i < v.Elem().Len(); i++ {
				arrValue := v.Elem().Index(i)

				if arrValue.Elem().Kind() == reflect.Map {
					scrubInternalMap(arrValue.Elem(), fieldsToScrub)
				}
			}
		}
	}

	return targetMap
}

// doMasking does the real masking of the string values
func doMasking(targetValue reflect.Value, fieldName string, fieldsToScrub map[string]FieldScrubOptioner, checkCanSet bool) (string, bool) {
	if opts, ok := fieldsToScrub[strings.ToLower(fieldName)]; ok {

		// Check if value can be changed depending of the use case
		if checkCanSet && !targetValue.CanSet() {
			return "", false
		}

		// Scrub this string value. Other types are not scrubbed.
		if targetValue.Kind() == reflect.String && !targetValue.IsZero() {
			var symbol string

			if opts != nil && len(opts.GetMaskingSymbol()) == 1 {
				symbol = opts.GetMaskingSymbol()
			} else {
				// Fallback to default symbol *
				symbol = defaultMaskSymbol
			}

			if opts != nil && opts.PartMaskEnabled() {
				switch {
				case targetValue.Len() < opts.PartMaskMinFldLen():
					return applyFullMask(symbol, maskLen(targetValue.Len())), ok
				case targetValue.Len() > opts.PartMaskMaxFldLen():
					return applyFullMask(symbol, maskLen(targetValue.Len())), ok
				case targetValue.Len() < opts.PartMaskVisibleBackOnlyIfFldLenGreaterThan():
					return applyPartBackMask(targetValue.String(), symbol, opts.PartMaskVisibleFrontLen()), ok
				case targetValue.Len() <= opts.PartMaskMaxFldLen():
					return applyPartMiddleMask(targetValue.String(), symbol, opts.PartMaskVisibleFrontLen(), opts.PartMaskVisibleBackLen()), ok
				}
			}

			return applyFullMask(symbol, maskLen(targetValue.Len())), ok
		}
	}

	return "", false
}

func maskLen(targetValueLen int) int {
	if MaskLenVary {
		return targetValueLen
	}

	return defaultMaskLen
}

func applyPartBackMask(value string, symbol string, visibleFrontLen int) string {
	visibleFront := value[0:visibleFrontLen]
	maskedBack := strings.Repeat(symbol, len(value)-visibleFrontLen)

	return fmt.Sprintf("%s%s", visibleFront, maskedBack)
}

func applyPartMiddleMask(value string, symbol string, visibleFrontLen int, visibleBackLen int) string {
	visibleFront := value[0:visibleFrontLen]
	visibleBack := value[len(value)-visibleBackLen:]
	maskedMiddle := strings.Repeat(symbol, (len(value)-visibleFrontLen)-visibleBackLen)

	return fmt.Sprintf("%s%s%s", visibleFront, maskedMiddle, visibleBack)
}

func applyFullMask(symbol string, maskLen int) string {
	return strings.Repeat(symbol, maskLen)
}

// Validate target pointers
func invalidInput(cloning interface{}, target interface{}) bool {
	return cloning == nil || target == nil || reflect.ValueOf(cloning).IsZero() || reflect.ValueOf(target).IsZero()
}
