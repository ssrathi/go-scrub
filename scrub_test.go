package scrub

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Structure definitions to test scrubbing functionalities.
// Simple struct
type User struct {
	Username           string
	Password           string
	DbSecrets          []string
	MapData            map[string]interface{}
	UnsupportedMapData map[string]string
}

// Nested struct
type Users struct {
	Secret   string
	Keys     []string
	UserInfo []User
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

// Tests scrubbing on a simple struct with default options.
func TestScrubSimpleFixedLen(t *testing.T) {
	MaskLenVary = false

	user := &User{
		Username:  "Shyam Rathi",
		Password:  "nutanix/4u",
		DbSecrets: []string{"db_secret_1", "db_secret_2"},
	}

	empty := &User{}

	userScrubbed := &User{
		Username:  "Shyam Rathi",
		Password:  "********",
		DbSecrets: []string{"db_secret_1", "db_secret_2"},
	}

	validateScrub(t, empty, user, userScrubbed, nil, JSONScrub)
	validateScrub(t, empty, user, userScrubbed, nil, XMLScrub)
}

// Tests scrubbing on a simple struct with default options and varying mask length.
func TestScrubSimpleVaryLen(t *testing.T) {
	MaskLenVary = true

	user := &User{
		Username:  "Shyam Rathi",
		Password:  "nutanix/4u",
		DbSecrets: []string{"db_secret_1", "db_secret_2"},
	}

	empty := &User{}

	userScrubbed := &User{
		Username:  "Shyam Rathi",
		Password:  strings.Repeat("*", len(user.Password)),
		DbSecrets: []string{"db_secret_1", "db_secret_2"},
	}

	validateScrub(t, empty, user, userScrubbed, nil, JSONScrub)
	validateScrub(t, empty, user, userScrubbed, nil, XMLScrub)
}

// Tests scrubbing on a simple struct with default options and varying mask length and partial masking of a given field.
func TestScrubSimplePartialMask(t *testing.T) {
	MaskLenVary = true

	target := "1234567891111111111"
	targetMasked := "123456*********1111"

	// Middle mask

	user := &User{
		Username:  target,
		Password:  "nutanix/4u",
		DbSecrets: []string{"db_secret_1", "db_secret_2"},
	}

	empty := &User{}

	userScrubbed := &User{
		Username:  targetMasked,
		Password:  strings.Repeat("*", len(user.Password)),
		DbSecrets: []string{strings.Repeat("*", len(user.DbSecrets[0])), strings.Repeat("*", len(user.DbSecrets[1]))},
	}

	secretFields := map[string]FieldScrubOptioner{
		"username":  newFieldScrubOpts("*", NewPartScrubConf(true, 10, 19, 6, 16, 4)),
		"password":  nil,
		"keys":      nil,
		"secret":    nil,
		"dbsecrets": nil,
	}

	validateScrub(t, empty, user, userScrubbed, secretFields, JSONScrub)
	validateScrub(t, empty, user, userScrubbed, secretFields, XMLScrub)

	// Backend mask

	target = "123456789111111"
	targetMasked = "123456*********"

	user.Username = target

	empty = &User{}

	userScrubbed.Username = targetMasked

	validateScrub(t, empty, user, userScrubbed, secretFields, JSONScrub)
	validateScrub(t, empty, user, userScrubbed, secretFields, XMLScrub)

	// Lower than min len mask

	target = "123456789"
	targetMasked = strings.Repeat("*", len(target))

	user.Username = target

	empty = &User{}

	userScrubbed.Username = targetMasked

	validateScrub(t, empty, user, userScrubbed, secretFields, JSONScrub)
	validateScrub(t, empty, user, userScrubbed, secretFields, XMLScrub)

	// Greater than max len mask

	target = "12345678911111111110"
	targetMasked = strings.Repeat("*", len(target))

	user.Username = target

	empty = &User{}

	userScrubbed.Username = targetMasked

	validateScrub(t, empty, user, userScrubbed, secretFields, JSONScrub)
	validateScrub(t, empty, user, userScrubbed, secretFields, XMLScrub)
}

// Tests scrubbing on a nested complex struct with specific sensitive fields.
func TestScrubNestedFixedLen(t *testing.T) {
	MaskLenVary = false

	users := &Users{
		Secret: "secret_sshhh",
		Keys:   []string{"key_1", "key_2", "key_3"},
		UserInfo: []User{
			{
				Username:  "John Doe",
				Password:  "John_Doe's_Password",
				DbSecrets: []string{"John's_db_secret_1", "John's_db_secret_2"},
			},
			{
				Username:  "Jane Doe",
				Password:  "Jane_Doe's_Password",
				DbSecrets: []string{"Jane's_db_secret_1", "Jane's_db_secret_2"},
			},
		},
	}

	empty := &Users{}

	userScrubbed := &Users{
		Secret: "********",
		Keys:   []string{"........", "........", "........"},
		UserInfo: []User{
			{
				Username:  "John Doe",
				Password:  "********",
				DbSecrets: []string{"********", "********"},
			},
			{
				Username:  "Jane Doe",
				Password:  "********",
				DbSecrets: []string{"********", "********"},
			},
		},
	}

	secretFields := map[string]FieldScrubOptioner{
		"password":  nil,
		"keys":      newFieldScrubOpts(".", nil),
		"secret":    nil,
		"dbsecrets": nil,
	}

	validateScrub(t, empty, users, userScrubbed, secretFields, JSONScrub)
	validateScrub(t, empty, users, userScrubbed, secretFields, XMLScrub)
}

// Tests scrubbing on a nested complex struct with specific sensitive fields.
func TestScrubNestedVaryLen(t *testing.T) {
	MaskLenVary = true

	users := &Users{
		Secret: "secret_sshhh",
		Keys:   []string{"key_1", "key_2", "key_3"},
		UserInfo: []User{
			{
				Username:  "John Doe",
				Password:  "John_Doe's_Password",
				DbSecrets: []string{"John's_db_secret_1", "John's_db_secret_2"},
			},
			{
				Username:  "Jane Doe",
				Password:  "Jane_Doe's_Password",
				DbSecrets: []string{"Jane's_db_secret_1", "Jane's_db_secret_2"},
			},
		},
	}

	empty := &Users{}

	userScrubbed := &Users{
		Secret: "************",
		Keys:   []string{".....", ".....", "....."},
		UserInfo: []User{
			{
				Username:  "John Doe",
				Password:  "*******************",
				DbSecrets: []string{"******************", "******************"},
			},
			{
				Username:  "Jane Doe",
				Password:  "*******************",
				DbSecrets: []string{"******************", "******************"},
			},
		},
	}

	secretFields := map[string]FieldScrubOptioner{
		"password":  nil,
		"keys":      newFieldScrubOpts(".", nil),
		"secret":    nil,
		"dbsecrets": nil,
	}

	validateScrub(t, empty, users, userScrubbed, secretFields, JSONScrub)
	validateScrub(t, empty, users, userScrubbed, secretFields, XMLScrub)
}

// Tests scrubbing on a nested complex struct with specified sensitive fields and partial masking of a given field.
func TestScrubNestedPartialMask(t *testing.T) {
	MaskLenVary = true

	secretFields := map[string]FieldScrubOptioner{
		"password":  nil,
		"keys":      newFieldScrubOpts(".", NewPartScrubConf(true, 10, 19, 6, 16, 4)),
		"secret":    nil,
		"dbsecrets": newFieldScrubOpts("*", NewPartScrubConf(true, 10, 19, 6, 16, 4)),
	}

	target := "1234567891111111111"
	targetMasked := "123456*********1111"
	targetMasked2 := "123456.........1111"

	// Middle mask

	users := &Users{
		Secret: "secret_sshhh",
		Keys:   []string{target, target, target},
		UserInfo: []User{
			{
				Username:  "John Doe",
				Password:  "John_Doe's_Password",
				DbSecrets: []string{target, target},
			},
			{
				Username:  "Jane Doe",
				Password:  "Jane_Doe's_Password",
				DbSecrets: []string{target, target},
			},
		},
	}

	empty := &Users{}

	userScrubbed := &Users{
		Secret: strings.Repeat("*", len(users.Secret)),
		Keys:   []string{targetMasked2, targetMasked2, targetMasked2},
		UserInfo: []User{
			{
				Username:  "John Doe",
				Password:  strings.Repeat("*", len(users.UserInfo[0].Password)),
				DbSecrets: []string{targetMasked, targetMasked},
			},
			{
				Username:  "Jane Doe",
				Password:  strings.Repeat("*", len(users.UserInfo[1].Password)),
				DbSecrets: []string{targetMasked, targetMasked},
			},
		},
	}

	validateScrub(t, empty, users, userScrubbed, secretFields, JSONScrub)
	validateScrub(t, empty, users, userScrubbed, secretFields, XMLScrub)

	// Backend mask

	target = "123456789111111"
	targetMasked = "123456*********"
	targetMasked2 = "123456........."

	users.Keys = []string{target, target, target}
	users.UserInfo[0].DbSecrets = []string{target, target}
	users.UserInfo[1].DbSecrets = []string{target, target}

	empty = &Users{}

	userScrubbed.Keys = []string{targetMasked2, targetMasked2, targetMasked2}
	userScrubbed.UserInfo[0].DbSecrets = []string{targetMasked, targetMasked}
	userScrubbed.UserInfo[1].DbSecrets = []string{targetMasked, targetMasked}

	validateScrub(t, empty, users, userScrubbed, secretFields, JSONScrub)
	validateScrub(t, empty, users, userScrubbed, secretFields, XMLScrub)

	// Lower than min len mask

	target = "123456789"
	targetMasked = strings.Repeat("*", len(target))
	targetMasked2 = strings.Repeat(".", len(target))

	users.Keys = []string{target, target, target}
	users.UserInfo[0].DbSecrets = []string{target, target}
	users.UserInfo[1].DbSecrets = []string{target, target}

	empty = &Users{}

	userScrubbed.Keys = []string{targetMasked2, targetMasked2, targetMasked2}
	userScrubbed.UserInfo[0].DbSecrets = []string{targetMasked, targetMasked}
	userScrubbed.UserInfo[1].DbSecrets = []string{targetMasked, targetMasked}

	validateScrub(t, empty, users, userScrubbed, secretFields, JSONScrub)
	validateScrub(t, empty, users, userScrubbed, secretFields, XMLScrub)

	// Greater than max len mask

	target = "12345678911111111110"
	targetMasked = strings.Repeat("*", len(target))
	targetMasked2 = strings.Repeat(".", len(target))

	users.Keys = []string{target, target, target}
	users.UserInfo[0].DbSecrets = []string{target, target}
	users.UserInfo[1].DbSecrets = []string{target, target}

	empty = &Users{}

	userScrubbed.Keys = []string{targetMasked2, targetMasked2, targetMasked2}
	userScrubbed.UserInfo[0].DbSecrets = []string{targetMasked, targetMasked}
	userScrubbed.UserInfo[1].DbSecrets = []string{targetMasked, targetMasked}

	validateScrub(t, empty, users, userScrubbed, secretFields, JSONScrub)
	validateScrub(t, empty, users, userScrubbed, secretFields, XMLScrub)
}

// Tests scrubbing on a nested complex struct with specific sensitive fields and map[string]interface{} support.
func TestScrubNestedMapSupportFixedLen(t *testing.T) {
	MaskLenVary = false

	users := &Users{
		Secret: "secret_sshhh",
		Keys:   []string{"key_1", "key_2", "key_3"},
		UserInfo: []User{
			{
				Username:  "John Doe",
				Password:  "John_Doe's_Password",
				DbSecrets: []string{"John's_db_secret_1", "John's_db_secret_2"},
				MapData: map[string]interface{}{
					"72": []map[string]interface{}{
						{"86": "84240002107004C1119054885C52A2555576F148AA"},
						{"86": "84240000083AB8700FAE0CB0DD"},
						{"77": "84240000083AB8700FAE0CB0DD"},
					},
					"91": "CA3D8B21F20B5CEB0012",
				},
				UnsupportedMapData: map[string]string{
					"91": "CA3D8B21F20B5CEB0012",
				},
			},
			{
				Username:  "Jane Doe",
				Password:  "Jane_Doe's_Password",
				DbSecrets: []string{"Jane's_db_secret_1", "Jane's_db_secret_2"},
				MapData: map[string]interface{}{
					"72": []map[string]interface{}{
						{"86": "84240002107004C1119054885C52A2555576F148AA"},
						{"86": "84240000083AB8700FAE0CB0DD"},
						{"77": "84240000083AB8700FAE0CB0DD"},
					},
					"91": "CA3D8B21F20B5CEB0012",
				},
				UnsupportedMapData: map[string]string{
					"91": "CA3D8B21F20B5CEB0012",
				},
			},
		},
	}

	empty := &Users{}

	userScrubbed := &Users{
		Secret: "********",
		Keys:   []string{"........", "........", "........"},
		UserInfo: []User{
			{
				Username:  "John Doe",
				Password:  "********",
				DbSecrets: []string{"********", "********"},
				MapData: map[string]interface{}{
					"72": []map[string]interface{}{
						{"86": "********"},
						{"86": "********"},
						{"77": "84240000083AB8700FAE0CB0DD"},
					},
					"91": "********",
				},
				UnsupportedMapData: map[string]string{
					"91": "CA3D8B21F20B5CEB0012",
				},
			},
			{
				Username:  "Jane Doe",
				Password:  "********",
				DbSecrets: []string{"********", "********"},
				MapData: map[string]interface{}{
					"72": []map[string]interface{}{
						{"86": "********"},
						{"86": "********"},
						{"77": "84240000083AB8700FAE0CB0DD"},
					},
					"91": "********",
				},
				UnsupportedMapData: map[string]string{
					"91": "CA3D8B21F20B5CEB0012",
				},
			},
		},
	}

	secretFields := map[string]FieldScrubOptioner{
		"password":  nil,
		"keys":      newFieldScrubOpts(".", nil),
		"secret":    nil,
		"dbsecrets": nil,
		"91":        nil,
		"86":        nil,
	}

	validateScrub(t, empty, users, userScrubbed, secretFields, JSONScrub)
	validateScrub(t, empty, users, userScrubbed, secretFields, XMLScrub)
}

// Tests scrubbing on a nested complex struct with specific sensitive fields and map[string]interface{} support.
func TestScrubNestedMapSupportVaryLen(t *testing.T) {
	MaskLenVary = true

	users := &Users{
		Secret: "secret_sshhh",
		Keys:   []string{"key_1", "key_2", "key_3"},
		UserInfo: []User{
			{
				Username:  "John Doe",
				Password:  "John_Doe's_Password",
				DbSecrets: []string{"John's_db_secret_1", "John's_db_secret_2"},
				MapData: map[string]interface{}{
					"72": []map[string]interface{}{
						{"86": "84240002107004C1119054885C52A2555576F148AA"},
						{"86": "84240000083AB8700FAE0CB0DD"},
						{"77": "84240000083AB8700FAE0CB0DD"},
					},
					"91": "CA3D8B21F20B5CEB0012",
				},
				UnsupportedMapData: map[string]string{
					"91": "CA3D8B21F20B5CEB0012",
				},
			},
			{
				Username:  "Jane Doe",
				Password:  "Jane_Doe's_Password",
				DbSecrets: []string{"Jane's_db_secret_1", "Jane's_db_secret_2"},
				MapData: map[string]interface{}{
					"72": []map[string]interface{}{
						{"86": "84240002107004C1119054885C52A2555576F148AA"},
						{"86": "84240000083AB8700FAE0CB0DD"},
						{"77": "84240000083AB8700FAE0CB0DD"},
					},
					"91": "CA3D8B21F20B5CEB0012",
				},
				UnsupportedMapData: map[string]string{
					"91": "CA3D8B21F20B5CEB0012",
				},
			},
		},
	}

	empty := &Users{}

	userScrubbed := &Users{
		Secret: "************",
		Keys:   []string{".....", ".....", "....."},
		UserInfo: []User{
			{
				Username:  "John Doe",
				Password:  "*******************",
				DbSecrets: []string{"******************", "******************"},
				MapData: map[string]interface{}{
					"72": []map[string]interface{}{
						{"86": "******************************************"},
						{"86": "**************************"},
						{"77": "84240000083AB8700FAE0CB0DD"},
					},
					"91": "********************",
				},
				UnsupportedMapData: map[string]string{
					"91": "CA3D8B21F20B5CEB0012",
				},
			},
			{
				Username:  "Jane Doe",
				Password:  "*******************",
				DbSecrets: []string{"******************", "******************"},
				MapData: map[string]interface{}{
					"72": []map[string]interface{}{
						{"86": "******************************************"},
						{"86": "**************************"},
						{"77": "84240000083AB8700FAE0CB0DD"},
					},
					"91": "********************",
				},
				UnsupportedMapData: map[string]string{
					"91": "CA3D8B21F20B5CEB0012",
				},
			},
		},
	}

	secretFields := map[string]FieldScrubOptioner{
		"password":  nil,
		"keys":      newFieldScrubOpts(".", nil),
		"secret":    nil,
		"dbsecrets": nil,
		"91":        nil,
		"86":        nil,
	}

	validateScrub(t, empty, users, userScrubbed, secretFields, JSONScrub)
	validateScrub(t, empty, users, userScrubbed, secretFields, XMLScrub)
}

// Tests scrubbing on a nested complex struct with specific sensitive fields and map[string]interface{} support and partial masking of a given map key.
func TestScrubNestedMapSupportPartialMask(t *testing.T) {
	MaskLenVary = true

	secretFields := map[string]FieldScrubOptioner{
		"password":  nil,
		"keys":      newFieldScrubOpts(".", nil),
		"secret":    nil,
		"dbsecrets": nil,
		"91":        newFieldScrubOpts("*", NewPartScrubConf(true, 10, 19, 6, 16, 4)),
		"86":        newFieldScrubOpts("*", NewPartScrubConf(true, 10, 19, 6, 16, 4)),
	}

	target := "1234567891111111111"
	targetMasked := "123456*********1111"

	// Middle mask

	users := &Users{
		Secret: "secret_sshhh",
		Keys:   []string{"key_1", "key_2", "key_3"},
		UserInfo: []User{
			{
				Username:  "John Doe",
				Password:  "John_Doe's_Password",
				DbSecrets: []string{"John's_db_secret_1", "John's_db_secret_2"},
				MapData: map[string]interface{}{
					"72": []map[string]interface{}{
						{"86": target},
						{"86": target},
						{"77": "84240000083AB8700FAE0CB0DD"},
					},
					"91": target,
				},
				UnsupportedMapData: map[string]string{
					"91": target,
				},
			},
			{
				Username:  "Jane Doe",
				Password:  "Jane_Doe's_Password",
				DbSecrets: []string{"Jane's_db_secret_1", "Jane's_db_secret_2"},
				MapData: map[string]interface{}{
					"72": []map[string]interface{}{
						{"86": target},
						{"86": target},
						{"77": "84240000083AB8700FAE0CB0DD"},
					},
					"91": target,
				},
				UnsupportedMapData: map[string]string{
					"91": target,
				},
			},
		},
	}

	empty := &Users{}

	userScrubbed := &Users{
		Secret: strings.Repeat("*", len(users.Secret)),
		Keys:   []string{strings.Repeat(".", len(users.Keys[0])), strings.Repeat(".", len(users.Keys[1])), strings.Repeat(".", len(users.Keys[2]))},
		UserInfo: []User{
			{
				Username:  "John Doe",
				Password:  strings.Repeat("*", len(users.UserInfo[0].Password)),
				DbSecrets: []string{strings.Repeat("*", len(users.UserInfo[0].DbSecrets[0])), strings.Repeat("*", len(users.UserInfo[0].DbSecrets[1]))},
				MapData: map[string]interface{}{
					"72": []map[string]interface{}{
						{"86": targetMasked},
						{"86": targetMasked},
						{"77": "84240000083AB8700FAE0CB0DD"},
					},
					"91": targetMasked,
				},
				UnsupportedMapData: map[string]string{
					"91": target,
				},
			},
			{
				Username:  "Jane Doe",
				Password:  strings.Repeat("*", len(users.UserInfo[1].Password)),
				DbSecrets: []string{strings.Repeat("*", len(users.UserInfo[1].DbSecrets[0])), strings.Repeat("*", len(users.UserInfo[1].DbSecrets[1]))},
				MapData: map[string]interface{}{
					"72": []map[string]interface{}{
						{"86": targetMasked},
						{"86": targetMasked},
						{"77": "84240000083AB8700FAE0CB0DD"},
					},
					"91": targetMasked,
				},
				UnsupportedMapData: map[string]string{
					"91": target,
				},
			},
		},
	}

	validateScrub(t, empty, users, userScrubbed, secretFields, JSONScrub)
	validateScrub(t, empty, users, userScrubbed, secretFields, XMLScrub)

	// Backend mask

	target = "123456789111111"
	targetMasked = "123456*********"

	users.UserInfo[0].MapData = map[string]interface{}{
		"72": []map[string]interface{}{
			{"86": target},
			{"86": target},
			{"77": "84240000083AB8700FAE0CB0DD"},
		},
		"91": target,
	}
	users.UserInfo[0].UnsupportedMapData = map[string]string{
		"91": target,
	}
	users.UserInfo[1].MapData = map[string]interface{}{
		"72": []map[string]interface{}{
			{"86": target},
			{"86": target},
			{"77": "84240000083AB8700FAE0CB0DD"},
		},
		"91": target,
	}
	users.UserInfo[1].UnsupportedMapData = map[string]string{
		"91": target,
	}

	empty = &Users{}

	userScrubbed.UserInfo[0].MapData = map[string]interface{}{
		"72": []map[string]interface{}{
			{"86": targetMasked},
			{"86": targetMasked},
			{"77": "84240000083AB8700FAE0CB0DD"},
		},
		"91": targetMasked,
	}
	userScrubbed.UserInfo[0].UnsupportedMapData = map[string]string{
		"91": target,
	}
	userScrubbed.UserInfo[1].MapData = map[string]interface{}{
		"72": []map[string]interface{}{
			{"86": targetMasked},
			{"86": targetMasked},
			{"77": "84240000083AB8700FAE0CB0DD"},
		},
		"91": targetMasked,
	}
	userScrubbed.UserInfo[1].UnsupportedMapData = map[string]string{
		"91": target,
	}

	validateScrub(t, empty, users, userScrubbed, secretFields, JSONScrub)
	validateScrub(t, empty, users, userScrubbed, secretFields, XMLScrub)

	// Lower than min len mask

	target = "123456789"
	targetMasked = strings.Repeat("*", len(target))

	users.UserInfo[0].MapData = map[string]interface{}{
		"72": []map[string]interface{}{
			{"86": target},
			{"86": target},
			{"77": "84240000083AB8700FAE0CB0DD"},
		},
		"91": target,
	}
	users.UserInfo[0].UnsupportedMapData = map[string]string{
		"91": target,
	}
	users.UserInfo[1].MapData = map[string]interface{}{
		"72": []map[string]interface{}{
			{"86": target},
			{"86": target},
			{"77": "84240000083AB8700FAE0CB0DD"},
		},
		"91": target,
	}
	users.UserInfo[1].UnsupportedMapData = map[string]string{
		"91": target,
	}

	empty = &Users{}

	userScrubbed.UserInfo[0].MapData = map[string]interface{}{
		"72": []map[string]interface{}{
			{"86": targetMasked},
			{"86": targetMasked},
			{"77": "84240000083AB8700FAE0CB0DD"},
		},
		"91": targetMasked,
	}
	userScrubbed.UserInfo[0].UnsupportedMapData = map[string]string{
		"91": target,
	}
	userScrubbed.UserInfo[1].MapData = map[string]interface{}{
		"72": []map[string]interface{}{
			{"86": targetMasked},
			{"86": targetMasked},
			{"77": "84240000083AB8700FAE0CB0DD"},
		},
		"91": targetMasked,
	}
	userScrubbed.UserInfo[1].UnsupportedMapData = map[string]string{
		"91": target,
	}

	validateScrub(t, empty, users, userScrubbed, secretFields, JSONScrub)
	validateScrub(t, empty, users, userScrubbed, secretFields, XMLScrub)

	// Greater than max len mask

	target = "12345678911111111110"
	targetMasked = strings.Repeat("*", len(target))

	users.UserInfo[0].MapData = map[string]interface{}{
		"72": []map[string]interface{}{
			{"86": target},
			{"86": target},
			{"77": "84240000083AB8700FAE0CB0DD"},
		},
		"91": target,
	}
	users.UserInfo[0].UnsupportedMapData = map[string]string{
		"91": target,
	}
	users.UserInfo[1].MapData = map[string]interface{}{
		"72": []map[string]interface{}{
			{"86": target},
			{"86": target},
			{"77": "84240000083AB8700FAE0CB0DD"},
		},
		"91": target,
	}
	users.UserInfo[1].UnsupportedMapData = map[string]string{
		"91": target,
	}

	empty = &Users{}

	userScrubbed.UserInfo[0].MapData = map[string]interface{}{
		"72": []map[string]interface{}{
			{"86": targetMasked},
			{"86": targetMasked},
			{"77": "84240000083AB8700FAE0CB0DD"},
		},
		"91": targetMasked,
	}
	userScrubbed.UserInfo[0].UnsupportedMapData = map[string]string{
		"91": target,
	}
	userScrubbed.UserInfo[1].MapData = map[string]interface{}{
		"72": []map[string]interface{}{
			{"86": targetMasked},
			{"86": targetMasked},
			{"77": "84240000083AB8700FAE0CB0DD"},
		},
		"91": targetMasked,
	}
	userScrubbed.UserInfo[1].UnsupportedMapData = map[string]string{
		"91": target,
	}

	validateScrub(t, empty, users, userScrubbed, secretFields, JSONScrub)
	validateScrub(t, empty, users, userScrubbed, secretFields, XMLScrub)
}

// Tests scrubbing on a empty or nil input.
func TestScrubNilInput(t *testing.T) {
	MaskLenVary = false

	user := &User{
		Username:  "",
		Password:  "nutanix/4u",
		DbSecrets: []string{},
	}

	empty := &User{}

	userScrubbed := &User{
		Username:  "",
		Password:  "********",
		DbSecrets: []string{},
	}

	// Validate input with empty fields
	validateScrub(t, empty, user, userScrubbed, nil, JSONScrub)
	validateScrub(t, empty, user, userScrubbed, nil, XMLScrub)

	// Validate empty pointer input
	var userEmpty *User
	validateScrub(t, empty, userEmpty, userEmpty, nil, JSONScrub)
	validateScrub(t, empty, userEmpty, userEmpty, nil, XMLScrub)

	// Validate nil input
	validateScrub(t, empty, nil, nil, nil, JSONScrub)
	validateScrub(t, empty, nil, nil, nil, XMLScrub)
}

// Tests scrubbing on a nested complex struct with some nil, empty and specified sensitive fields.
func TestScrubNestedNilInput(t *testing.T) {
	MaskLenVary = false

	users := &Users{
		Secret: "",
		Keys:   nil,
		UserInfo: []User{
			{
				Username:  "John Doe",
				Password:  "",
				DbSecrets: []string{"John's_db_secret_1", "John's_db_secret_2"},
			},
			{
				Username:  "Jane Doe",
				Password:  "Jane_Doe's_Password",
				DbSecrets: []string{},
			},
		},
	}

	empty := &Users{}

	userScrubbed := &Users{
		Secret: "",
		Keys:   nil,
		UserInfo: []User{
			{
				Username:  "John Doe",
				Password:  "",
				DbSecrets: []string{"********", "********"},
			},
			{
				Username:  "Jane Doe",
				Password:  "********",
				DbSecrets: []string{},
			},
		},
	}

	// Test a nested struct with some empty and nil fields.
	secretFields := map[string]FieldScrubOptioner{
		"password":  nil,
		"keys":      newFieldScrubOpts(".", nil),
		"secret":    nil,
		"dbsecrets": nil,
	}

	validateScrub(t, empty, users, userScrubbed, secretFields, JSONScrub)
	validateScrub(t, empty, users, userScrubbed, secretFields, XMLScrub)
}

// validateScrub is a helper function to validate scrubbing functionality on a struct.
func validateScrub(t *testing.T, cloning, target, scrubbedMsg interface{}, secretFields map[string]FieldScrubOptioner, dataType DataType) {
	t.Helper()

	// Get the scrubbed string from util API.
	got := Scrub(cloning, target, secretFields, dataType)

	var b []byte
	var want string
	// Compare it against the given scrubbed representaation.
	switch dataType {
	case JSONScrub:
		b, _ = json.Marshal(scrubbedMsg)
		want = string(b)
	case XMLScrub:
		b, _ = xml.MarshalIndent(scrubbedMsg, "  ", "    ")
		want = string(b)
	}

	assert.Equal(t, want, got, fmt.Sprintf("%s representation mismatch after scrubbing sensitive fields", dataType))
}
