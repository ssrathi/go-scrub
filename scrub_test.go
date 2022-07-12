package scrub

import (
	"encoding/json"
	"encoding/xml"
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

// Tests json format scrubbing on a simple struct with default options.
func TestScrubSimpleFixedLenJson(t *testing.T) {
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
}

// Tests xml format scrubbing on a simple struct with default options.
func TestScrubSimpleFixedLenXml(t *testing.T) {
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

	validateScrub(t, empty, user, userScrubbed, nil, XMLScrub)
}

// Tests json format scrubbing on a simple struct with default options and varying mask length.
func TestScrubSimpleVaryLenJson(t *testing.T) {
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
}

// Tests xml format scrubbing on a simple struct with default options and varying mask length.
func TestScrubSimpleVaryLenXml(t *testing.T) {
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

	validateScrub(t, empty, user, userScrubbed, nil, XMLScrub)
}

// Tests json format scrubbing on a nested complex struct with specific sensitive fields.
func TestScrubNestedFixedLenJson(t *testing.T) {
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

	secretFields := map[string]map[string]string{
		"password": make(map[string]string),
		"keys": make(map[string]string),
		"secret": make(map[string]string),
		"dbsecrets": make(map[string]string),
	}
	secretFields["password"]["symbol"] = "*"
	secretFields["keys"]["symbol"] = "."
	secretFields["secret"]["symbol"] = "*"
	secretFields["dbsecrets"]["symbol"] = "*"

	validateScrub(t, empty, users, userScrubbed, secretFields, JSONScrub)
}

// Tests xml format scrubbing on a nested complex struct with specific sensitive fields.
func TestScrubNestedFixedLenXml(t *testing.T) {
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

	secretFields := map[string]map[string]string{
		"password": make(map[string]string),
		"keys": make(map[string]string),
		"secret": make(map[string]string),
		"dbsecrets": make(map[string]string),
	}
	secretFields["password"]["symbol"] = "*"
	secretFields["keys"]["symbol"] = "."
	secretFields["secret"]["symbol"] = "*"
	secretFields["dbsecrets"]["symbol"] = "*"

	validateScrub(t, empty, users, userScrubbed, secretFields, XMLScrub)
}

// Tests json format scrubbing on a nested complex struct with specific sensitive fields.
func TestScrubNestedVaryLenJson(t *testing.T) {
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

	secretFields := map[string]map[string]string{
		"password": make(map[string]string),
		"keys": make(map[string]string),
		"secret": make(map[string]string),
		"dbsecrets": make(map[string]string),
	}
	secretFields["password"]["symbol"] = "*"
	secretFields["keys"]["symbol"] = "."
	secretFields["secret"]["symbol"] = "*"
	secretFields["dbsecrets"]["symbol"] = "*"

	validateScrub(t, empty, users, userScrubbed, secretFields, JSONScrub)
}

// Tests xml format scrubbing on a nested complex struct with specified sensitive fields.
func TestScrubNestedVaryLenXml(t *testing.T) {
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

	secretFields := map[string]map[string]string{
		"password": make(map[string]string),
		"keys": make(map[string]string),
		"secret": make(map[string]string),
		"dbsecrets": make(map[string]string),
	}
	secretFields["password"]["symbol"] = "*"
	secretFields["keys"]["symbol"] = "."
	secretFields["secret"]["symbol"] = "*"
	secretFields["dbsecrets"]["symbol"] = "*"

	validateScrub(t, empty, users, userScrubbed, secretFields, XMLScrub)
}

// Tests json format scrubbing on a nested complex struct with specific sensitive fields and map[string]interface{} support.
func TestScrubNestedMapSupportFixedLenJson(t *testing.T) {
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
						{"86":"84240002107004C1119054885C52A2555576F148AA"},
						{"86":"84240000083AB8700FAE0CB0DD"},
						{"77":"84240000083AB8700FAE0CB0DD"},
					},
					"91":"CA3D8B21F20B5CEB0012",
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
						{"86":"84240002107004C1119054885C52A2555576F148AA"},
						{"86":"84240000083AB8700FAE0CB0DD"},
						{"77":"84240000083AB8700FAE0CB0DD"},
					},
					"91":"CA3D8B21F20B5CEB0012",
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
						{"86":"********"},
						{"86":"********"},
						{"77":"84240000083AB8700FAE0CB0DD"},
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
						{"86":"********"},
						{"86":"********"},
						{"77":"84240000083AB8700FAE0CB0DD"},
					},
					"91": "********",
				},
				UnsupportedMapData: map[string]string{
					"91": "CA3D8B21F20B5CEB0012",
				},
			},
		},
	}

	secretFields := map[string]map[string]string{
		"password": make(map[string]string),
		"keys": make(map[string]string),
		"secret": make(map[string]string),
		"dbsecrets": make(map[string]string),
		"91": make(map[string]string),
		"86": make(map[string]string),
	}
	secretFields["password"]["symbol"] = "*"
	secretFields["keys"]["symbol"] = "."
	secretFields["secret"]["symbol"] = "*"
	secretFields["dbsecrets"]["symbol"] = "*"

	validateScrub(t, empty, users, userScrubbed, secretFields, JSONScrub)
}

// Tests json format scrubbing on a nested complex struct with specific sensitive fields and map[string]interface{} support.
func TestScrubNestedMapSupportVaryLenJson(t *testing.T) {
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
						{"86":"84240002107004C1119054885C52A2555576F148AA"},
						{"86":"84240000083AB8700FAE0CB0DD"},
						{"77":"84240000083AB8700FAE0CB0DD"},
					},
					"91":"CA3D8B21F20B5CEB0012",
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
						{"86":"84240002107004C1119054885C52A2555576F148AA"},
						{"86":"84240000083AB8700FAE0CB0DD"},
						{"77":"84240000083AB8700FAE0CB0DD"},
					},
					"91":"CA3D8B21F20B5CEB0012",
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
						{"86":"******************************************"},
						{"86":"**************************"},
						{"77":"84240000083AB8700FAE0CB0DD"},
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
						{"86":"******************************************"},
						{"86":"**************************"},
						{"77":"84240000083AB8700FAE0CB0DD"},
					},
					"91": "********************",
				},
				UnsupportedMapData: map[string]string{
					"91": "CA3D8B21F20B5CEB0012",
				},
			},
		},
	}

	secretFields := map[string]map[string]string{
		"password": make(map[string]string),
		"keys": make(map[string]string),
		"secret": make(map[string]string),
		"dbsecrets": make(map[string]string),
		"91": make(map[string]string),
		"86": make(map[string]string),
	}
	secretFields["password"]["symbol"] = "*"
	secretFields["keys"]["symbol"] = "."
	secretFields["secret"]["symbol"] = "*"
	secretFields["dbsecrets"]["symbol"] = "*"

	validateScrub(t, empty, users, userScrubbed, secretFields, JSONScrub)
}

// Tests xml format scrubbing on a nested complex struct with specific sensitive fields and map[string]interface{} support.
func TestScrubNestedMapSupportFixedLenxml(t *testing.T) {
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
						{"86":"84240002107004C1119054885C52A2555576F148AA"},
						{"86":"84240000083AB8700FAE0CB0DD"},
						{"77":"84240000083AB8700FAE0CB0DD"},
					},
					"91":"CA3D8B21F20B5CEB0012",
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
						{"86":"84240002107004C1119054885C52A2555576F148AA"},
						{"86":"84240000083AB8700FAE0CB0DD"},
						{"77":"84240000083AB8700FAE0CB0DD"},
					},
					"91":"CA3D8B21F20B5CEB0012",
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
						{"86":"********"},
						{"86":"********"},
						{"77":"84240000083AB8700FAE0CB0DD"},
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
						{"86":"********"},
						{"86":"********"},
						{"77":"84240000083AB8700FAE0CB0DD"},
					},
					"91": "********",
				},
				UnsupportedMapData: map[string]string{
					"91": "CA3D8B21F20B5CEB0012",
				},
			},
		},
	}

	secretFields := map[string]map[string]string{
		"password": make(map[string]string),
		"keys": make(map[string]string),
		"secret": make(map[string]string),
		"dbsecrets": make(map[string]string),
		"91": make(map[string]string),
		"86": make(map[string]string),
	}
	secretFields["password"]["symbol"] = "*"
	secretFields["keys"]["symbol"] = "."
	secretFields["secret"]["symbol"] = "*"
	secretFields["dbsecrets"]["symbol"] = "*"

	validateScrub(t, empty, users, userScrubbed, secretFields, XMLScrub)
}

// Tests xml format scrubbing on a nested complex struct with specific sensitive fields and map[string]interface{} support.
func TestScrubNestedMapSupportVaryLenXml(t *testing.T) {
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
						{"86":"84240002107004C1119054885C52A2555576F148AA"},
						{"86":"84240000083AB8700FAE0CB0DD"},
						{"77":"84240000083AB8700FAE0CB0DD"},
					},
					"91":"CA3D8B21F20B5CEB0012",
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
						{"86":"84240002107004C1119054885C52A2555576F148AA"},
						{"86":"84240000083AB8700FAE0CB0DD"},
						{"77":"84240000083AB8700FAE0CB0DD"},
					},
					"91":"CA3D8B21F20B5CEB0012",
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
						{"86":"******************************************"},
						{"86":"**************************"},
						{"77":"84240000083AB8700FAE0CB0DD"},
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
						{"86":"******************************************"},
						{"86":"**************************"},
						{"77":"84240000083AB8700FAE0CB0DD"},
					},
					"91": "********************",
				},
				UnsupportedMapData: map[string]string{
					"91": "CA3D8B21F20B5CEB0012",
				},
			},
		},
	}

	secretFields := map[string]map[string]string{
		"password": make(map[string]string),
		"keys": make(map[string]string),
		"secret": make(map[string]string),
		"dbsecrets": make(map[string]string),
		"91": make(map[string]string),
		"86": make(map[string]string),
	}
	secretFields["password"]["symbol"] = "*"
	secretFields["keys"]["symbol"] = "."
	secretFields["secret"]["symbol"] = "*"
	secretFields["dbsecrets"]["symbol"] = "*"

	validateScrub(t, empty, users, userScrubbed, secretFields, XMLScrub)
}

// Tests json format scrubbing on a empty or nil input.
func TestScrubNilJson(t *testing.T) {
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

	// Validate empty pointer input
	var userEmpty *User
	validateScrub(t, empty, userEmpty, userEmpty, nil, JSONScrub)

	// Validate nil input
	validateScrub(t, empty, nil, nil, nil, JSONScrub)
}

// Tests xml format scrubbing on a empty or nil input.
func TestScrubNilXml(t *testing.T) {
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
	validateScrub(t, empty, user, userScrubbed, nil, XMLScrub)

	// Validate empty pointer input
	var userEmpty *User
	validateScrub(t, empty, userEmpty, userEmpty, nil, XMLScrub)

	// Validate nil input
	validateScrub(t, empty, nil, nil, nil, XMLScrub)
}

// Tests json format scrubbing on a nested complex struct with some nil, empty and specified sensitive fields.
func TestScrubNestedNilJson(t *testing.T) {
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
	secretFields := map[string]map[string]string{
		"password": make(map[string]string),
		"keys": make(map[string]string),
		"secret": make(map[string]string),
		"dbsecrets": make(map[string]string),
	}
	secretFields["password"]["symbol"] = "*"
	secretFields["keys"]["symbol"] = "."
	secretFields["secret"]["symbol"] = "*"
	secretFields["dbsecrets"]["symbol"] = "*"

	validateScrub(t, empty, users, userScrubbed, secretFields, JSONScrub)
}

// Tests xml format scrubbing on a nested complex struct with some nil, empty and specified sensitive fields.
func TestScrubNestedNilXml(t *testing.T) {
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
	secretFields := map[string]map[string]string{
		"password": make(map[string]string),
		"keys": make(map[string]string),
		"secret": make(map[string]string),
		"dbsecrets": make(map[string]string),
	}
	secretFields["password"]["symbol"] = "*"
	secretFields["keys"]["symbol"] = "."
	secretFields["secret"]["symbol"] = "*"
	secretFields["dbsecrets"]["symbol"] = "*"

	validateScrub(t, empty, users, userScrubbed, secretFields, XMLScrub)
}

// validateScrub is a helper function to validate scrubbing functionality on a struct.
func validateScrub(t *testing.T, cloning, target, scrubbedMsg interface{}, secretFields map[string]map[string]string, dataType DataType) {
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

	assert.Equal(t, want, got,
		"JSON representation mismatch after scrubbing sensitive fields")
}
