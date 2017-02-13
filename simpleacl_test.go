package simpleacl_test

import (
	"github.com/jardmitrii/simpleacl"

	"testing"
)

func TestHasRight (t *testing.T) {
	test_rules := [][]string{
		{"user1", "endpoint1", simpleacl.CREATE,},
		{"user1", "endpoint1", simpleacl.READ,},
		{"user1", "endpoint1", simpleacl.UPDATE,},
		{"user1", "endpoint1", simpleacl.DELETE,},
		{"user2", "endpoint2", simpleacl.CREATE,},
		{"user2", "endpoint2", simpleacl.READ,},
		{"user2", "endpoint2", simpleacl.UPDATE,},
		{"user2", "endpoint2", simpleacl.DELETE,},
		{"user3", "", simpleacl.CREATE,},
		{"user3", "", simpleacl.READ,},
		{"user3", "", simpleacl.UPDATE,},
		{"user3", "", simpleacl.DELETE,},
		{"", "endpoint4", simpleacl.CREATE,},
		{"", "endpoint4", simpleacl.READ,},
		{"", "endpoint4", simpleacl.UPDATE,},
		{"", "endpoint4", simpleacl.DELETE,},
		{"user5", "endpoint5", "",},
		{"user5", "endpoint5", "",},
		{"user5", "endpoint5", "",},
		{"user5", "endpoint5", "",},
	}

	acl := &simpleacl.Acl
	for _, allow := range []bool{simpleacl.ALLOW, simpleacl.DENY} {
		for _, v := range test_rules {
			acl.AddRule(v[0], v[1], v[2], allow)
			has_right := acl.HasRight(v[0], v[1], v[2])
			if has_right != allow {
				t.Fatal("TestHasRight", v[0])
			}
		}
	}
}

func TestDeleteRule (t *testing.T) {

}