package simpleacl_test

import (
	"testing"

	"github.com/jardmitrii/simpleacl"
)

type rule struct {
	user, endpoint, action string
	allow                  bool
}

type testCase struct {
	rules, check []rule
}

var (
	allAllowedCase testCase = testCase{
		rules: []rule{
			{simpleacl.ANY, simpleacl.ANY, simpleacl.ANY, simpleacl.ALLOW},
		},
		check: []rule{
			{simpleacl.ANY, simpleacl.ANY, simpleacl.ANY, simpleacl.ALLOW},

			{simpleacl.ANY, simpleacl.ANY, simpleacl.CREATE, simpleacl.ALLOW},
			{simpleacl.ANY, simpleacl.ANY, simpleacl.READ, simpleacl.ALLOW},
			{simpleacl.ANY, simpleacl.ANY, simpleacl.UPDATE, simpleacl.ALLOW},
			{simpleacl.ANY, simpleacl.ANY, simpleacl.DELETE, simpleacl.ALLOW},

			{simpleacl.ANY, "endpoint1", simpleacl.ANY, simpleacl.ALLOW},
			{"user1", simpleacl.ANY, simpleacl.ANY, simpleacl.ALLOW},

			{simpleacl.ANY, "endpoint1", simpleacl.CREATE, simpleacl.ALLOW},
			{simpleacl.ANY, "endpoint1", simpleacl.READ, simpleacl.ALLOW},
			{simpleacl.ANY, "endpoint1", simpleacl.UPDATE, simpleacl.ALLOW},
			{simpleacl.ANY, "endpoint1", simpleacl.DELETE, simpleacl.ALLOW},

			{"user1", simpleacl.ANY, simpleacl.CREATE, simpleacl.ALLOW},
			{"user1", simpleacl.ANY, simpleacl.READ, simpleacl.ALLOW},
			{"user1", simpleacl.ANY, simpleacl.UPDATE, simpleacl.ALLOW},
			{"user1", simpleacl.ANY, simpleacl.DELETE, simpleacl.ALLOW},

			{"user1", "endpoint1", simpleacl.ANY, simpleacl.ALLOW},

			{"user1", "endpoint1", simpleacl.CREATE, simpleacl.ALLOW},
			{"user1", "endpoint1", simpleacl.READ, simpleacl.ALLOW},
			{"user1", "endpoint1", simpleacl.UPDATE, simpleacl.ALLOW},
			{"user1", "endpoint1", simpleacl.DELETE, simpleacl.ALLOW},
		},
	}
	allDeniedOneAllowedCase testCase = testCase{
		rules: []rule{
			{simpleacl.ANY, simpleacl.ANY, simpleacl.ANY, simpleacl.DENY},
			{"user2", "endpoint1", simpleacl.CREATE, simpleacl.ALLOW},
		},
		check: []rule{
			{simpleacl.ANY, simpleacl.ANY, simpleacl.ANY, simpleacl.DENY},

			{simpleacl.ANY, simpleacl.ANY, simpleacl.CREATE, simpleacl.DENY},
			{simpleacl.ANY, simpleacl.ANY, simpleacl.READ, simpleacl.DENY},
			{simpleacl.ANY, simpleacl.ANY, simpleacl.UPDATE, simpleacl.DENY},
			{simpleacl.ANY, simpleacl.ANY, simpleacl.DELETE, simpleacl.DENY},

			{simpleacl.ANY, "endpoint1", simpleacl.ANY, simpleacl.DENY},
			{"user1", simpleacl.ANY, simpleacl.ANY, simpleacl.DENY},

			{simpleacl.ANY, "endpoint1", simpleacl.CREATE, simpleacl.DENY},
			{simpleacl.ANY, "endpoint1", simpleacl.READ, simpleacl.DENY},
			{simpleacl.ANY, "endpoint1", simpleacl.UPDATE, simpleacl.DENY},
			{simpleacl.ANY, "endpoint1", simpleacl.DELETE, simpleacl.DENY},

			{"user1", simpleacl.ANY, simpleacl.CREATE, simpleacl.DENY},
			{"user1", simpleacl.ANY, simpleacl.READ, simpleacl.DENY},
			{"user1", simpleacl.ANY, simpleacl.UPDATE, simpleacl.DENY},
			{"user1", simpleacl.ANY, simpleacl.DELETE, simpleacl.DENY},

			{"user1", "endpoint1", simpleacl.ANY, simpleacl.DENY},

			{"user1", "endpoint1", simpleacl.CREATE, simpleacl.DENY},
			{"user1", "endpoint1", simpleacl.READ, simpleacl.DENY},
			{"user1", "endpoint1", simpleacl.UPDATE, simpleacl.DENY},
			{"user1", "endpoint1", simpleacl.DELETE, simpleacl.DENY},

			{"user2", "endpoint1", simpleacl.CREATE, simpleacl.ALLOW},
			{"user2", "endpoint1", simpleacl.READ, simpleacl.DENY},
			{"user2", "endpoint1", simpleacl.UPDATE, simpleacl.DENY},
			{"user2", "endpoint1", simpleacl.DELETE, simpleacl.DENY},

			{"user2", simpleacl.ANY, simpleacl.CREATE, simpleacl.DENY},
			{"user2", simpleacl.ANY, simpleacl.READ, simpleacl.DENY},
			{"user2", simpleacl.ANY, simpleacl.UPDATE, simpleacl.DENY},
			{"user2", simpleacl.ANY, simpleacl.DELETE, simpleacl.DENY},

			{"user2", "endpoint1", simpleacl.ANY, simpleacl.DENY},
		},
	}
)

func TestHasRight(t *testing.T) {
	testCases := []testCase{allAllowedCase, allDeniedOneAllowedCase}

	acl := simpleacl.Acl
	for _, testCase := range testCases {
		for _, rule := range testCase.rules {
			acl.AddRule(rule.user, rule.endpoint, rule.action, rule.allow)
		}

		for _, check := range testCase.check {
			has_right := acl.HasRight(check.user, check.endpoint, check.action)
			if has_right != check.allow {
				t.Log("Rules: ", acl)
				t.Log("Check: ", check)
				t.Fatal("Expect", check.allow)
			}
		}

		for _, rule := range testCase.rules {
			acl.DeleteRule(rule.user, rule.endpoint, rule.action)
		}
	}
}
