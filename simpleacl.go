package simpleacl

const (
	ANY = ""

	CREATE = "create"
	READ = "read"
	UPDATE = "update"
	DELETE = "delete"

	ALLOW = true
	DENY = false
)

type aclManager struct {
	by_default bool
	permissions map[string]map[string]map[string]bool
}

func (acl *aclManager) SetDefaultPolicy (by_default bool) {
	acl.by_default = by_default
}

func (acl *aclManager) AddRule (user, endpoint, action string, allow bool) {
	acl.permissions[endpoint] = map[string]map[string]bool{user:{action: allow,},}
}

func (acl *aclManager) DeleteRule (user, endpoint, action string) {
	delete(acl.permissions[endpoint][user], action)
}

func (acl *aclManager) HasRight (user, endpoint, action string) bool {

	endpointRules, endpoint_present := acl.permissions[endpoint]
	if !endpoint_present && endpoint != ANY {
		endpointRules, endpoint_present = acl.permissions[ANY]
	}

	if !endpoint_present {
		return acl.by_default
	}

	userRules, user_present := endpointRules[user]
	if !user_present && user != ANY {
		userRules, user_present = endpointRules[ANY]
	}

	if !user_present {
		return acl.by_default
	}

	actionRule, action_present := userRules[action]
	if !action_present && user != ANY {
		actionRule, action_present = userRules[ANY]
	}

	if !action_present {
		return acl.by_default
	}

	return actionRule
}


var (
	Acl *aclManager = &aclManager{false, make(map[string]map[string]map[string]bool)}
)
