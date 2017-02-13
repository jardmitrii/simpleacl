package simpleacl

const (
	CREATE = "create"
	READ = "read"
	UPDATE = "update"
	DELETE = "delete"

	ALLOW = true
	DENY = false
)

type aclManager struct {
	permissions map[string]map[string]map[string]bool
}

func (acl *aclManager) AddRule (user, endpoint, action string, allow bool) {
	acl.permissions[endpoint] = map[string]map[string]bool{user:{action: allow,},}
}

func (acl *aclManager) DeleteRule (user, endpoint, action string) {
	delete(acl.permissions[endpoint][user], action)
}

func (acl *aclManager) HasRight (user, endpoint, action string) bool {
	return acl.permissions[endpoint][user][action]
}


var (
	Acl aclManager = aclManager{make(map[string]map[string]map[string]bool)}
)
