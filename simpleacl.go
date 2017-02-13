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
	users []string
	endpoints []string
	permissions map[string]map[string]map[string]bool
}

var (
	acl aclManager = aclManager{[]string{}, []string{}, make(map[string]map[string]map[string]bool)}
)
