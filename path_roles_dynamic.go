package vaultobjectscale

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
)

const (
	apiPathRolesDynamic            string = "roles/dynamic"
	fieldPathRolesDynamicBoundary  string = "boundary"
	fieldPathRolesDynamicGroup     string = "group"
	fieldPathRolesDynamicName      string = "name"
	fieldPathRolesDynamicNamespace string = "namespace"
	fieldPathRolesDynamicPolicy    string = "policy"
	fieldPathRolesDynamicTag       string = "tag"
	fieldPathRolesDynamicTTL       string = "ttl"
	fieldPathRolesDynamicTTLMax    string = "ttl_max"
)

func pathRolesDynamicBuild(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: apiPathRolesDynamic + "/" + framework.GenericNameRegex(fieldPathRolesDynamicName),
			Fields: map[string]*framework.FieldSchema{
				fieldPathRolesDynamicBoundary: {
					Type:        framework.TypeString,
					Description: "Name of permission boundary to apply to the user.",
				},
				fieldPathRolesDynamicGroup: {
					Type:        framework.TypeStringSlice,
					Description: "Name of group(s) that this role should belong. To specify multiple groups repeat the group=<group_name> key value pair.",
				},
				fieldPathRolesDynamicName: {
					Type:        framework.TypeString,
					Description: "Name of the role. The name should start and end with alphanumeric characters. Characters in the middle can be alphanumeric, . (period), or - (dash).",
				},
				fieldPathRolesDynamicNamespace: {
					Type:        framework.TypeString,
					Description: "The IAM namespace for users, policies, groups, and boundaries.",
				},
				fieldPathRolesDynamicPolicy: {
					Type:        framework.TypeStringSlice,
					Description: "Name of policy or policies that this role should belong. To specify multiple policies repeat the policy=<policy_name> key value pair.",
				},
				fieldPathRolesDynamicTag: {
					Type:        framework.TypeStringSlice,
					Description: "Tags to apply to a user in the format tag=key=value pair. To specify multiple tags, repeat the tag=key=value pair.",
				},
				fieldPathRolesDynamicTTL: {
					Type:        framework.TypeInt,
					Description: "Default credential duration in seconds. If not set or 0, plugin configuration will be used. If set to -1 no TTL will be used up to the plugin configuration.",
				},
				fieldPathRolesDynamicTTLMax: {
					Type:        framework.TypeInt,
					Description: "Maximum credential duration in seconds. If not set or 0, plugin configuration will be used. If set to -1, no TTL will be used up to the plugin configuration.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.pathRolesDynamicWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRolesDynamicRead},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRolesDynamicWrite},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRolesDynamicDelete},
			},
		},
	}
}

func (b *backend) pathRolesDynamicWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var validationErrors []string
	roleName := data.Get(fieldPathRolesDynamicName).(string)
	if roleName == "" {
		return logical.ErrorResponse("Role name is missing"), nil
	}
	// Get existing role object or create a new one as necessary
	role, err := getDynamicRoleFromStorage(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &iamRole{}
	}
	// Set role struct to values from request
	boundaryName, ok := data.GetOk(fieldPathRolesDynamicBoundary)
	if ok {
		role.Boundary = boundaryName.(string)
	}
	groupNames, ok := data.GetOk(fieldPathRolesDynamicGroup)
	if ok {
		role.Groups = groupNames.([]string)
	}
	namespace, ok := data.GetOk(fieldPathRolesDynamicNamespace)
	if ok {
		role.Namespace = namespace.(string)
	}
	policyNames, ok := data.GetOk(fieldPathRolesDynamicPolicy)
	if ok {
		role.Policies = policyNames.([]string)
	}
	tags, ok := data.GetOk(fieldPathRolesDynamicTag)
	if ok {
		for _, kvPair := range tags.([]string) {
			kvSlice := strings.SplitN(kvPair, "=", 2)
			if len(kvSlice) != 2 {
				validationErrors = append(validationErrors, "Unable to parse key value pair: "+kvPair)
			} else {
				role.Tags[kvSlice[0]] = kv_slice[1]
			}
		}
	}
	TTLDuration, ok := data.GetOk(fieldPathRolesDynamicTTL)
	if ok {
		role.TTL = TTLDuration.(int)
	}
	TTLMaxDuration, ok := data.GetOk(fieldPathRolesDynamicTTLMax)
	if ok {
		role.TTLMax = TTLMaxDuration.(int)
	}
	// Validate values
	if role.Namespace == "" {
		validationErrors = append(validationErrors, "A namespace is required for a role")
	}
	if role.TTLMax < 0 {
		role.TTLMax = -1
	}
	if role.TTL < 0 {
		role.TTL = -1
	}

	if len(validationErrors) > 0 {
		return nil, fmt.Errorf("Validation errors for role: %s\n%s", roleName, strings.Join(validationErrors[:], "\n"))
	}
	// Format and store data on the backend server
	entry, err := logical.StorageEntryJSON((apiPathRolesDynamic + "/" + roleName), role)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("Unable to create storage object for role: %s", roleName)
	}
	if err = req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathRolesDynamicRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get(fieldPathRolesDynamicName).(string)
	if roleName == "" {
		return logical.ErrorResponse("Unable to parse role name"), nil
	}
	role, err := getDynamicRoleFromStorage(ctx, req.Storage, roleName)
	if err != nil || role == nil {
		return nil, err
	}
	// Fill a key value struct with the stored values
	kv := map[string]interface{}{
		fieldPathRolesDynamicBoundary:  role.Boundary,
		fieldPathRolesDynamicGroup:     role.Groups,
		fieldPathRolesDynamicNamespace: role.Namespace,
		fieldPathRolesDynamicPolicy:    role.Policies,
		fieldPathRolesDynamicTag:       role.Tags,
		fieldPathRolesDynamicTTL:       role.TTL,
		fieldPathRolesDynamicTTLMax:    role.TTLMax,
	}
	return &logical.Response{Data: kv}, nil
}

// pathRolesDynamicDelete removes a role from the system
func (b *backend) pathRolesDynamicDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get(fieldPathRolesDynamicName).(string)
	if roleName == "" {
		return logical.ErrorResponse("Unable to parse role name"), nil
	}
	if err := req.Storage.Delete(ctx, apiPathRolesDynamic+"/"+roleName); err != nil {
		return nil, err
	}
	return nil, nil
}

// getDynamicRoleFromStorage retrieves a roles configuration from the API backend server and returns it in a iamRole struct
func getDynamicRoleFromStorage(ctx context.Context, s logical.Storage, roleName string) (*iamRole, error) {
	data, err := s.Get(ctx, apiPathRolesDynamic+"/"+roleName)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	role := &iamRole{}
	if err := json.Unmarshal(data.Value, role); err != nil {
		return nil, err
	}
	return role, nil
}
