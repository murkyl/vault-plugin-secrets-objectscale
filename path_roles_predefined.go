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
	pathRolesPredefinedHelpSynopsis    = "List the configured backend roles"
	pathRolesPredefinedHelpDescription = `
This endpoint returns a list of all the configured backend roles
`
)

const (
	apiPathRolesPredefined            string = "roles/predefined/"
	fieldPathRolesPredefinedName      string = "name"
	fieldPathRolesPredefinedNamespace string = "namespace"
	fieldPathRolesPredefinedTTL       string = "ttl"
	fieldPathRolesPredefinedTTLMax    string = "ttl_max"
)

func pathRolesPredefinedBuild(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: apiPathRolesPredefined + framework.GenericNameRegex(fieldPathRolesPredefinedName),
			Fields: map[string]*framework.FieldSchema{
				fieldPathRolesPredefinedNamespace: {
					Type:        framework.TypeString,
					Description: "The IAM namespace for the user",
				},
				fieldPathRolesPredefinedName: {
					Type:        framework.TypeString,
					Description: "Name of the role. For the predefined mode, the role name is the user name that will be managed. The name should start and end with alphanumeric characters. Characters in the middle can be alphanumeric, . (period), or - (dash).",
				},
				fieldPathRolesPredefinedTTL: {
					Type:        framework.TypeInt,
					Description: "Default credential duration in seconds. If not set or 0, plugin configuration will be used. If set to -1 no TTL will be used up to the plugin configuration.",
				},
				fieldPathRolesPredefinedTTLMax: {
					Type:        framework.TypeInt,
					Description: "Maximum credential duration in seconds. If not set or 0, plugin configuration will be used. If set to -1, no TTL will be used up to the plugin configuration.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.pathRolesPredefinedWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRolesPredefinedRead},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRolesPredefinedWrite},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRolesPredefinedDelete},
			},
		},
	}
}

func pathRolesPredefinedList(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: apiPathRolesPredefined + "?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathRolesPredefinedList},
			},
			HelpSynopsis:    pathRolesPredefinedHelpSynopsis,
			HelpDescription: pathRolesPredefinedHelpDescription,
		},
	}
}

func (b *backend) pathRolesPredefinedList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	roleList, err := req.Storage.List(ctx, apiPathRolesPredefined)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roleList), nil
}

func (b *backend) pathRolesPredefinedWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var validationErrors []string
	userName := data.Get(fieldPathRolesPredefinedName).(string)
	if userName == "" {
		return logical.ErrorResponse("Role name is missing"), nil
	}
	// Get existing role object or create a new one as necessary
	role, err := getPredefinedRoleFromStorage(ctx, req.Storage, userName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &iamRole{}
	}
	// Set role struct to values from request
	namespace, ok := data.GetOk(fieldPathRolesPredefinedNamespace)
	if ok {
		role.Namespace = namespace.(string)
	}
	TTLDuration, ok := data.GetOk(fieldPathRolesPredefinedTTL)
	if ok {
		role.TTL = TTLDuration.(int)
	}
	TTLMaxDuration, ok := data.GetOk(fieldPathRolesPredefinedTTLMax)
	if ok {
		role.TTLMax = TTLMaxDuration.(int)
	}
	// Validate values
	if role.Namespace == "" {
		validationErrors = append(validationErrors, "A namespace is required for a role/user")
	}
	if role.TTLMax < 0 {
		role.TTLMax = -1
	}
	if role.TTL < 0 {
		role.TTL = -1
	}

	if len(validationErrors) > 0 {
		return nil, fmt.Errorf("Validation errors for role/user: %s\n%s", userName, strings.Join(validationErrors[:], "\n"))
	}
	// Format and store data on the backend server
	entry, err := logical.StorageEntryJSON((apiPathRolesPredefined + userName), role)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("Unable to create storage object for role: %s", userName)
	}
	if err = req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathRolesPredefinedRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	userName := data.Get(fieldPathRolesPredefinedName).(string)
	if userName == "" {
		return logical.ErrorResponse("Unable to parse role name"), nil
	}
	role, err := getPredefinedRoleFromStorage(ctx, req.Storage, userName)
	if err != nil || role == nil {
		return nil, err
	}
	// Fill a key value struct with the stored values
	kv := map[string]interface{}{
		fieldPathRolesPredefinedNamespace: role.Namespace,
		fieldPathRolesPredefinedTTL:       role.TTL,
		fieldPathRolesPredefinedTTLMax:    role.TTLMax,
	}
	return &logical.Response{Data: kv}, nil
}

// PathRolesPredefinedDelete removes a role from the system
func (b *backend) pathRolesPredefinedDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	userName := data.Get(fieldPathRolesPredefinedName).(string)
	if userName == "" {
		return logical.ErrorResponse("Unable to parse role name"), nil
	}
	if err := req.Storage.Delete(ctx, apiPathRolesPredefined+userName); err != nil {
		return nil, err
	}
	return nil, nil
}

// getPredefinedRoleFromStorage retrieves a roles configuration from the API backend server and returns it in a iamRole struct
func getPredefinedRoleFromStorage(ctx context.Context, s logical.Storage, userName string) (*iamRole, error) {
	data, err := s.Get(ctx, apiPathRolesPredefined+userName)
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
