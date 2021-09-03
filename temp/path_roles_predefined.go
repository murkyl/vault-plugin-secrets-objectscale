package vaultobjectscale

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	apiPathRolesPredefined                  string = "roles/predefined"
	fieldPathRolesPredefinedNamespace       string = "namespace"
	fieldPathRolesPredefinedName            string = "name"
	fieldPathRolesPredefinedTTL             string = "ttl"
	fieldPathRolesPredefinedTTLMax          string = "ttl_max"
)

type iamPredefinedRole struct {
	Namespace string
	TTL       int
	TTLMax    int
}

func pathRolesPredefinedBuild(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: apiPathRolesPredefined + "/" + framework.GenericNameWithAtRegex(fieldPathRolesPredefinedName),
			Fields: map[string]*framework.FieldSchema{
				fieldPathRolesPredefinedNamespace: {
					Type:        framework.TypeString,
					Description: "Namespace that this role will apply.",
				},
				fieldPathRolesPredefinedName: {
					Type:        framework.TypeString,
					Description: "Name of the user",
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

func (b *backend) pathRolesPredefinedWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get(fieldPathRolesPredefinedName).(string)
	if roleName == "" {
		return logical.ErrorResponse("Role name is missing"), nil
	}
	// Get existing role object or create a new one as necessary
	role, err := getPredefinedRoleFromStorage(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &iamPredefinedRole{}
	}
	// Set role struct to values from request
	azName, ok := data.GetOk(fieldPathRolesPredefinedAccessZone)
	if ok {
		role.AccessZone = azName.(string)
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
	if role.AccessZone == "" {
		role.AccessZone = apiPathRolesPredefinedDefaultAccessZone
	}
	if role.TTLMax < 0 {
		role.TTLMax = -1
	}
	if role.TTL < 0 {
		role.TTL = -1
	}

	// Format and store data on the backend server
	entry, err := logical.StorageEntryJSON((apiPathRolesPredefined + "/" + roleName), role)
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

func (b *backend) pathRolesPredefinedRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get(fieldPathRolesPredefinedName).(string)
	if roleName == "" {
		return logical.ErrorResponse("Unable to parse role name"), nil
	}
	role, err := getPredefinedRoleFromStorage(ctx, req.Storage, roleName)
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

// pathRolesPredefinedDelete removes a role from the system
func (b *backend) pathRolesPredefinedDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get(fieldPathRolesPredefinedName).(string)
	if roleName == "" {
		return logical.ErrorResponse("Unable to parse role name"), nil
	}
	if err := req.Storage.Delete(ctx, apiPathRolesPredefined+"/"+roleName); err != nil {
		return nil, err
	}
	return nil, nil
}

// getPredefinedRoleFromStorage retrieves a roles configuration from the API backend server and returns it in a iamPredefinedRole struct
func getPredefinedRoleFromStorage(ctx context.Context, s logical.Storage, roleName string) (*iamPredefinedRole, error) {
	data, err := s.Get(ctx, apiPathRolesPredefined+"/"+roleName)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	role := &iamPredefinedRole{}
	if err := json.Unmarshal(data.Value, role); err != nil {
		return nil, err
	}
	return role, nil
}
