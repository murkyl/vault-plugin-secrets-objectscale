package vaultobjectscale

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"time"
)

const (
	apiPathCredsPredefined                string = "creds/predefined/"
	fieldPathCredsPredefinedAccessKey     string = "access_key"
	fieldPathCredsPredefinedKeyExpiry     string = "key_expiry"
	fieldPathCredsPredefinedName          string = "name"
	fieldPathCredsPredefinedSecretKey     string = "secret_key"
	fieldPathCredsPredefinedSecurityToken string = "security_token"
	fieldPathCredsPredefinedTTL           string = "ttl"
)

func pathCredsPredefinedBuild(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: apiPathCredsPredefined + framework.GenericNameRegex(fieldPathCredsPredefinedName),
			Fields: map[string]*framework.FieldSchema{
				fieldPathCredsPredefinedName: {
					Type:        framework.TypeString,
					Description: "Name of the role to get an access token and secret",
				},
				fieldPathCredsPredefinedTTL: {
					Type:        framework.TypeInt,
					Description: "Requested credentials duration in seconds. If not set or set to 0, configured default will be used. If set to -1, an unlimited duration credential will be requested if possible. Otherwise the maximum lease time will be granted.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.pathCredsPredefinedRead},
			},
		},
	}
}

// pathCredsPredefinedRead
// Returns
// access_key is a text string of the access ID
// secret_key is a text string of the access ID secret
// secret_token
// key_expiry is the expiration time of the access ID and secret given in UNIX epoch timestamp seconds.
func (b *backend) pathCredsPredefinedRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	userName := data.Get(fieldPathCredsPredefinedName).(string)
	if userName == "" {
		return logical.ErrorResponse("Unable to parse role name"), nil
	}
	var credTTL int = 0
	TTLDuration, ok := data.GetOk(fieldPathCredsPredefinedTTL)
	if ok {
		credTTL = TTLDuration.(int)
	}
	// Get configuration from backend storage
	role, err := getPredefinedRoleFromStorage(ctx, req.Storage, userName)
	if err != nil || role == nil {
		return nil, err
	}
	cfg, err := getCfgFromStorage(ctx, req.Storage)
	if err != nil || cfg == nil {
		return nil, err
	}
	// Calculate actual TTL in minutes based on the requested TTL and the rules in the role and plugin config
	maxTTL := CalcMaxTTL(role.TTLMax, cfg.TTLMax)
	TTLSeconds := CalcTTL(credTTL, role.TTL, cfg.TTL, maxTTL)
	TTLMinutes := 0
	if TTLSeconds > 0 {
		TTLMinutes = RoundTTLToUnit(TTLSeconds, TTLTimeUnit) / TTLTimeUnit
	} else {
		TTLMinutes = TTLSeconds // The TTL should be 0 or -1 which results in an infinite lease
	}

	// Remove any existing credentials
	err = b.Conn.DeleteIAMAccessKeyAll(role.Namespace, userName)
	if err != nil {
		b.Logger().Error(fmt.Sprintf("Unable to clean up all keys: %v", err))
	}

	// Get new credentials
	creds, err := b.Conn.CreateIAMAccessKey(role.Namespace, userName)
	if err != nil {
		b.Conn.DeleteIAMUserForce(role.Namespace, userName)
		return nil, fmt.Errorf("Error getting access key for user %s: %s", userName, err)
	}
	kv := map[string]interface{}{
		fieldPathCredsPredefinedAccessKey:     creds.AccessKeyID,
		fieldPathCredsPredefinedSecretKey:     creds.SecretAccessKey,
		fieldPathCredsPredefinedSecurityToken: nil,
		fieldPathCredsPredefinedKeyExpiry:     0, // 0 represents no expiration
	}
	if TTLMinutes > 0 {
		kv[fieldPathCredsPredefinedKeyExpiry] = time.Now().Add(time.Duration(TTLMinutes) * time.Minute).Unix()
	}
	// Save this roles secret expiration to the role itself and store it back to Vault
	role.SecretExpiration = kv[fieldPathCredsPredefinedKeyExpiry].(int64)
	// Write role into Vault storage
	if err = setPredefinedRoleToStorage(ctx, req.Storage, userName, role); err != nil {
		return nil, err
	}
	if err = b.addCleanupEntry(kv[fieldPathCredsPredefinedKeyExpiry].(int64), role.Namespace, userName); err != nil {
		return nil, err
	}
	res := &logical.Response{Data: kv}
	return res, nil
}
