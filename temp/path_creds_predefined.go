package vaultobjectscale

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	apiPathCredsPredefined                  string = "creds/predefined"
	defaultPathCredsPredefinedRandomLength  int    = 6
	defaultPathCredsPredefinedTimeFormat    string = "20060102150405"
	defaultPathCredsPredefinedExpireSprintf string = "%s_%s_%s_%s"
	defaultPathCredsPredefinedInfSprintf    string = "%s_%s_%s_INF_%s"
	fieldPathCredsPredefinedName            string = "name"
	fieldPathCredsPredefinedTTL             string = "ttl"
)

func pathCredsPredefinedBuild(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: apiPathCredsPredefined + "/" + framework.GenericNameWithAtRegex(fieldPathCredsPredefinedName),
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
// key_expiry is the expiration time of the access ID and secret given in UNIX epoch timestamp seconds.
func (b *backend) pathCredsPredefinedRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get(fieldPathCredsPredefinedName).(string)
	if roleName == "" {
		return logical.ErrorResponse("Unable to parse role name"), nil
	}
	var credTTL int = 0
	TTLDuration, ok := data.GetOk(fieldPathCredsPredefinedTTL)
	if ok {
		credTTL = TTLDuration.(int)
	}
	// Get configuration from backend storage
	role, err := getPredefinedRoleFromStorage(ctx, req.Storage, roleName)
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

	// Get the S3 access ID and secret key  
	token, err := b.Conn.PapiGetS3Token(roleName, role.AccessZone, 0)
	if err != nil {
		return nil, fmt.Errorf("Unable to get S3 token for user %s: %s", roleName, err)
	}
	// Fill a key value struct with the stored values
	kv := map[string]interface{}{
		"access_key": token.AccessID,
		"secret_key": token.SecretKey,
		"key_expiry": 0, // 0 represents no expiration
	}
	// To have a token automatically expire, you need to create a second token and set the expiration duration of the previous token
	if TTLMinutes > 0 {
		token2, err := b.Conn.PapiGetS3Token(roleName, role.AccessZone, TTLMinutes)
		if err != nil {
			return nil, fmt.Errorf("Unable to get the second S3 token for user %s: %s", roleName, err)
		}
		kv["key_expiry"] = token2.OldKeyExpiry
	}

	res := &logical.Response{Data: kv}
	return res, nil
}
