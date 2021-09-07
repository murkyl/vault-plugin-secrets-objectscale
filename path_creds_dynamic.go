package vaultobjectscale

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	oslite "github.com/murkyl/go-objectscale-lite"
	"time"
)

const (
	apiPathCredsDynamic                  string = "creds/dynamic/"
	defaultPathCredsDynamicRandomLength  int    = 6
	defaultPathCredsDynamicTimeFormat    string = "20060102150405"
	defaultPathCredsDynamicExpireSprintf string = "%s_%s_%s_%s"
	defaultPathCredsDynamicInfSprintf    string = "%s_%s_%s_INF_%s"
	fieldPathCredsDynamicAccessKey       string = "access_key"
	fieldPathCredsDynamicKeyExpiry       string = "key_expiry"
	fieldPathCredsDynamicName            string = "name"
	fieldPathCredsDynamicSecretKey       string = "secret_key"
	fieldPathCredsDynamicSecurityToken   string = "security_token"
	fieldPathCredsDynamicTTL             string = "ttl"
)

func pathCredsDynamicBuild(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: apiPathCredsDynamic + framework.GenericNameRegex(fieldPathCredsDynamicName),
			Fields: map[string]*framework.FieldSchema{
				fieldPathCredsDynamicName: {
					Type:        framework.TypeString,
					Description: "Name of the role to get an access token and secret",
				},
				fieldPathCredsDynamicTTL: {
					Type:        framework.TypeInt,
					Description: "Requested credentials duration in seconds. If not set or set to 0, configured default will be used. If set to -1, an unlimited duration credential will be requested if possible. Otherwise the maximum lease time will be granted.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.pathCredsDynamicRead},
			},
		},
	}
}

// pathCredsReadDynamic
// Returns
// access_key is a text string of the access ID
// secret_key is a text string of the access ID secret
// secret_token
// key_expiry is the expiration time of the access ID and secret given in UNIX epoch timestamp seconds.
func (b *backend) pathCredsDynamicRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get(fieldPathCredsDynamicName).(string)
	if roleName == "" {
		return logical.ErrorResponse("Unable to parse role name"), nil
	}
	var credTTL int = 0
	TTLDuration, ok := data.GetOk(fieldPathCredsDynamicTTL)
	if ok {
		credTTL = TTLDuration.(int)
	}
	// Get configuration from backend storage
	role, err := getDynamicRoleFromStorage(ctx, req.Storage, roleName)
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

	// Generate userName
	// If there is a TTL > 0 then the format of the user name has 4 parts:
	// Username prefix, random string, first 4 digits of Vault request UUID, and the expiration time
	// If the TTL is 0 or -1 (no TTL), the format has 5 parts:
	// Username prefix, random string, first 4 digits of Vault request UUID, the string INF, the create time for the user instead of expiration time
	randString, err := GenerateRandomString(defaultPathCredsDynamicRandomLength)
	if err != nil {
		return nil, err
	}
	credTime := time.Now().Local()
	credTimeString := defaultPathCredsDynamicInfSprintf
	if TTLMinutes > 0 {
		credTime = credTime.Add(time.Duration(TTLMinutes*TTLTimeUnit) * time.Second)
		credTimeString = defaultPathCredsDynamicExpireSprintf
	}
	userName := fmt.Sprintf(credTimeString, cfg.UsernamePrefix, randString, req.ID[0:4], credTime.Format(defaultPathCredsDynamicTimeFormat))

	// Create the user
	qParams := oslite.ObjectScaleQueryParams{}
	if role.Boundary != "" {
		qParams.Boundary = oslite.GetURNPolicyFromString(role.Boundary)
	}
	if len(role.Tags) > 0 {
		qParams.Tags = role.Tags
	}
	_, err = b.Conn.CreateIAMUser(role.Namespace, userName, &qParams)
	if err != nil {
		return nil, fmt.Errorf("Error creating user: %s", err)
	}
	// Update user with group memberships from the role
	for _, groupName := range role.Groups {
		_, err = b.Conn.AddIAMUserToGroup(role.Namespace, userName, groupName)
		if err != nil {
			b.Conn.DeleteIAMUserForce(role.Namespace, userName)
			return nil, fmt.Errorf("Error setting user's groups: %s", err)
		}
	}
	// Update the user with policies from the role
	for _, policyName := range role.Policies {
		_, err = b.Conn.AttachIAMUserPolicy(role.Namespace, userName, policyName)
		if err != nil {
			b.Conn.DeleteIAMUserForce(role.Namespace, userName)
			return nil, fmt.Errorf("Error setting user's policies: %s", err)
		}
	}
	// Get the credentials
	creds, err := b.Conn.CreateIAMAccessKey(role.Namespace, userName)
	if err != nil {
		b.Conn.DeleteIAMUserForce(role.Namespace, userName)
		return nil, fmt.Errorf("Error getting access key for user %s: %s", userName, err)
	}
	kv := map[string]interface{}{
		fieldPathCredsDynamicAccessKey:     creds.AccessKeyID,
		fieldPathCredsDynamicSecretKey:     creds.SecretAccessKey,
		fieldPathCredsDynamicSecurityToken: nil,
		fieldPathCredsDynamicKeyExpiry:     0, // 0 represents no expiration
	}
	if TTLMinutes > 0 {
		kv[fieldPathCredsDynamicKeyExpiry] = time.Now().Add(time.Duration(TTLMinutes) * time.Minute).Unix()
	}
	res := &logical.Response{Data: kv}
	return res, nil
}
