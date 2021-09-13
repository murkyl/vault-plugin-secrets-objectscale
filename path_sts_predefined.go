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
	apiPathSTSPredefined                string = "sts/predefined/"
	apiPathSTSExpirationTimeFormat      string = "2006-01-02T15:04:05Z"
	fieldPathSTSPredefinedAccessKey     string = "access_key"
	fieldPathSTSPredefinedDuration      string = "duration"
	fieldPathSTSPredefinedKeyExpiry     string = "key_expiry"
	fieldPathSTSPredefinedName          string = "name"
	fieldPathSTSPredefinedRoleArn       string = "role_arn"
	fieldPathSTSPredefinedSecretKey     string = "secret_key"
	fieldPathSTSPredefinedSecurityToken string = "security_token"
	fieldPathSTSPredefinedSessionName   string = "session_name"
)

func pathSTSPredefinedBuild(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: apiPathSTSPredefined + framework.GenericNameRegex(fieldPathSTSPredefinedName),
			Fields: map[string]*framework.FieldSchema{
				fieldPathSTSPredefinedDuration: {
					Type:        framework.TypeInt,
					Description: "Requested assumed role session duration in seconds. If not set or set to 0, configured default of 3600 seconds will be used.",
				},
				fieldPathSTSPredefinedName: {
					Type:        framework.TypeString,
					Description: "Name of the role to get an STS access ID, secret, and secret token",
				},
				fieldPathSTSPredefinedRoleArn: {
					Type:        framework.TypeString,
					Description: "The ARN of the role to assume",
				},
				fieldPathSTSPredefinedSessionName: {
					Type:        framework.TypeString,
					Description: "Name for the assumed role session. If not set a default generated from the user and time of request will be used.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.pathSTSPredefinedRead},
			},
		},
	}
}

// pathSTSPredefinedRead
// Returns
// access_key is a text string of the access ID
// secret_key is a text string of the access ID secret
// secret_token is the assumed role secret
// key_expiry is the expiration time of the secrets given in seconds
func (b *backend) pathSTSPredefinedRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	qParams := oslite.ObjectScaleQueryParams{}
	userName := data.Get(fieldPathSTSPredefinedName).(string)
	if userName == "" {
		return logical.ErrorResponse("Unable to parse role name"), nil
	}
	roleArn := data.Get(fieldPathSTSPredefinedRoleArn).(string)
	if roleArn == "" {
		return logical.ErrorResponse("A role ARN to assume is required"), nil
	}
	qParams.RoleSessionName = data.Get(fieldPathSTSPredefinedSessionName).(string)
	qParams.DurationSeconds = int64(data.Get(fieldPathSTSPredefinedDuration).(int))
	// Get configuration from backend storage
	role, err := getPredefinedRoleFromStorage(ctx, req.Storage, userName)
	if err != nil || role == nil {
					return nil, err
	}
	// Get the second access key. This key is only temporarily used to generate the STS token and then deleted
	creds, err := b.Conn.CreateIAMAccessKey(role.Namespace, userName)
	if err != nil {
					return nil, fmt.Errorf("Error getting access key for user %s: %s", userName, err)
	}
	signingCtx := oslite.NewV4SignerContext(
		creds.AccessKeyID,
		creds.SecretAccessKey,
		"",	// ObjectScale does not care about the region
		"",	// ObjectScale does not care about the service
	)
	// Retrieve the STS secret token
	roleCreds, err := b.Conn.AssumeRole(
		roleArn,
		&qParams,
		&signingCtx,
	)
	// Cleanup the second access key immediately after trying to assume the role
	if _, err2 := b.Conn.DeleteIAMAccessKey(role.Namespace, userName, creds.AccessKeyID); err2 != nil {
		b.Logger().Error(fmt.Sprintf("Unable to clean up key: %v", err2))
	}
	if err != nil {
		return nil, fmt.Errorf("Assume role failed: %v", err)
	}
	expiration, _ := time.Parse(apiPathSTSExpirationTimeFormat, roleCreds.Credentials.Expiration)
	kv := map[string]interface{}{
		fieldPathSTSPredefinedAccessKey:     roleCreds.Credentials.AccessKeyID,
		fieldPathSTSPredefinedSecretKey:     roleCreds.Credentials.SecretAccessKey,
		fieldPathSTSPredefinedSecurityToken: roleCreds.Credentials.SessionToken,
		fieldPathSTSPredefinedKeyExpiry:     expiration.Sub(time.Now()).Truncate(time.Second).Seconds(),
	}
	res := &logical.Response{Data: kv}
	return res, nil
}
