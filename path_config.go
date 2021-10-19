package vaultobjectscale

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	apiPathConfigRoot               string = "config/root"
	apiPathConfigInfo               string = "config/info"
	defaultPathConfigAuthType       string = "iam"
	defaultPathConfigCleanupPeriod  int    = 600
	defaultPathConfigUsernamePrefix string = "vault"
	defaultPathConfigDefaultTTL     int    = 300
	fieldConfigAuthType             string = "auth_type"
	fieldConfigBypassCert           string = "bypass_cert_check"
	fieldConfigCleanupPeriod        string = "cleanup_period"
	fieldConfigEndpoint             string = "endpoint"
	fieldConfigPassword             string = "password"
	fieldConfigTTL                  string = "ttl"
	fieldConfigTTLMax               string = "ttl_max"
	fieldConfigUser                 string = "user"
	fieldConfigUsernamePrefix       string = "username_prefix"
	fieldConfigVersion              string = "version"
)

type iamRole struct {
	Boundary         string
	Groups           []string
	Namespace        string
	Policies         []string
	SecretExpiration int64 `json:"omitempty"`
	Tags             map[string]string
	TTL              int
	TTLMax           int
}

func pathConfigBuild(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: apiPathConfigRoot,
			Fields: map[string]*framework.FieldSchema{
				fieldConfigAuthType: {
					Type:        framework.TypeString,
					Description: fmt.Sprintf("Authentication type to use for connections to ObjectScale. Allowed values: iam and basic. When IAM is used the user field is used as the access key. Default is: %s", defaultPathConfigAuthType),
				},
				fieldConfigBypassCert: {
					Type:        framework.TypeBool,
					Description: "Set to true to disable SSL certificate authority verification. Default is false.",
				},
				fieldConfigCleanupPeriod: {
					Type:        framework.TypeDurationSecond,
					Description: fmt.Sprintf("Number of seconds between each automatic user cleanup operation. If not set or 0, default of %d will be used", defaultPathConfigCleanupPeriod),
				},
				fieldConfigEndpoint: {
					Type:        framework.TypeString,
					Description: "ObjectScale API endpoint. Typically the endpoint looks like: https://fqdn:4443",
				},
				fieldConfigPassword: {
					Type:        framework.TypeString,
					Description: "Password for user or secret key. The password or secret is not returned in a GET of the configuration.",
				},
				fieldConfigTTL: {
					Type:        framework.TypeInt,
					Description: fmt.Sprintf("Default credential duration for all roles in seconds. If not set or 0, a default of %d seconds will be used. If set to -1 no TTL will be used.", defaultPathConfigDefaultTTL),
				},
				fieldConfigTTLMax: {
					Type:        framework.TypeInt,
					Description: "Default maximum credential duration for all roles in seconds. If not set, 0 or -1, no maximum TTL will be enforced.",
				},
				fieldConfigUser: {
					Type:        framework.TypeString,
					Description: "Name of user or IAM Access ID with appropriate RBAC privileges. See documentation for required privileges. The user or IAM access ID is returned in a GET of the configuration.",
				},
				fieldConfigUsernamePrefix: {
					Type:        framework.TypeString,
					Description: fmt.Sprintf("Prefix used when creating local users for Vault. If not set or set to the emptry string, default of '%s' will be used.", defaultPathConfigUsernamePrefix),
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigRootWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRootRead},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigRootWrite},
			},
		},
	}
}

func pathConfigInfo(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: apiPathConfigInfo,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.pathConfigRootInfo},
			},
		},
	}
}

func (b *backend) pathConfigRootInfo(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	// Fill a key value struct with the stored values
	kv := map[string]interface{}{
		fieldConfigVersion: PluginVersion,
	}
	return &logical.Response{Data: kv}, nil
}

func (b *backend) pathConfigRootRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := getCfgFromStorage(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	// Fill a key value struct with the stored values
	kv := map[string]interface{}{
		fieldConfigAuthType:       cfg.AuthType,
		fieldConfigBypassCert:     cfg.BypassCert,
		fieldConfigCleanupPeriod:  cfg.CleanupPeriod,
		fieldConfigEndpoint:       cfg.Endpoint,
		fieldConfigTTL:            cfg.TTL,
		fieldConfigTTLMax:         cfg.TTLMax,
		fieldConfigUser:           cfg.User,
		fieldConfigUsernamePrefix: cfg.UsernamePrefix,
	}
	return &logical.Response{Data: kv}, nil
}

func (b *backend) pathConfigRootWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Get existing cfg object or create a new one as necessary
	cfg, err := getCfgFromStorage(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &backendCfg{}
	}
	// Set config struct to values from request
	authType, ok := data.GetOk(fieldConfigAuthType)
	if ok {
		cfg.AuthType = authType.(string)
	}
	bypassCert, ok := data.GetOk(fieldConfigBypassCert)
	if ok {
		cfg.BypassCert = bypassCert.(bool)
	}
	cleanupPeriod, ok := data.GetOk(fieldConfigCleanupPeriod)
	if ok {
		cfg.CleanupPeriod = cleanupPeriod.(int)
	}
	endpoint, ok := data.GetOk(fieldConfigEndpoint)
	if ok {
		cfg.Endpoint = endpoint.(string)
	}
	pw, ok := data.GetOk(fieldConfigPassword)
	if ok {
		cfg.Password = pw.(string)
	}
	ttl, ok := data.GetOk(fieldConfigTTL)
	if ok {
		cfg.TTL = ttl.(int)
	}
	ttlMax, ok := data.GetOk(fieldConfigTTLMax)
	if ok {
		cfg.TTLMax = ttlMax.(int)
	}
	user, ok := data.GetOk(fieldConfigUser)
	if ok {
		cfg.User = user.(string)
	}
	usernamePrefix, ok := data.GetOk(fieldConfigUsernamePrefix)
	if ok {
		cfg.UsernamePrefix = usernamePrefix.(string)
	}
	// Validate data
	if cfg.AuthType == "" {
		cfg.AuthType = defaultPathConfigAuthType
	}
	if cfg.CleanupPeriod == 0 {
		cfg.CleanupPeriod = defaultPathConfigCleanupPeriod
	}
	if cfg.UsernamePrefix == "" {
		cfg.UsernamePrefix = defaultPathConfigUsernamePrefix
	}
	if cfg.TTLMax < 1 {
		cfg.TTLMax = -1
	}
	if cfg.TTL < 0 {
		cfg.TTL = -1
	} else if cfg.TTL == 0 {
		cfg.TTL = defaultPathConfigDefaultTTL
	}

	// Format and store data on the backend server
	entry, err := logical.StorageEntryJSON((apiPathConfigRoot), cfg)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("Unable to create storage object for root config")
	}
	if err = req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	res := &logical.Response{}
	res.AddWarning("Read access to this endpoint should be controlled via Hashicorp Vault ACLs as it will return sensitive information including credentials")
	err = b.pluginReinit(ctx, req.Storage)
	if err != nil {
		res.AddWarning(fmt.Sprintf("Unable to connect to initialize plugin after config update: %s", err))
	}
	return res, nil
}

func getCfgFromStorage(ctx context.Context, s logical.Storage) (*backendCfg, error) {
	data, err := s.Get(ctx, apiPathConfigRoot)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	cfg := &backendCfg{}
	if err := json.Unmarshal(data.Value, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
