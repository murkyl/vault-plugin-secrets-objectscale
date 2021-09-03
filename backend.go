package vaultobjectscale

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	oslite "github.com/murkyl/go-objectscale-lite"
	//"regexp"
	"strings"
	"time"
)

const backendHelp = `
The ObjectScale secrets plugin for Vault allows dynamic creation and removal of users to return dynamic access ID
and secrets. Policies and groups can be applied to the user depending on the configuration for a role.
`
const defaultUserRegexp string = "^%s_[^_]+_[^_]+_(?P<TimeStamp>[0-9]{14})$"

type backend struct {
	*framework.Backend
	Conn        *oslite.ObjectScaleConn
	LastCleanup time.Time
}

type backendCfg struct {
	BypassCert     bool
	CleanupPeriod  int
	Endpoint       string
	Password       string
	TTL            int
	TTLMax         int
	User           string
	UsernamePrefix string
}

var _ logical.Factory = Factory

// Factory returns a Hashicorp Vault secrets backend object
func Factory(ctx context.Context, cfg *logical.BackendConfig) (logical.Backend, error) {
	b := &backend{}
	b.LastCleanup = time.Now()
	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        strings.TrimSpace(backendHelp),
		Paths: framework.PathAppend(
			pathConfigBuild(b),
			pathRolesDynamicBuild(b),
			//pathRolesPredefinedBuild(b),
			pathCredsDynamicBuild(b),
			//pathCredsPredefinedBuild(b),
		),
		InitializeFunc: b.pluginInit,
		PeriodicFunc:   b.pluginPeriod,
		Clean:          b.pluginCleanup,
	}
	if err := b.Setup(ctx, cfg); err != nil {
		b.Logger().Info(fmt.Sprintf("Error during setup: %s", err))
		return nil, err
	}
	return b, nil
}

func (b *backend) pluginInit(ctx context.Context, req *logical.InitializationRequest) error {
	cfg, err := getCfgFromStorage(ctx, req.Storage)
	if err != nil {
		return err
	}
	b.Conn = oslite.NewObjectScaleConn()
	if cfg == nil {
		b.Logger().Info("No configuration found. Configure this plugin at the URL <plugin_path>/config/root")
		return nil
	}
	err = b.Conn.Connect(&oslite.ObjectScaleCfg{
		User:       cfg.User,
		Password:   cfg.Password,
		Endpoint:   cfg.Endpoint,
		BypassCert: cfg.BypassCert,
	})
	if err != nil {
		b.Logger().Info(fmt.Sprintf("Unable to connect to endpoint during plugin creation: %s", err))
	}
	return nil
}

func (b *backend) pluginPeriod(ctx context.Context, req *logical.Request) error {
	cfg, err := getCfgFromStorage(ctx, req.Storage)
	if err != nil || cfg == nil {
		return nil
	}
	// Wait until we have a valid config
	if cfg.CleanupPeriod <= 0 {
		return nil
	}
	// Use the stored last cleanup time and only after the configured cleanup time is exceeded do we query all users and perform cleanup
	cleanupTime := b.LastCleanup.Add(time.Second * time.Duration(cfg.CleanupPeriod))
	curTime := time.Now()
	if curTime.After(cleanupTime) {
		//rex := regexp.MustCompile(fmt.Sprintf(defaultUserRegexp, cfg.UsernamePrefix))
		// TODO: Need to look through all the namespaces in all configured roles, find all users that match our dynamic user name format and
		// clean them up as necessary
		// TODO: We should increment a multiple of LastCleanup. Just using the current time can lead to cleanup time drift.
		b.LastCleanup = curTime
	}
	return nil
}

func (b *backend) pluginCleanup(ctx context.Context) {
	if b.Conn != nil {
		b.Conn.Disconnect()
	}
}
