package vaultobjectscale

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	oslite "github.com/murkyl/go-objectscale-lite"
	"regexp"
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
			pathRolesDynamicList(b),
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
		// Look through all the namespaces in all configured roles, find all users that match our dynamic user name format and
		// clean them up as necessary
		configuredRoles, err := req.Storage.List(ctx, apiPathRolesDynamic)
		if err != nil {
			return err
		}
		rex := regexp.MustCompile(fmt.Sprintf(defaultUserRegexp, cfg.UsernamePrefix))
		// Get all the active namespaces
		namespaces := map[string]bool{}
		for _, role := range configuredRoles {
			roleData, err := getDynamicRoleFromStorage(ctx, req.Storage, role)
			if err != nil || roleData == nil {
				b.Logger().Error("[pluginPeriod] Unable to get role information for role %s: %s", role, err)
				continue
			}
			namespaces[roleData.Namespace] = true
		}
		// Get a list of all users in the namespace
		for ns, _ := range namespaces {
			userList, err := b.Conn.ListIAMUsers(ns, nil)
			if err != nil {
				b.Logger().Error("[pluginPeriod] Unable to list users in namespace %s: %s", ns, err)
				continue
			}
			for _, user := range userList.Users {
				result := rex.FindAllStringSubmatch(user.UserName, -1)
				if result != nil {
					// If the user name matches, we need to parse the expiration timestamp from the user name and compare it to the current time
					expireTime, err := time.ParseInLocation(defaultPathCredsDynamicTimeFormat, result[0][1], time.Local)
					if err != nil {
						b.Logger().Error("[pluginPeriod] Unable to parse expiration time for user %s: %s", user.UserName, err)
						continue
					}
					// If expireTime is earlier than our current time then this user has expired
					if expireTime.Before(curTime) {
						_, err := b.Conn.DeleteIAMUserForce(ns, user.UserName)
						if err != nil {
							b.Logger().Error(fmt.Sprintf("[pluginPeriod] Unable to delete user %s for namespace %s: %v", user.UserName, ns, err))
						}
					}
				}
			}
		}
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
