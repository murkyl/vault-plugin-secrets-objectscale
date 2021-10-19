package vaultobjectscale

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	oslite "github.com/murkyl/go-objectscale-lite"
	"regexp"
	"sort"
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
	CleanupList []cleanupEntry
	Conn        *oslite.ObjectScaleConn
	NextCleanup time.Time
}

type backendCfg struct {
	AuthType       string
	BypassCert     bool
	CleanupPeriod  int
	Endpoint       string
	Password       string
	TTL            int
	TTLMax         int
	User           string
	UsernamePrefix string
}

type cleanupEntry struct {
	Expiration int64
	Namespace  string
	UserName   string
}

var _ logical.Factory = Factory

// Factory returns a Hashicorp Vault secrets backend object
func Factory(ctx context.Context, cfg *logical.BackendConfig) (logical.Backend, error) {
	b := &backend{}
	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        strings.TrimSpace(backendHelp),
		Paths: framework.PathAppend(
			pathConfigBuild(b),
			pathConfigInfo(b),
			pathRolesDynamicList(b),
			pathRolesDynamicBuild(b),
			pathRolesPredefinedBuild(b),
			pathRolesPredefinedList(b),
			pathCredsDynamicBuild(b),
			pathCredsPredefinedBuild(b),
			pathSTSPredefinedBuild(b),
		),
		InitializeFunc: b.pluginInit,
		PeriodicFunc:   b.pluginPeriod,
		Clean:          b.pluginCleanup,
	}
	if err := b.Setup(ctx, cfg); err != nil {
		b.Logger().Error(fmt.Sprintf("Error during setup: %s", err))
		return nil, err
	}
	return b, nil
}

func (b *backend) pluginInit(ctx context.Context, req *logical.InitializationRequest) error {
	b.Conn = oslite.NewObjectScaleConn()
	if b.Conn == nil {
		return fmt.Errorf("Failed to create a new ObjectScale connection")
	}
	return b.pluginReinit(ctx, req.Storage)
}

func (b *backend) pluginReinit(ctx context.Context, s logical.Storage) error {
	cfg, err := getCfgFromStorage(ctx, s)
	if err != nil {
		return err
	}
	if cfg == nil {
		b.Logger().Info("No configuration found. Configure this plugin at the URL <plugin_path>/config/root")
		return nil
	}
	b.NextCleanup = time.Now().Round(time.Second * time.Duration(cfg.CleanupPeriod))
	if b.NextCleanup.Before(time.Now()) {
		b.NextCleanup = b.NextCleanup.Add(time.Second * time.Duration(cfg.CleanupPeriod))
	}
	newCleanupList, err := b.getCleanupEntriesFromRoles(ctx, s)
	if err != nil {
		b.Logger().Error("Could not get new cleanup list from predefined roles. Old list is being retained")
	} else {
		b.CleanupList = newCleanupList
	}
	osCfg := &oslite.ObjectScaleCfg{
		User:       cfg.User,
		Password:   cfg.Password,
		AuthType:   cfg.AuthType,
		Endpoint:   cfg.Endpoint,
		BypassCert: cfg.BypassCert,
	}
	// When using IAM credentials all requests need to be signed so we set the automatic signing context
	if cfg.AuthType != "basic" {
		// We can use an empty region and service as ObjectScale does not require these values
		osCfg.SigningCtx = oslite.NewV4SignerContext(cfg.User, cfg.Password, "", "")
	}
	err = b.Conn.Connect(osCfg)
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
	curTime := time.Now()
	// Check dynamic user expiration
	if curTime.After(b.NextCleanup) {
		// We purposely update the next cleanup time immediately in case a cleanup error occurs. This will prevent
		// cleanup from running each time pluginPeriod is called
		timeDiff := time.Now().Sub(b.NextCleanup).Truncate(time.Second * time.Duration(cfg.CleanupPeriod))
		b.NextCleanup = b.NextCleanup.Add(timeDiff).Add(time.Second * time.Duration(cfg.CleanupPeriod))

		rex := regexp.MustCompile(fmt.Sprintf(defaultUserRegexp, cfg.UsernamePrefix))
		namespaces, err := b.getActiveNamespacesFromRoles(ctx, req.Storage, cfg.UsernamePrefix)
		if err != nil {
			b.Logger().Error(fmt.Sprintf("[pluginPeriod] Unable to get active namespaces"))
		} else {
			// Get a list of all users in the namespace
			for ns := range namespaces {
				userList, err := b.Conn.ListIAMUsers(ns, nil)
				if err != nil {
					b.Logger().Error(fmt.Sprintf("[pluginPeriod] Unable to list users in namespace %s: %s", ns, err))
					continue
				}
				for _, user := range userList.Users {
					result := rex.FindAllStringSubmatch(user.UserName, -1)
					if result != nil {
						// If the user name matches, we need to parse the expiration timestamp from the user name and compare it to the current time
						expireTime, err := time.ParseInLocation(defaultPathCredsDynamicTimeFormat, result[0][1], time.Local)
						if err != nil {
							b.Logger().Error(fmt.Sprintf("[pluginPeriod] Unable to parse expiration time for user %s: %s", user.UserName, err))
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
		}
	}
	// Check predefined user expiration
	curUnixTime := curTime.Unix()
	cutoff := -1
	for i, entry := range b.CleanupList {
		if entry.Expiration > curUnixTime {
			// Since the expiration list is sorted, the first entry we encounter that is in the future lets us halt the search
			break
		}
		// One of the entries in the predefined cleanup list has expired
		cutoff = i
		err = b.Conn.DeleteIAMAccessKeyAll(entry.Namespace, entry.UserName)
		if err != nil {
			b.Logger().Error(fmt.Sprintf("Unable to clean up key for %s:%s", entry.Namespace, entry.UserName))
		}
		err = clearPredefinedRoleExpiration(ctx, req.Storage, entry.UserName)
		if err != nil {
			b.Logger().Error(fmt.Sprintf("Unable to clear role expiration for role %s: %v", entry.UserName, err))
		}
	}
	if cutoff != -1 {
		// Trim the cleanup list
		var newList []cleanupEntry
		b.CleanupList = append(newList, b.CleanupList[cutoff+1:]...)
	}
	return nil
}

func (b *backend) pluginCleanup(ctx context.Context) {
	if b.Conn != nil {
		b.Conn.Disconnect()
	}
}

// getActiveNamespacesFromRoles searches all configured roles and returns a list of access zones that have users
// configured
func (b *backend) getActiveNamespacesFromRoles(ctx context.Context, s logical.Storage, userNamePrefix string) (map[string]bool, error) {
	configuredRoles, err := s.List(ctx, apiPathRolesDynamic)
	if err != nil {
		return nil, err
	}
	// Get all the active namespaces
	namespaces := map[string]bool{}
	for _, role := range configuredRoles {
		roleData, err := getDynamicRoleFromStorage(ctx, s, role)
		if err != nil || roleData == nil {
			b.Logger().Error("[getActiveNamespacesFromRoles] Unable to get role information for role %s: %s", role, err)
			continue
		}
		namespaces[roleData.Namespace] = true
	}
	return namespaces, nil
}

// getCleanupEntriesFromRoles returns a list of cleanup entries for all roles under the roles/predefined path
func (b *backend) getCleanupEntriesFromRoles(ctx context.Context, s logical.Storage) ([]cleanupEntry, error) {
	configuredRoles, err := s.List(ctx, apiPathRolesPredefined)
	if err != nil {
		return nil, err
	}
	var cleanupList []cleanupEntry
	for _, role := range configuredRoles {
		roleData, err := getPredefinedRoleFromStorage(ctx, s, role)
		if err != nil || roleData == nil {
			b.Logger().Error("[getCleanupEntriesFromRoles] Unable to get role information for role %s: %s", role, err)
			continue
		}
		if roleData.SecretExpiration > 0 {
			cleanupList = append(cleanupList, cleanupEntry{
				Expiration: roleData.SecretExpiration,
				Namespace:  roleData.Namespace,
				UserName:   role,
			})
		}
	}
	sort.Slice(cleanupList, func(i, j int) bool { return cleanupList[i].Expiration < cleanupList[j].Expiration })
	return cleanupList, nil
}

// addCleanupEntry will create, insert, and sort a new cleanup entry onto the existing cleanup list
func (b *backend) addCleanupEntry(expiration int64, namespace string, userName string) error {
	found := false
	for _, entry := range b.CleanupList {
		if entry.UserName == userName && entry.Namespace == namespace {
			found = true
			entry.Expiration = expiration
		}
	}
	if found == false {
		b.CleanupList = append(b.CleanupList, cleanupEntry{
			Expiration: expiration,
			Namespace:  namespace,
			UserName:   userName,
		})
	}
	sort.Slice(b.CleanupList, func(i, j int) bool { return b.CleanupList[i].Expiration < b.CleanupList[j].Expiration })
	return nil
}
