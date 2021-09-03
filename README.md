# OneFS secrets plugin for Hashicorp Vault
This plug in will manage S3 dynamic access key ID and secret for accessing OneFS S3 buckets.

## How it works
This plugin has 2 modes of operation for generating credentials.
1. Dynamic mode
2. Predefined mode

In the dynamic mode, the plugin dynamically creates local users on the OneFS cluster that belong to different groups depending on their roles. The S3 buckets created in OneFS are configured to have bucket ACLs providing access to the same groups that are configured for a user. This allows many users to access the same bucket without adding and removing user accounts to each bucket individually. This mode may be most appropriate for temporary read only access as any objects created using these credentials belong to a user that will be deleted. This mode can be used if the OneFS cluster is set to do permission inheritance at the bucket directory level.

To access the dynamic mode the Vault paths are `roles/dynamic/<role_name>` and `creds/dynamic/<role_name>`

In the predefined mode, the plugin system is only responsible for rotating the S3 secrets on the OneFS cluster. The user is assumed to already exist in an authentication provider that is accessible by the cluster.

To access the predefined mode the Vault paths are `roles/predefined/<user_name>` and `creds/predefined/<user_name>`

## Installation
All modes require some configuration on the OneFS cluster side. Some modes require additional configuration steps which are outlined in their own section below.

A secrets engine plugin must be setup and configured before it can be used. Follow the directions below to properly install and configure the plugin.

### General OneFS cluster configuration
A user account with the following privileges in the System zone is required for the plugin to generate S3 secrets.

* ISI_PRIV_AUTH with read and write permission (dynamic mode only)
* ISI_PRIV_LOGIN_PAPI with read permission
* ISI_PRIV_S3 with read and write permission

The name and password are required configuration parameters for the plugin. It is recommended to create a user specifically for Vault to use.

#### Create a role that has the proper privileges and assign our new user to the role
	isi auth roles create --name=VaultMgr
	isi auth roles modify VaultMgr --add-priv=ISI_PRIV_S3
	isi auth roles modify VaultMgr --add-priv-ro=ISI_PRIV_LOGIN_PAPI

The following RBAC permission is required only if using the dynamic mode

	isi auth roles modify VaultMgr --add-priv=ISI_PRIV_AUTH

#### Create a user for use by Vault
This step is required if you do not already have a user that can be assigned the Vault manager role.

	isi auth users create vault_mgr --enabled=True --set-password

#### Add your Vault user to the VaultMgr role

	isi auth roles modify VaultMgr --add-user=vault_mgr


## Dynamic mode
### General OneFS cluster configuration
* A local group needs to be configured in each access zone. This group is used as the primary group for all dynamically created users. The default group name assumed by the plugin is __vault__. The group should have the same name in each access zone. It is not necessary for the groups to have the same GID.
* A common home directory under /ifs needs to be created. This directory will be the home directory for all dynamically created users in all access zones. The permission on the directory should be 755. Use this as the **homedir** option for the configuration at `config/root`.

An example of the commands required on the OneFS cluster side follow.
#### Create the local group, and default home directory
    isi auth groups create vault
    mkdir /ifs/home/vault
    chown root:wheel /ifs/home/vault
    chmod 755 /ifs/home/vault

## Predefined mode
In this mode the plugin only handles creating S3 access secrets that expire within the defined TTL values. The user is expected to already exist either locally on the cluster or in another authentication provider like Active Directory.

No additional cluster configuration is required for this mode.

## Vault Plugin
### Using pre-built releases (recommended)
Any binary releases available can be found [here](https://github.com/murkyl/vault-plugin-secrets-onefs/releases).

### From source
Clone the GitHub repository to your local machine and run `make build` from the root of the sources directory. After successful compilation the resulting `vault-plugin-secrets-onefs` binary is located in the `bin/` directory.

Building from source assumes you have installed the Go development environment.

### Registering the plugin
Before a Vault plugin can be used, it must be copied to the Vault plugins directory and registered. The plugin directory for Vault is located in the Vault configuration file, often located at `/etc/vault.d/vault.hcl`.

Details of the Vault configuration file can be found in the [Vault online docs](https://www.vaultproject.io/docs/configuration "docs").

The required settings for registering a plugin are `plugin_directory` and `api_addr`. These need to be set according to your environment.

After copying the binary into the plugin directory, make sure that the permissions on the binary allow the Vault server process to execute it. Sometimes this means changing the ownership and group of the plugin to the Vault POSIX user account, for example chown vault:vault and a chmod 750.

Make sure the Vault server itself is running, unsealed, and your have logged into Vault before registering the plugin.

Plugins also need to be registered with the Vault server [plugin catalog](https://www.vaultproject.io/docs/internals/plugins.html#plugin-catalog) before they can be enabled. A SHA256 sum of the binary is required in the register command.

```shell
vault plugin register \
	-sha256=$(sha256sum /etc/vault.d/vault_plugins/vault-plugin-secrets-onefs | cut -d " " -f 1) \
	secret vault-plugin-secrets-onefs
```

### Enabling the plugin
After the plugin is registered you can enable the plugin and have it available on a mount path.

```shell
vault secrets enable -path=onefs vault-plugin-secrets-onefs
```

### Plugin configuration
To configure the plugin you need to write a set of key/value pairs to the path /config/root off of your plugin mount point. These configuration values should be written as key value pairs. Only 3 values are mandatory while the remainder have defaults. See the [available options](#path-configroot) below for additional customization. The configuration below assumes defaults are used.

### Dynamic mode
```shell
vault write onefs/config/root \
    user="vault_mgr" \
    password="isasecret" \
    endpoint="https://cluster.com:8080"
    homedir="/ifs/home/vault"
    primary_group="vault"
```

#### Predefined mode
```shell
vault write onefs/config/root \
    user="vault_mgr" \
    password="isasecret" \
    endpoint="https://cluster.com:8080"
```

## Dynamic mode usage
Normal use involves creating roles that associate local groups to the role and then retrieving the credentials for that role. The roles and credential paths need to be secured via ACLs in Vault itself as the plugin does not perform any authentication or access control. Any request that reaches the plugin is assumed to have permission to do so from Vault.

#### Create an initial test S3 bucket on the OneFS cluster and add ACEs
    isi s3 buckets create --create-path --name=testbucket --path=/ifs/testbucket --owner=root
    isi s3 buckets modify testbucket --add-ace="name=Backup Operators,type=group,perm=full_control"
    isi s3 buckets modify testbucket --add-ace="name=Guests,type=group,perm=full_control"

### Create a plugin role in Vault that will have access to the test bucket
This plugin role will associate local groups to the dynamic user and since the bucket ACL has these groups the dynamic user will have access to the bucket. Backup Operators and Guests are used in this example as they are available by default on the cluster.

```shell
vault write onefs/roles/dynamic/Test1 group="Guests" group="Backup Operators" bucket="s3-test" access_zone="System"
```

The access zone is required when defining a role. See the [available options](#path-rolesdynamicrole_name) below for additional customization.

### Retrieve a credential with the default TTL
```shell
vault read onefs/creds/dynamic/Test1
```

### Retrieve a credential with an unlimited TTL
```shell
vault read onefs/creds/dynamic/Test1 ttl=-1
```

### Retrieve a credential with a TTL of 180 seconds
```shell
vault read onefs/creds/dynamic/Test1 ttl=180
```

### Credential expiration and cleanup
By default the plugin will provide an access token and secret that has an expiration of 300 seconds (5 minutes). The plugin creates a user name that looks like `vault_4xzkHE_7090_20210826133755`. The name begins with the **username_prefix** followed by a 6 character random string. It is followed by the first 4 characters of the Vault request UUID and then finally a time stamp. For credentials that expire, this timestamp represents the local time that the credential will become invalid.

If a credential with an unlimited duration is requested the user name will be in the format `vault_4xzkHE_7090_INF_20210826133755`. The extra string `INF` is added before the timestamp. The timestamp in this situation represents the time the credential was created instead of when it will expire.

The dynamically generated users will periodically be cleaned up by the plugin. The frequency that this occurs is determined by the `cleanup_period` option. The default is 600 seconds (10 minutes). Credentials that expire in between the cleanup periods will not be deleted until the next cleanup period occurs. The cleanup period is not exact but is an approximate time.

## Predefined mode usage
Normal use involves creating roles that represent a user's user name. The user name can be a local user on the cluster or it can be an Active Directory user. An Active Directory username should be in the format `username@domain.com` while local user's are in the format `username`.

### Create the role
A user needs to have a role created for them before they are allowed to retrieve a credential. This role should have a Vault access policy only allowing the specified user to access this particular path. Failure to do so could result in a user prematurely invalidating another user's credentials and also reading another user's credentials.

```shell
vault write onefs/roles/predefined/someuser@domain.com
vault write onefs/roles/predefined/local_cluster_user ttl=600
```

Attempts to configure a role where the user does not exist will succeed. However, when a credential is requested an error will be returned.

When using the CLI vault command to create a predefined role with all defaults you must use the -force option or provide some parameter.

### Retrieve a credential with the default TTL
```shell
vault read onefs/creds/predefined/someuser@domain.com
```

### Retrieve a credential with an unlimited TTL
```shell
vault read onefs/creds/predefined/local_cluster_user ttl=-1
```

### Retrieve a credential with a TTL of 180 seconds
```shell
vault read onefs/creds/predefined/someuser@domain.com ttl=180
```

### Retrieve a credential for a non-existent user
```shell
$ vault read onefs/creds/predefined/BadUser ttl=6000
Error reading onefs/creds/predefined/BadUser: Error making API request.

URL: GET http://127.0.0.1:8200/v1/onefs/creds/predefined/BadUser?ttl=6000
Code: 500. Errors:

* 1 error occurred:
	* Unable to get S3 token for user BadUser: [Send] Non 2xx response received (404): 
{
"errors" : 
[

{
"code" : "AEC_NOT_FOUND",
"message" : "Failed to find user for 'BadUser'"
}
]
}
```

## Security
HashiCorp Vault administrators are responsible for plugin security, including creating the Vault policy to ensure only authorized Hashicorp Vault users have access to the onefs  secrets plugin.

The following example creates a HashiCorpy Vault policy and token restricted to generating access_id and secret keys for the predefined OneFS AD user account `aduser1@domain.com`.
 

Contents of policy file /tmp/example_policy_file:
```
path "onefs/creds/predefined/aduser1@domain.com" {
  capabilities = ["read", "list"]
}
```

Configure HashiCorp Vault policy and create new token:
```shell
vault policy write onefs-predefined-readcred-aduser1 /tmp/example_policy_file
vault token create -policy=onefs-predefined-readcred-aduser1
```

## Plugin options
### Available paths
    /config/root
    /roles/dynamic/<role_name>
    /creds/dynamic/<role_name>
    /roles/predefined/<role_name>
    /creds/predefined/<role_name>

### Available options
The configured TTL values for the role and plugin itself can be any value however, all TTL value will get rounded to the nearest 60 seconds (1 minute) when actually used.

#### Path: /config/root
| Key               | Description | Default | Required |
| ----------------- | ------------| :------ | :------: |
| endpoint          | **string** - FQDN or IP address of the OneFS cluster. The string should contain the protocol and port. e.g. https://cluster.name:8080 | | Yes |
| user              | **string** - User name for the user that will be used to access the OneFS cluster over the PAPI | | Yes |
| password          | **string** - Password for the user that will be used to access the OneFS cluster over the PAPI | | Yes |
| bypass_cert_check | **boolean** - When set to *true* SSL self-signed certificate issues are bypassed | false | No |
| cleanup_period    | **integer** - Number of seconds between calls to cleanup user accounts | 600 | No |
| homedir           | **string** - A common home directory under /ifs for all dynamically generated users - ensure 755 POSIX mode permissions on OneFS | /ifs/home/vault | No |
| primary_group     | **string** - Name of the primary group used by all users created by this plugin. The group must already exist in any access zone on the cluster where S3 user accounts will be used | vault | No |
| ttl               | **int** - Default number of seconds that a secret token is valid. Individual roles and requests can override this value. A value of -1 or 0 represents an unlimited lifetime token. This value will be limited by the ttl_max value | 300 | No |
| ttl_max           | **int** - Maximum number of seconds a secret token can be valid. Individual roles can be less than or equal to this value. A value of -1 or 0 represents an unlimited lifetime token | 0 | No |
| username_prefix   | **string** - String to be used as the prefix for all users dynamically created by the plugin | vault | No |

#### Path: /roles/dynamic/role_name
| Key               | Description | Default | Required |
| ----------------- | ------------| :------ | :------: |
| bucket            | **string** - Name of the S3 bucket | | Yes |
| group             | **string** - Name of the group(s) that this role will have. Use multiple group key/value pairs to specify multiple groups | | Yes |
| access_zone       | **string** - Access zone on the OneFS cluster that the role belongs | System | No |
| ttl               | **int** - Default number of seconds that a secret token is valid. Individual requests can override this value. A value of -1 represents an unlimited lifetime token. A value of 0 takes the plugin TTL. This value will be limited by the ttl_max value | -1 | No |
| ttl_max           | **int** - Maximum number of seconds a secret token can be valid. This value may be limited by plugin configuration. A value of -1 represents an unlimited lifetime token. A value of 0 takes the plugin max TTL | -1 | No |

#### Path: /creds/dynamic/role_name
| Key               | Description | Default | Required |
| ----------------- | ------------| :------ | :------: |
| ttl               | **int** - Requested number of seconds that  secret token is valid. This value will be capped by the maximum TTL specified by the role and plugin configuration. A value of -1 represents an unlimited lifetime token. A value of 0 represents taking the role or plugin configuration default | 0 | No |

#### Path: /roles/predefined/role_name
| Key               | Description | Default | Required |
| ----------------- | ------------| :------ | :------: |
| access_zone       | **string** - Access zone on the OneFS cluster that the role belongs | System | No |
| ttl               | **int** - Default number of seconds that a secret token is valid. Individual requests can override this value. A value of -1 represents an unlimited lifetime token. A value of 0 takes the plugin TTL. This value will be limited by the ttl_max value | -1 | No |
| ttl_max           | **int** - Maximum number of seconds a secret token can be valid. This value may be limited by plugin configuration. A value of -1 represents an unlimited lifetime token. A value of 0 takes the plugin max TTL | -1 | No |

#### Path: /creds/predefined/role_name
| Key               | Description | Default | Required |
| ----------------- | ------------| :------ | :------: |
| ttl               | **int** - Requested number of seconds that  secret token is valid. This value will be capped by the maximum TTL specified by the role and plugin configuration. A value of -1 represents an unlimited lifetime token. A value of 0 represents taking the role or plugin configuration default | 0 | No |
