
# ObjectScale secrets plugin for Hashicorp Vault
This plug in will manage IAM dynamic access key ID and secrets for accessing ObjectScale S3 buckets.

## How it works
This plugin has 2 modes of operation for generating credentials.
1. Dynamic mode
2. Predefined mode

In the dynamic mode, the plugin dynamically creates users in a namespace and assigns policies, groups, and permission boundaries.

To access the dynamic mode the Vault paths are `roles/dynamic/<role_name>` and `creds/dynamic/<role_name>`

In the predefined mode, the plugin system is only responsible for rotating the access key and secret of a user. The user is assumed to already exist.

To access the predefined mode the Vault paths are `roles/predefined/<user_name>` and `creds/predefined/<user_name>`

## Installation
A secrets engine plugin must be setup and configured before it can be used. Follow the directions below to properly install and configure the plugin.

### General ObjectScale configuration
1) A management account must exist for that will be used by the plugin.
2) Policies, groups, and permission boundaries that are to be configured for a role must already exist in the System namespace or the specific namespace used in the role.

## Dynamic mode
In this mode, a user is dynamically created and deleted as determined by a TTL value and policies, groups, tags, and a permission boundary can be applied to the created user. Credentials for this user will be returned for use to access resources of the cluster.

## Predefined mode
In this mode the plugin only handles creating S3 access secrets that expire within the defined TTL values. The user is expected to already exist in the namespace configured in the role. In ObjectScale a user can have up to 2 access keys active at any one time. These access keys are predetermined for a user at user creation time and do not change so the plugin can only invalidate the secrets for a user and not the access key as well. When in the predefined mode the user that is configured should only have access keys managed by the plugin and not manually via the management console. Manually created access keys will get cleaned up by the plugin and having 2 access keys will prevent the STS/role assumption from working properly.

No additional cluster configuration is required for this mode.

## Vault Plugin

### Using pre-built releases (recommended)
Any binary releases available can be found [here](https://github.com/murkyl/vault-plugin-secrets-objectscale/releases).

### From source
Clone the GitHub repository to your local machine and run `make build` from the root of the sources directory. After successful compilation the resulting `vault-plugin-secrets-objectscale` binary is located in the `bin/` directory.

Building from source assumes you have installed the Go development environment. The instructions and Makefile are developed for Linux based systems. Adjust the instructions according to your platform.

### Registering the plugin
Before a Vault plugin can be used, it must be copied to the Vault plugins directory and registered. The plugin directory for Vault is located in the Vault configuration file, often located at `/etc/vault.d/vault.hcl`.

Details of the Vault configuration file can be found in the [Vault online docs](https://www.vaultproject.io/docs/configuration "docs").

The required settings for registering a plugin are `plugin_directory` and `api_addr`. These need to be set according to your environment.

After copying the binary into the plugin directory, make sure that the permissions on the binary allow the Vault server process to execute it. Sometimes this means changing the ownership and group of the plugin to the Vault POSIX user account, for example chown vault:vault and a chmod 750. On a Windows platform make sure the binary ends with the .exe extension.

Make sure the Vault server itself is running, unsealed, and your have logged into Vault before registering the plugin.

Plugins also need to be registered with the Vault server [plugin catalog](https://www.vaultproject.io/docs/internals/plugins.html#plugin-catalog) before they can be enabled. A SHA256 sum of the binary is required in the register command.

```shell
vault plugin register \
  -sha256=$(sha256sum /etc/vault.d/vault_plugins/vault-plugin-secrets-objectscale_vX.Y.Z | cut -d " " -f 1) \
  -command vault-plugin-secrets-objectscale_vX.Y.Z \
  secret vault-plugin-secrets-objectscale
```

The -command option can be skipped and the default of the plugin name will be used as the executable. It is easier to always use the -command value to point to a specific version of the plugin executable.

You may see a warning in your Vault logs similar to this:
```shell
[WARN]  secrets.vault-plugin-secrets-objectscale.vault-plugin-secrets-objectscale_f798c167.vault-plugin-secrets-objectscale: plugin failed to exit gracefully: metadata=true
```
This warning is expected and can be safely ignored.

### Upgrading the plugin
[Upgrading a plugin](https://www.vaultproject.io/docs/upgrading/plugins) and keeping the existing configuration requires some specific steps. The procedure is similar to registering the plugin for the first time.

1) Ensure the current plugin is already registered, enabled, and mounted to a path
2) Copy the new binary to the plugin directory
3) Generate the SHA256 hash of the new binary
4) Register the new binary with the old plugin name
5) Ask Vault to reload the plugin

```shell
vault plugin register \
  -sha256=$(sha256sum /etc/vault.d/vault_plugins/vault-plugin-secrets-objectscale_vX.Y.Z | cut -d " " -f 1) \
  -command vault-plugin-secrets-objectscale_vA.B.C \
  secret vault-plugin-secrets-objectscale

vault plugin reload -plugin vault-plugin-secrets-objectscale
```

### Enabling the plugin
After the plugin is registered you can enable the plugin and have it available on a mount path.

```shell
vault secrets enable -path=objectscale vault-plugin-secrets-objectscale
```

You may see a warning in your Vault logs similar to this:
```shell
[WARN]  secrets.vault-plugin-secrets-objectscale.vault-plugin-secrets-objectscale_f798c167.vault-plugin-secrets-objectscale: plugin failed to exit gracefully: metadata=true
```
This warning is expected and can be safely ignored.

### Plugin configuration
To configure the plugin you need to write a set of key/value pairs to the path /config/root off of your plugin mount point. These configuration values should be written as key value pairs. Only 3 values are mandatory while the remainder have defaults. See the [available options](#path-configroot) below for additional customization.

The configuration below assumes defaults are used. The user and password need to be an IAM user's access key and secret. Using an IAM user is recommended for the highest level of security. The IAM user should be granted the minimum privileges required to perform the actions required by the plugin.

```shell
vault write objectscale/config/root \
    user=<iam_user_access_key> \
    password=<iam_user_secret> \
    endpoint=https://cluster.com:4443
```

An alternative is to use basic authentication and a session token. In this configuration the user and password needs to be a management or namespace user. Do note the additional parameter to specify the authentication type.

```shell
vault write objectscale/config/root \
    auth_type=basic \
    user=vault_mgr \
    password=isasecret \
    endpoint=https://cluster.com:4443
```

## Dynamic mode usage
Normal use involves creating roles that associate local groups to the role and then retrieving the credentials for that role. The roles and credential paths need to be secured via ACLs in Vault itself as the plugin does not perform any authentication or access control. Any request that reaches the plugin is assumed to have permission to do so from Vault.

### Create a role in Vault that will apply a set of policies to a user
This plugin role will associate policies, groups, tags, and boundary permissions to a dynamically created user. Only the namespace parameter is required however not providing a policy or group results in a created user with no permissions. Replace VaultRoleName with the name of the role you want to create.

```shell
vault write objectscale/roles/dynamic/VaultRoleName namespace=somenamespace policy=iampolicy1
vault write objectscale/roles/dynamic/VaultRoleName2 namespace=somenamespace policy=usernamespace:useriampolicy1
```

The namespace is required when defining a role. See the [available options](#path-rolesdynamicrole_name) below for additional customization.

### Retrieve a credential with the default TTL
```shell
vault read objectscale/creds/dynamic/VaultRoleName
```

### Retrieve a credential with an unlimited TTL
```shell
vault read objectscale/creds/dynamic/VaultRoleName ttl=-1
```

### Retrieve a credential with a TTL of 180 seconds
```shell
vault read objectscale/creds/dynamic/VaultRoleName ttl=180
```
In dynamic mode, repeated calls to read the objectscale/creds/dynamic/`role_name` path will each return a new access ID and secret pair.

### Credential expiration and cleanup
By default the plugin will provide an access token and secret that has an expiration of 300 seconds (5 minutes). The plugin creates a user name that looks like `vault_4xzkHE_7090_20210826133755`. The name begins with the **username_prefix** followed by a 6 character random string. It is followed by the first 4 characters of the Vault request UUID and then finally a time stamp. For credentials that expire, this timestamp represents the local time that the credential will become invalid.

If a credential with an unlimited duration is requested the user name will be in the format `vault_4xzkHE_7090_INF_20210826133755`. The extra string `INF` is added before the timestamp. The timestamp in this situation represents the time the credential was created instead of when it will expire.

The dynamically generated users will periodically be cleaned up by the plugin. The frequency that this occurs is determined by the `cleanup_period` option. The default is 600 seconds (10 minutes). Credentials that expire in between the cleanup periods will not be deleted until the next cleanup period occurs. A cleanup period check happens every minute from when the plugin is enabled. Internally the cleanup schedule is fixed at an interval of the cleanup period. For an example, if the plugin is started at 09:28, then the next cleanup periods will be 09:30, 09:40, 09:50, etc. If the cleanup period is 1 hour and the plugin is started at 09:28, the next cleanup will occur at 10:00, 11:00, 12:00, etc.

## Predefined mode usage
Normal use involves creating roles that represent a user's user name and then automatically expiring secrets.

### Create the role
A user needs to have a role created for them before they are allowed to retrieve a credential. This role should have a Vault access policy only allowing the specified user to access this particular path. Failure to do so could result in a user prematurely invalidating another user's credentials and also reading another user's credentials.

```shell
vault write objectscale/roles/predefined/user1 namespace=somenamespace
vault write objectscale/roles/predefined/user1 namespace=somenamespace ttl=600 policy=iampolicy1
vault write objectscale/roles/predefined/user1 namespace=somenamespace ttl=600 policy=usernamespace:iampolicy1
```

Attempts to configure a role where the user does not exist will succeed. However, when a credential is requested an error will be returned.

When using the CLI vault command to create a predefined role with all defaults you must use the -force option or provide some parameter.

### Retrieve a credential with the default TTL
```shell
vault read objectscale/creds/predefined/user1
```

### Retrieve a credential with an unlimited TTL
```shell
vault read objectscale/creds/predefined/user1 ttl=-1
```

### Retrieve a credential with a TTL of 180 seconds
```shell
vault read objectscale/creds/predefined/user1 ttl=180
```

## Predefined STS/IAM role assumption usage
The plugin supports returning credentials for a user assuming a role. The configuration is simple and only requires that the the user have a role configured as per the normal predefined mode usage. When retrieving the elevated privileges the plugin will automatically create a temporary set of Access ID and secrets for the user, use the new credentials to retrieve the elevated privileges, and then delete the temporary credentials.

Retrieving elevated credentials requires knowing the ARN for the role that is to be assumed by the user. This ARN needs to be passed into the call to the endpoint. The minimum duration for the elevated privileges is 3600 seconds. A longer duration can be requested during the credential request but the maximum is limited by the role itself.

The ARN for the role can be in the full form of: urn:ecs:iam::*__namespace__*:*__policy__* or a shortened form of *__namespace__*:*__policy__*. 

### Retrieve elevated role privileges
```shell
vault read oscale/sts/predefined/regularjoe role_arn=urn:ecs:iam::apj:role/upgradeJoe
Key               Value
---               -----
access_key        ASIA6605D5BA9FC4B2DC
key_expiry        3600
secret_key        K_A3pc8k7NNPV6dbxFaugkdbUbhgGGL42pN9ld5nAHE
security_token    CgNhcGoSCnJlZ3VsYXJqb2UaFEFST0E4RTk3OUFEODgwODlFRjJEIiB1cm46ZWNzOmlhbTo6YXBqOnJvbGUvdXBncmFkZUpvZSoUQVNJQTY2MDVENUJBOUZDNEIyREMyUE1hc3RlcktleVJlY29yZC0zZGE0ZTJlNmMyMGNiMzg2NDVlZTJlYjlkNWUxYzUxODJiYTBhYjQ3NWIxMDg4YWE5NDBmMzIyZTAyNWEzY2Q1OPKls_O9L1IfQUtJQTUwNzExREExQUJCMzc3NEItMTYzMTUyMDY3N2inj_yJBg
```

### Retrieve elevated role privileges with a short ARN
```shell
vault read oscale/sts/predefined/regularjoe role_arn=apj:upgradeJoe
Key               Value
---               -----
access_key        ASIAF485735B1E00B6AD
key_expiry        3600
secret_key        _lSn4juWxKBlZ3No-83QRLLN-RPA2ZF-SH-t8HrkxQQ
security_token    CgNhcGoSCnJlZ3VsYXJqb2UaFEFST0E4RTk3OUFEODgwODlFRjJEIiB1cm46ZWNzOmlhbTo6YXBqOnJvbGUvdXBncmFkZUpvZSoUQVNJQUY0ODU3MzVCMUUwMEI2QUQyUE1hc3RlcktleVJlY29yZC0zZGE0ZTJlNmMyMGNiMzg2NDVlZTJlYjlkNWUxYzUxODJiYTBhYjQ3NWIxMDg4YWE5NDBmMzIyZTAyNWEzY2Q1OMGA-PW9L1IfQUtJQTUwNzExREExQUJCMzc3NEItMTYzMTUyNTk5N2jvuPyJBg
```

### Specifying an invalid duration results in an error
```shell
vault read oscale/sts/predefined/regularjoe role_arn=apj:upgradeJoe duration=30000
Error reading oscale/sts/predefined/regularjoe: Error making API request.

URL: GET http://127.0.0.1:8200/v1/oscale/sts/predefined/regularjoe?duration=30000&role_arn=apj%3AupgradeJoe
Code: 500. Errors:

* 1 error occurred:
        * Assume role failed: [Send] Non 2xx response received (400): {"Error":{"Type":"Sender","Code":"ValidationError","Message":"The requested DurationSeconds 30000 exceeds the MaxSessionDuration 14400 set for this role urn:ecs:iam::apj:role/upgradeJoe."},"RequestId":"0a3bc915:17aa04e9c58:10743:0"}
```

## Security
HashiCorp Vault administrators are responsible for plugin security, including creating the Vault policy to ensure only authorized Hashicorp Vault users have access to the ObjectScale secrets plugin.

The following example creates a HashiCorp Vault policy and token restricted to generating access_id and secret keys for the predefined user account `user1`.
 

Contents of policy file /tmp/example_policy_file:
```
path "objectscale/creds/predefined/user1" {
  capabilities = ["read", "list"]
}
```

Configure HashiCorp Vault policy and create new token:
```shell
vault policy write objectscale-predefined-readcred-user1 /tmp/example_policy_file
vault token create -policy=objectscale-predefined-readcred-user1
```

## Plugin options
### Available paths
    /config/root
    /roles/dynamic/<role_name>
    /creds/dynamic/<role_name>
    /roles/predefined/<role_name>
    /creds/predefined/<role_name>
    /sts/predefined/<role_name>

### Available options
The configured TTL values for the role and plugin itself can be any value however, all TTL value will get rounded to the nearest 60 seconds (1 minute) when actually used.

#### Path: /config/root
| Key               | Description | Default | Required |
| ----------------- | ------------| :------ | :------: |
| auth_type         | **string** - The type of authentication used to connect to the ObjectScale API. Valid values are: iam or basic. This value changes the meaning of the values used in the user and password options. | iam | No |
| bypass_cert_check | **boolean** - When set to *true* SSL self-signed certificate issues are bypassed | false | No |
| cleanup_period    | **integer** - Number of seconds between calls to cleanup user accounts | 600 | No |
| endpoint          | **string** - FQDN or IP address of the ObjectScale cluster. The string should contain the protocol and port. e.g. https://cluster.name:4443 | | Yes |
| password          | **string** - Password for user or secret key. The password or secret is not returned in a GET of the configuration. | | Yes |
| ttl               | **int** - Default number of seconds that a secret token is valid. Individual roles and requests can override this value. A value of -1 or 0 represents an unlimited lifetime token. This value will be limited by the ttl_max value | 300 | No |
| ttl_max           | **int** - Maximum number of seconds a secret token can be valid. Individual roles can be less than or equal to this value. A value of -1 or 0 represents an unlimited lifetime token | 0 | No |
| user              | **string** - Name of user or IAM Access ID with appropriate RBAC privileges. See documentation for required privileges. The user or IAM access ID is returned in a GET of the configuration. | | Yes |
| username_prefix   | **string** - String to be used as the prefix for all users dynamically created by the plugin | vault | No |

#### Path: /roles/dynamic/role_name
| Key               | Description | Default | Required |
| ----------------- | ------------| :------ | :------: |
| boundary          | **string** - Name or URN of the policy that will be applied to the user as a boundary permission. See policy for format details. | | No |
| group             | **string** - Name of the group(s) that this role will have. Use multiple group key/value pairs to specify multiple groups | | No |
| namespace         | **string** - Namespace in the ObjectScale cluster that the role belongs | | Yes |
| policy            | **string** - Name or URN of the policy or policies that this role will have. Use multiple policy key/value pairs to specify multiple policies. Policies in non system namespaces should be preceded by the namespace and a colon or a full URN should be used<br/>Example<br/>SystemPolicyName<br/>namespace1:policyname<br/>urn:ecs:iam::namespace:policy/policyname<br/>urn:ecs:iam:::policy/SystemPolicyName | | No |
| tag               | **string** - Set of key=value pairs that will be applied to the created user. Use mulitple tag key/value pairs to specify multiple tags.<br />Example<br />tag=foo=bar tag=other=variable | | No |
| ttl               | **int** - Default number of seconds that a secret token is valid. Individual requests can override this value. A value of -1 represents an unlimited lifetime token. A value of 0 takes the plugin TTL. This value will be limited by the ttl_max value | -1 | No |
| ttl_max           | **int** - Maximum number of seconds a secret token can be valid. This value may be limited by plugin configuration. A value of -1 represents an unlimited lifetime token. A value of 0 takes the plugin max TTL | -1 | No |

#### Path: /creds/dynamic/role_name
| Key               | Description | Default | Required |
| ----------------- | ------------| :------ | :------: |
| ttl               | **int** - Requested number of seconds that  secret token is valid. This value will be capped by the maximum TTL specified by the role and plugin configuration. A value of -1 represents an unlimited lifetime token. A value of 0 represents taking the role or plugin configuration default | 0 | No |

#### Path: /roles/predefined/role_name
| Key               | Description | Default | Required |
| ----------------- | ------------| :------ | :------: |
| namespace         | **string** - Namespace in the ObjectScale cluster that the role belongs | | No |
| ttl               | **int** - Default number of seconds that a secret token is valid. Individual requests can override this value. A value of -1 represents an unlimited lifetime token. A value of 0 takes the plugin TTL. This value will be limited by the ttl_max value | -1 | No |
| ttl_max           | **int** - Maximum number of seconds a secret token can be valid. This value may be limited by plugin configuration. A value of -1 represents an unlimited lifetime token. A value of 0 takes the plugin max TTL | -1 | No |

#### Path: /creds/predefined/role_name
| Key               | Description | Default | Required |
| ----------------- | ------------| :------ | :------: |
| ttl               | **int** - Requested number of seconds that  secret token is valid. This value will be capped by the maximum TTL specified by the role and plugin configuration. A value of -1 represents an unlimited lifetime token. A value of 0 represents taking the role or plugin configuration default | 0 | No |

#### Path: /sts/predefined/role_name
| Key               | Description | Default | Required |
| ----------------- | ------------| :------ | :------: |
| duration          | **int** - Requested assumed role session duration in seconds. If not set or set to 0, role configured default will be used | 3600 | No |
| role_arn          | **string** - The ARN of the role to assume. The ARN for the role can be in the full form:<br/>urn:ecs:iam::*__namespace__*:*__policy__*<br/>or a shortened form:<br/>*__namespace__*:*__policy__* |  | Yes |
| session_name      | **string** - Name for the assumed role session. If not set a default generated from the user and time of request will be used. | 0 | No |
