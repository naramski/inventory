# Inventory

Inventory reconciles Microsoft Intune and Entra ID with Snipe-IT.

## Commands

- `inventory devices` finds Windows, Linux, and macOS devices in Intune and creates missing Snipe-IT assets, matching by serial number.
- `inventory employee` finds active Entra ID users and creates missing Snipe-IT users, matching by email.
- `inventory check` reports active Entra ID users missing from Snipe-IT or without an assigned Snipe-IT asset.

Run a command with `--help` for CLI options. The config file defaults to `config.toml`; override it with `--config PATH`.

## Configuration

Copy `config.example.toml` to `config.toml` and fill in the credentials and Snipe-IT IDs. `config.toml` is ignored by Git because it contains secrets.

```toml
[azure]
tenant_id = "YOUR_TENANT_ID"
client_id = "YOUR_APP_CLIENT_ID"
client_secret = "YOUR_APP_CLIENT_SECRET"

[snipe_it]
url = "https://snipe.example.com"
api_token = "YOUR_SNIPE_IT_API_TOKEN"

[defaults]
model_id = 1
status_id = 1
asset_tag_prefix = "INTUNE-"
```

### Azure AD App Registration Permissions

Your Microsoft Entra ID app registration requires the following **Application permissions** in Microsoft Graph, with **admin consent** granted:

| Permission | Purpose | Required For |
|-----------|---------|--------------|
| `User.Read.All` | Read all user properties (displayName, mail, userPrincipalName) | `inventory employee` command |
| `DeviceManagementServiceConfig.Read.All` | Read Intune managed devices | `inventory devices` command |

**To grant permissions:**

1. Go to **Azure Portal** → **Microsoft Entra ID** → **App registrations**
2. Find your app registration (by Client ID)
3. Click **API permissions** in the left sidebar
4. Click **+ Add a permission**
5. Select **Microsoft Graph** → **Application permissions**
6. Search for and add each permission listed above
7. Click **Grant admin consent for [Organization]** (requires admin privileges)

If you receive a `401 Unauthorized` error, ensure the permissions are granted and admin consent has been applied.

### Snipe-IT Configuration

Snipe-IT requires an API token with permission to read and create users and assets. `model_id` and `status_id` are existing Snipe-IT IDs used for newly created assets. Asset tags are formed from `asset_tag_prefix` followed by the device serial number.

## Build

```sh
cargo build --release
./target/release/inventory devices
```

