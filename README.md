# Inventory

Inventory reconciles Microsoft Intune and Entra ID with Snipe-IT.

## Commands

- `inventory devices` finds Windows, Linux, and macOS devices in Intune and creates missing Snipe-IT assets, matching by serial number.
- `inventory owner` compares the Intune primary user of each device with the Snipe-IT assignee, matching users by email. Unassigned assets are checked out to the Intune primary user when that user exists in Snipe-IT. Existing assignments are not replaced; mismatches, assignments without an email, and devices missing from Snipe-IT are reported.
- `inventory employee` finds active Entra ID users and creates missing Snipe-IT users, matching by email.
- `inventory check` reports active Entra ID users missing from Snipe-IT or without an assigned Snipe-IT asset. It also warns about Snipe-IT assets whose serial number is not found in Intune, unless their status label is "Server mode"; those assets are set to the "Not In Intune" status label, which must exist in Snipe-IT.

Run a command with `--help` for CLI options. The config file defaults to `config.toml`; override it with `--config PATH`.

## Configuration

Copy `config.example.toml` to `config.toml` and fill in the credentials and Snipe-IT IDs. `config.toml` is ignored by Git because it contains secrets.

```toml
[azure]
tenant_id = "YOUR_TENANT_ID"
client_id = "YOUR_APP_CLIENT_ID"
client_secret = "YOUR_APP_CLIENT_SECRET"
employee_group_id = "YOUR_EMPLOYEE_GROUP_ID"

[snipe_it]
url = "https://snipe.example.com"
api_token = "YOUR_SNIPE_IT_API_TOKEN"

[defaults]
model_id = 1
ready_to_deploy_status = "Ready to Deploy"
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

Snipe-IT requires an API token with permission to read and create users and assets and to check out assets. `model_id` is an existing Snipe-IT model ID used for newly created assets. `ready_to_deploy_status` is the name of a deployable Snipe-IT status label, used both for newly created assets and when checking out an asset. Asset tags are set to the Intune device ID (UUID) and the asset name to the Intune device name. Existing assets are matched on serial number, or on asset tag = Intune device ID when the device has no serial number.

## Build

```sh
cargo build --release
./target/release/inventory devices
```
