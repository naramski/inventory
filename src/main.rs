use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::cell::OnceCell;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use ureq::{Agent, Request};
use url::Url;

fn empty_string_as_none<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    Ok(value.and_then(|s| if s.trim().is_empty() { None } else { Some(s) }))
}

fn normalized_serial_or_none_if_empty<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    Ok(value
        .map(|s| normalize_serial(&s))
        .filter(|s| !s.is_empty()))
}

#[derive(Parser)]
#[command(
    name = "inventory",
    about = "Keep Microsoft Intune and Snipe-IT in sync"
)]
struct Cli {
    #[arg(short, long, global = true, default_value = "config.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Register Intune Windows, Linux, and macOS devices in Snipe-IT.
    Devices,
    /// Sync the Intune primary user with the assigned user in Snipe-IT.
    Owner,
    /// Register Microsoft Entra ID employees in Snipe-IT.
    Employees,
    /// Report employees who have no device assigned in Snipe-IT.
    Check,
    /// Normalize serial numbers in Snipe-IT (remove non-alphanumeric, uppercase).
    Normalise,
    /// Check Lenovo warranty information for devices.
    Lenovo,
}

#[derive(Debug, Clone, Copy)]
enum UserCheckStatus {
    CorrectlyAssigned,
    UserMismatch,
}

#[derive(Debug, Clone, Deserialize)]
struct IntuneDevice {
    id: String,
    #[serde(default, rename = "deviceName")]
    device_name: Option<String>,
    #[serde(default, deserialize_with = "normalized_serial_or_none_if_empty", rename = "serialNumber")]
    serial_number: Option<String>,
    #[serde(default, rename = "operatingSystem")]
    operating_system: Option<String>,
    #[serde(default, deserialize_with = "empty_string_as_none", rename = "userPrincipalName")]
    user_principal_email: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct SnipeUser {
    id: u64,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct SnipeStatusLabel {
    id: u64,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct SnipeDevice {
    id: u64,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    asset_tag: Option<String>,
    #[serde(default, deserialize_with = "normalized_serial_or_none_if_empty")]
    serial: Option<String>,
    #[serde(default)]
    assigned_to: Option<SnipeUser>,
    #[serde(default)]
    status_label: Option<SnipeStatusLabel>,
}

/// Body of `POST hardware`.
#[derive(Debug, Serialize)]
struct NewSnipeAsset<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    asset_tag: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    serial: Option<&'a str>,
    model_id: u64,
    status_id: u64,
}

/// Body of `PUT/PATCH hardware/{id}`: only the fields set are sent.
#[derive(Debug, Default, Serialize)]
struct SnipeAssetUpdate<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    status_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    serial: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purchase_date: Option<&'a str>,
}

/// Body of `POST hardware/{id}/checkout`.
#[derive(Debug, Serialize)]
struct SnipeCheckout {
    checkout_to_type: &'static str,
    assigned_user: u64,
    status_id: u64,
}

/// Body of `PUT users/{id}`.
#[derive(Debug, Serialize)]
struct SnipeUserUpdate<'a> {
    first_name: &'a str,
    last_name: &'a str,
    email: &'a str,
}

/// Body of `POST users`.
#[derive(Debug, Serialize)]
struct NewSnipeUser<'a> {
    username: &'a str,
    first_name: &'a str,
    last_name: &'a str,
    email: &'a str,
    password: &'a str,
    password_confirmation: &'a str,
    activated: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LenovoProductQuery<'a> {
    product_id: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LenovoIbaseQuery<'a> {
    serial_number: &'a str,
    machine_type: &'a str,
    country: &'a str,
    language: &'a str,
}

impl SnipeDevice {
    /// Name, else asset tag, else ID (empty values are skipped)
    fn display_name(&self) -> String {
        [self.name.as_deref(), self.asset_tag.as_deref()]
            .into_iter()
            .flatten()
            .map(str::trim)
            .find(|s| !s.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("ID {}", self.id))
    }
    fn match_asset_tag(&self, asset_tag: &str) -> bool {
        self.asset_tag
            .as_deref()
            .map(|t| t.trim().eq_ignore_ascii_case(asset_tag.trim()))
            .unwrap_or(false)
    }
}

const SERVER_MODE_STATUS: &str = "Server mode";
const NOT_IN_INTUNE_STATUS: &str = "Not in Intune";

fn has_status(device: &SnipeDevice, status: &str) -> bool {
    device
        .status_label
        .as_ref()
        .and_then(|label| label.name.as_deref())
        .is_some_and(|name| name.trim().eq_ignore_ascii_case(status))
}

fn is_server_mode(device: &SnipeDevice) -> bool {
    has_status(device, SERVER_MODE_STATUS)
}

/// Snipe-IT asset matching an Intune device: by serial number (normalized on
/// deserialization), or by asset tag = Intune device ID when there is no serial.
fn find_snipe_device<'a>(snipe_devices: &'a [SnipeDevice], device: &IntuneDevice) -> Option<&'a SnipeDevice> {
    match device.serial_number.as_deref() {
        Some(serial) => snipe_devices.iter().find(|d| d.serial.as_deref() == Some(serial)),
        None => snipe_devices.iter().find(|d| d.match_asset_tag(&device.id)),
    }
}

/// Snipe-IT devices with a serial number that no Intune device reports.
fn snipe_devices_missing_from_intune<'a>(
    snipe_devices: &'a [SnipeDevice],
    intune_devices: &[IntuneDevice],
) -> Vec<&'a SnipeDevice> {
    let intune_serials: HashSet<String> = intune_devices
        .iter()
        .filter_map(|d| d.serial_number.as_deref())
        .map(normalize_serial)
        .filter(|s| !s.is_empty())
        .collect();
    snipe_devices
        .iter()
        .filter(|d| {
            let serial = normalize_serial(d.serial.as_deref().unwrap_or_default());
            !serial.is_empty() && !intune_serials.contains(&serial)
        })
        .collect()
}

#[derive(Deserialize)]
struct Config {
    azure: AzureConfig,
    snipe_it: SnipeConfig,
    defaults: DefaultsConfig,
}

#[derive(Deserialize)]
struct AzureConfig {
    tenant_id: String,
    client_id: String,
    client_secret: String,
    employee_group_id: String,
}

#[derive(Deserialize)]
struct SnipeConfig {
    url: String,
    api_token: String,
}

#[derive(Deserialize)]
struct DefaultsConfig {
    model_id: u64,
    #[serde(default = "default_ready_to_deploy_status")]
    ready_to_deploy_status: String,
}

fn default_ready_to_deploy_status() -> String {
    "Ready to Deploy".to_owned()
}

fn is_supported_os(device: &IntuneDevice) -> bool {
    let operating_system = device.operating_system.as_deref().unwrap_or_default();
    let supported_os = ["Windows", "Linux", "macOS", "Linux (fedora)", "Linux (ubuntu)"];
    supported_os
        .iter()
        .any(|supported| operating_system.eq_ignore_ascii_case(supported))
}

struct App {
    agent: Agent,
    config: Config,
    graph_token: String,
    status_labels: OnceCell<Vec<SnipeStatusLabel>>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config_text = fs::read_to_string(&cli.config)
        .with_context(|| format!("could not read {}", cli.config.display()))?;
    let config: Config = toml::from_str(&config_text)
        .with_context(|| format!("could not parse {}", cli.config.display()))?;
    let app = App::connect(config)?;

    match cli.command {
        Command::Devices => app.sync_devices(),
        Command::Owner => app.sync_owners(),
        Command::Employees => app.sync_employees(),
        Command::Check => app.check_assignments(),
        Command::Normalise => app.normalise_serials(),
        Command::Lenovo => app.check_lenovo_warranty(),
    }
}

impl App {
    fn connect(config: Config) -> Result<Self> {
        let agent = ureq::AgentBuilder::new().build();
        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            config.azure.tenant_id
        );
        let response = agent
            .post(&token_url)
            .send_form(&[
                ("client_id", config.azure.client_id.as_str()),
                ("client_secret", config.azure.client_secret.as_str()),
                ("scope", "https://graph.microsoft.com/.default"),
                ("grant_type", "client_credentials"),
            ])
            .context("could not authenticate with Microsoft Entra ID")?;
        let token: Value = response
            .into_json()
            .context("Microsoft identity response was not valid JSON")?;
        let graph_token = token["access_token"]
            .as_str()
            .ok_or_else(|| anyhow!("Microsoft identity response did not contain an access token"))?
            .to_owned();

        Ok(Self {
            agent,
            config,
            graph_token,
            status_labels: OnceCell::new(),
        })
    }

    fn get_snipe_devices(&self) -> Result<Vec<SnipeDevice>> {
        let snipe_hardware = self.snipe_get("hardware")?;
        let snipe_devices = snipe_hardware["rows"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter_map(|v| serde_json::from_value(v.clone()).ok())
                    .collect()
            })
            .unwrap_or_default();
        Ok(snipe_devices)
    }

    fn get_intune_devices(&self) -> Result<Vec<IntuneDevice>> {
        let devices_json = self.graph_collection(
            "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,deviceName,serialNumber,operatingSystem,userPrincipalName,userDisplayName",
        )?;
        let devices = devices_json
            .iter()
            .filter_map(|v| serde_json::from_value(v.clone()).ok())
            .collect();

        Ok(devices)
    }

    fn create_device_in_snipe(&self, device: &IntuneDevice) -> Result<()> {
        // Asset tag = Intune device ID (UUID); asset name = Intune device name
        let asset_tag = &device.id;
        let status_id = self.snipe_status_id(&self.config.defaults.ready_to_deploy_status)?;
        let payload = NewSnipeAsset {
            name: device.device_name.as_deref().map(str::trim).filter(|name| !name.is_empty()),
            asset_tag,
            serial: device.serial_number.as_deref(),
            model_id: self.config.defaults.model_id,
            status_id,
        };
        let response = self.snipe_request("POST", "hardware", Some(&payload))?;
        if response["status"].as_str() != Some("success") {
            return Err(anyhow!("Snipe-IT asset creation for {asset_tag} failed: {}", response["messages"]));
        }
        Ok(())
    }

    fn snipe_asset_reference(&self, device: &SnipeDevice) -> String {
        let base = self.config.snipe_it.url.trim_end_matches('/');
        format!(
            "asset tag '{}', serial '{}', {}/hardware/{}",
            device.asset_tag.as_deref().unwrap_or("none"),
            device.serial.as_deref().unwrap_or("none"),
            base,
            device.id
        )
    }

    fn assign_device_in_snipe(&self, device: &SnipeDevice, user: &SnipeUser, intune_email: &str) -> Result<UserCheckStatus> {
        let device_id = device.id;
        let device_name = device.display_name();
        let device_name = device_name.as_str();
        let status_id = self.snipe_status_id(&self.config.defaults.ready_to_deploy_status)?;
        let payload = SnipeCheckout {
            checkout_to_type: "user",
            assigned_user: user.id,
            status_id,
        };
        let result = self.snipe_request("POST", &format!("hardware/{}/checkout", device_id), Some(&payload))
            .and_then(|response| {
                if response["status"].as_str() == Some("success") {
                    Ok(())
                } else {
                    Err(anyhow!("Snipe-IT checkout returned an unexpected response: {}", response))
                }
            });
        match result {
            Ok(()) => {
                if let Some(snipe_name) = &user.name {
                    println!("✓ Updated {} assignment to '{}' ({})", device_name, snipe_name, intune_email);
                } else {
                    println!("✓ Updated {} assignment to '{}'", device_name, intune_email);
                }
                Ok(UserCheckStatus::CorrectlyAssigned)
            }
            Err(e) => {
                eprintln!("⚠️  Failed to update {} assignment from Intune user '{}': {:#}", device_name, intune_email, e);
                eprintln!("    → {}", self.snipe_asset_reference(device));
                Ok(UserCheckStatus::UserMismatch)
            }
        }
    }

    fn sync_devices(&self) -> Result<()> {
        let devices = self.get_intune_devices()?;

        let snipe_devices = self.get_snipe_devices()?;
        
        let mut created = 0;
        let mut existing = 0;
        let mut skipped = 0;

        for device in devices {
            if !is_supported_os(&device) {
                println!("⚠️  Unsupported OS for device {:?} - {:?} : {:?}", device.serial_number, device.device_name, device.operating_system);
                skipped += 1;
                continue;
            }

            if find_snipe_device(&snipe_devices, &device).is_some() {
                existing += 1;
            } else {
                self.create_device_in_snipe(&device)?;
                created += 1;
            }
        }

        println!("Devices: {created} created, {existing} already present, {skipped} skipped");
        Ok(())
    }

    /// Compare the Intune primary user with the Snipe-IT assignee and check out unassigned assets.
    fn sync_owners(&self) -> Result<()> {
        let devices = self.get_intune_devices()?;
        let snipe_devices = self.get_snipe_devices()?;

        let mut correctly_assigned = 0;
        let mut user_mismatch = 0;
        let mut missing = 0;
        let mut skipped = 0;

        for device in devices {
            if !is_supported_os(&device) {
                skipped += 1;
                continue;
            }

            let Some(snipe_dev) = find_snipe_device(&snipe_devices, &device) else {
                eprintln!("⚠️  {:?} (serial {:?}) is not in Snipe-IT, run `inventory devices` first",
                    device.device_name, device.serial_number);
                missing += 1;
                continue;
            };

            match self.check_device_user_mismatch(snipe_dev, &device) {
                Ok(UserCheckStatus::CorrectlyAssigned) => correctly_assigned += 1,
                Ok(UserCheckStatus::UserMismatch) => user_mismatch += 1,
                Err(e) => {
                    eprintln!("Error checking device: {:#}", e);
                    user_mismatch += 1;
                }
            }
        }

        println!("Owners: {correctly_assigned} correctly assigned, {user_mismatch} mismatched, {missing} not in Snipe-IT, {skipped} skipped");
        Ok(())
    }

    fn check_device_user_mismatch(&self, snipe_device: &SnipeDevice, intune_device: &IntuneDevice) -> Result<UserCheckStatus> {
        let device_name = snipe_device.display_name();
        
        // Get primary user email from Intune (userPrincipalName is the user's email)
        let intune_primary_user_email = intune_device.user_principal_email.as_deref();
        
        // Get assigned user from Snipe-IT
        let snipe_assigned_user = snipe_device.assigned_to.as_ref();
        let snipe_assigned_email = snipe_assigned_user
            .and_then(|u| u.email.as_deref())
            .map(str::trim)
            .filter(|email| !email.is_empty());
        let snipe_assigned_name = snipe_assigned_user.and_then(|u| u.name.as_deref());
        
        match (intune_primary_user_email, snipe_assigned_user, snipe_assigned_email) {
            // Both have users and emails match
            (Some(intune_email), Some(_), Some(snipe_email))
                if intune_email.eq_ignore_ascii_case(snipe_email) => {
                if let Some(snipe_name) = snipe_assigned_name {
                    println!("✓ {} is correctly assigned to '{}' ({})", device_name, snipe_name, snipe_email);
                } else {
                    println!("✓ {} is correctly assigned to '{}'", device_name, snipe_email);
                }
                Ok(UserCheckStatus::CorrectlyAssigned)
            }
            // Intune has user but Snipe-IT is empty - update Snipe-IT
            (Some(intune_email), None, _) => {
                // Look up user in Snipe-IT by email
                match self.snipe_user_by_email(intune_email)? {
                    Some(user) => {
                        self.assign_device_in_snipe(snipe_device, &user, intune_email)
                    }
                    None => {
                        eprintln!("⚠️  Intune user '{}' not found in Snipe-IT for device {}", intune_email, device_name);
                        Ok(UserCheckStatus::UserMismatch)
                    }
                }
            }
            // Both have users but emails don't match - alert
            (Some(intune_email), Some(_), Some(snipe_email)) => {
                eprintln!("⚠️  User mismatch for {}: Intune user '{}', Snipe-IT assigned '{}' ({})",
                    device_name, intune_email, snipe_assigned_name.unwrap_or("unknown"), snipe_email);
                Ok(UserCheckStatus::UserMismatch)
            }
            (Some(intune_email), Some(_), None) => {
                eprintln!("⚠️  Cannot compare assignment for {}: Intune user '{}', Snipe-IT assignee '{}' has no email",
                    device_name, intune_email, snipe_assigned_name.unwrap_or("unknown"));
                Ok(UserCheckStatus::UserMismatch)
            }
            // Snipe-IT has user but Intune doesn't
            (None, Some(_), Some(snipe_email)) => {
                println!("✓ {} is assigned to '{}' ({})", device_name, snipe_assigned_name.unwrap_or("unknown"), snipe_email);
                Ok(UserCheckStatus::CorrectlyAssigned)
            }
            _ => Ok(UserCheckStatus::CorrectlyAssigned),
        }
    }

    fn sync_employees(&self) -> Result<()> {
        let group_id = &self.config.azure.employee_group_id;
        let employees = self.graph_collection(
            &format!("https://graph.microsoft.com/v1.0/groups/{group_id}/members?$select=displayName,givenName,surname,mail,userPrincipalName,accountEnabled"),
        )?;
        let mut created = 0;
        let mut existing = 0;
        let mut updated = 0;
        let mut skipped = 0;

        for employee in employees {
            if employee["accountEnabled"].as_bool() != Some(true) {
                continue;
            }

            let email = text(&employee, "mail")
                .or_else(|| text(&employee, "userPrincipalName"))
                .unwrap_or_default();
            if email.is_empty() {
                eprintln!("Skipping {}: no email address", display_employee(&employee));
                skipped += 1;
                continue;
            }

            if let Some(user) = self.snipe_user_by_email(&email)? {
                if user.email.is_none() || user.email.as_deref() == Some("") {
                    let user_id = user.id;
                    let (first_name, last_name) = employee_names(&employee);
                    let update_payload = SnipeUserUpdate {
                        first_name: &first_name,
                        last_name: &last_name,
                        email: &email,
                    };
                    self.snipe_request("PUT", &format!("users/{user_id}"), Some(&update_payload))?;
                    println!("Updated email for employee {}", display_employee(&employee));
                    updated += 1;
                } else {
                    existing += 1;
                }
                continue;
            }

            let (first_name, last_name) = employee_names(&employee);
            let username = text(&employee, "userPrincipalName").unwrap_or_else(|| email.clone());
            let password = generate_random_password(16);
            let payload = NewSnipeUser {
                username: &username,
                first_name: &first_name,
                last_name: &last_name,
                email: &email,
                password: &password,
                password_confirmation: &password,
                activated: false,
            };
            self.snipe_request("POST", "users", Some(&payload))?;
            println!("Created employee {}", display_employee(&employee));
            created += 1;
        }

        println!("Employees: {created} created, {existing} already present, {updated} updated with email, {skipped} skipped");
        Ok(())
    }

    fn check_assignments(&self) -> Result<()> {
        let group_id = &self.config.azure.employee_group_id;
        let employees = self.graph_collection(
            &format!("https://graph.microsoft.com/v1.0/groups/{group_id}/members?$select=displayName,mail,userPrincipalName,accountEnabled"),
        )?;
        let mut missing_employee = 0;
        let mut without_device = 0;

        for employee in employees {
            if employee["accountEnabled"].as_bool() != Some(true) {
                continue;
            }

            let email = text(&employee, "mail")
                .or_else(|| text(&employee, "userPrincipalName"))
                .unwrap_or_default();
            if email.is_empty() {
                continue;
            }

            let Some(user) = self.snipe_user_by_email(&email)? else {
                println!(
                    "Missing Snipe-IT employee: {} ({email})",
                    display_employee(&employee)
                );
                missing_employee += 1;
                continue;
            };
            let user_id = user.id;
            let assets = self.snipe_get(&format!("users/{user_id}/assets"))?;
            let rows = assets["rows"].as_array().cloned().unwrap_or_default();
            if rows.is_empty() {
                println!(
                    "No device assigned: {} ({email})",
                    display_employee(&employee)
                );
                without_device += 1;
            }
        }

        let intune_devices = self.get_intune_devices()?;
        let snipe_devices = self.get_snipe_devices()?;
        let mut server_mode = 0;
        let mut missing_from_intune = 0;
        let mut marked = 0;
        for device in snipe_devices_missing_from_intune(&snipe_devices, &intune_devices) {
            if is_server_mode(device) {
                server_mode += 1;
                continue;
            }
            let device_name = device
                .name
                .as_deref()
                .filter(|n| !n.trim().is_empty())
                .or(device.asset_tag.as_deref())
                .map(str::to_owned)
                .unwrap_or_else(|| format!("ID {}", device.id));
            let status = device
                .status_label
                .as_ref()
                .and_then(|label| label.name.as_deref())
                .unwrap_or("unknown");
            let serial = device.serial.as_deref().unwrap_or_default();
            missing_from_intune += 1;
            if has_status(device, NOT_IN_INTUNE_STATUS) {
                eprintln!("⚠️  {device_name} (serial {serial}) is in Snipe-IT but not in Intune, already '{NOT_IN_INTUNE_STATUS}'");
                continue;
            }
            eprintln!("⚠️  {device_name} (serial {serial}) is in Snipe-IT but not in Intune, status '{status}'");
            match self.mark_not_in_intune(device.id) {
                Ok(_) => {
                    println!("  → {device_name} status changed from '{status}' to '{NOT_IN_INTUNE_STATUS}'");
                    marked += 1;
                }
                Err(e) => eprintln!("  → Failed to set {device_name} to '{NOT_IN_INTUNE_STATUS}': {e:#}"),
            }
        }

        println!(
            "Check complete: {missing_employee} employees missing from Snipe-IT, {without_device} without a device, {missing_from_intune} devices missing from Intune ({marked} marked '{NOT_IN_INTUNE_STATUS}', {server_mode} in '{SERVER_MODE_STATUS}' ignored)"
        );
        Ok(())
    }

    /// Set only the status of a Snipe-IT asset to "Not In Intune".
    fn mark_not_in_intune(&self, device_id: u64) -> Result<()> {
        let status_id = self.snipe_status_id(NOT_IN_INTUNE_STATUS)?;
        self.snipe_request("PATCH", &format!("hardware/{device_id}"), Some(&SnipeAssetUpdate { status_id: Some(status_id), ..Default::default() }))?;
        Ok(())
    }

    fn normalise_serials(&self) -> Result<()> {
        let hardware = self.snipe_get("hardware")?;
        // SnipeDevice.serial is normalized on deserialization: keep the raw value to detect changes.
        let rows: Vec<(SnipeDevice, Option<String>)> = hardware["rows"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter_map(|v| {
                        let raw = v["serial"].as_str().map(str::to_owned);
                        serde_json::from_value(v.clone()).ok().map(|d| (d, raw))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut updated = 0;
        let mut skipped = 0;

        for (device, raw_serial) in rows {
            if let (Some(normalized), Some(raw)) = (&device.serial, &raw_serial) {
                let trimmed = raw.trim();
                if normalized != trimmed {
                    let device_name = device
                        .name
                        .as_ref()
                        .cloned()
                        .unwrap_or_else(|| format!("ID {}", device.id));
                    let payload = SnipeAssetUpdate {
                        serial: Some(normalized),
                        ..Default::default()
                    };
                    self.snipe_request("PUT", &format!("hardware/{}", device.id), Some(&payload))?;
                    println!("Updated {device_name}: {trimmed} → {normalized}");
                    updated += 1;
                }
            } else {
                skipped += 1;
            }
        }

        println!("Serial numbers: {updated} normalized, {skipped} skipped");
        Ok(())
    }

    fn check_lenovo_warranty(&self) -> Result<()> {
        let hardware = self.snipe_get("hardware")?;
        let rows: Vec<SnipeDevice> = hardware["rows"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter_map(|v| serde_json::from_value(v.clone()).ok())
                    .collect()
            })
            .unwrap_or_default();
        let mut checked = 0;
        let mut updated = 0;
        let mut failed = 0;

        for device in rows {
            if let Some(serial) = &device.serial {
                let device_name = device
                    .name
                    .as_ref()
                    .cloned()
                    .unwrap_or_else(|| serial.clone());
                match self.get_lenovo_warranty_info(serial) {
                    Ok(warranty_info) => {
                        if let Some((start_date, product_name)) = warranty_info {
                            println!("{}: {} - Warranty start date: {}", device_name, product_name, start_date);
                            
                            if let Err(e) = self.update_snipe_purchase_date(device.id, &start_date) {
                                eprintln!("Failed to update purchase date for {}: {}", device_name, e);
                                failed += 1;
                            } else {
                                updated += 1;
                            }
                        } else {
                            println!("{}: No warranty information found", device_name);
                        }
                        checked += 1;
                    }
                    Err(e) => {
                        eprintln!("{}: Error checking warranty - {}", device_name, e);
                        failed += 1;
                    }
                }
            }
        }

        println!("Lenovo warranty check: {checked} checked, {updated} purchase dates updated, {failed} failed");
        Ok(())
    }

    fn update_snipe_purchase_date(&self, device_id: u64, start_date: &str) -> Result<()> {
        let payload = SnipeAssetUpdate {
            purchase_date: Some(start_date),
            ..Default::default()
        };
        self.snipe_request("PUT", &format!("hardware/{device_id}"), Some(&payload))?;
        Ok(())
    }

    fn get_lenovo_warranty_info(&self, serial: &str) -> Result<Option<(String, String)>> {
        let normalized_serial = normalize_serial(serial).to_uppercase();
        
        let product_info = self.get_lenovo_product_info(&normalized_serial)?;
        if product_info.is_empty() {
            return Ok(None);
        }

        let product_id = &product_info[0];
        let machine_type = self.extract_machine_type(product_id)?;
        
        let warranty_info = self.get_lenovo_ibase_info(&normalized_serial, &machine_type)?;
        Ok(warranty_info)
    }

    fn get_lenovo_product_info(&self, serial: &str) -> Result<Vec<Value>> {
        let payload = LenovoProductQuery { product_id: serial };

        let url = "https://pcsupport.lenovo.com/lu/en/api/v4/mse/v2/getproducts";
        let request = self.agent
            .post(url)
            .set("Content-Type", "application/json")
            .set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");

        let response = send_json(request, Some(&payload))
            .context("Failed to get Lenovo product info")?;

        if let Some(arr) = response.as_array() {
            Ok(arr.clone())
        } else {
            Ok(Vec::new())
        }
    }

    fn extract_machine_type(&self, product: &Value) -> Result<String> {
        let full_id = product["Id"]
            .as_str()
            .ok_or_else(|| anyhow!("Product has no Id field"))?;
        
        let parts: Vec<&str> = full_id.split('/').collect();
        if parts.len() >= 4 {
            Ok(parts[3].to_owned())
        } else {
            Err(anyhow!("Cannot extract machine type from product id"))
        }
    }

    fn get_lenovo_ibase_info(&self, serial: &str, machine_type: &str) -> Result<Option<(String, String)>> {
        let payload = LenovoIbaseQuery {
            serial_number: serial,
            machine_type,
            country: "lu",
            language: "en",
        };

        let url = "https://pcsupport.lenovo.com/lu/en/api/v4/upsell/redport/getIbaseInfo";
        let request = self.agent
            .post(url)
            .set("Content-Type", "application/json")
            .set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");

        let response = send_json(request, Some(&payload))
            .context("Failed to get Lenovo warranty info")?;

        if let Some(data) = response.get("data").and_then(|d| d.get("machineInfo")) {
            if let Some(start_date) = data.get("baseStartDate").and_then(|d| d.as_str()) {
                if let Some(product_name) = data.get("productName").and_then(|n| n.as_str()) {
                    return Ok(Some((start_date.to_owned(), product_name.to_owned())));
                }
            }
        }

        Ok(None)
    }

    fn graph_collection(&self, first_url: &str) -> Result<Vec<Value>> {
        let mut next = Some(first_url.to_owned());
        let mut rows = Vec::new();
        while let Some(url) = next {
            let response = self
                .agent
                .get(&url)
                .set("Authorization", &format!("Bearer {}", self.graph_token))
                .call()
                .context("Microsoft Graph request failed")?;
            let page: Value = response
                .into_json()
                .context("Microsoft Graph response was not valid JSON")?;
            rows.extend(page["value"].as_array().cloned().ok_or_else(|| {
                anyhow!("Microsoft Graph response did not contain a value array")
            })?);
            next = page["@odata.nextLink"].as_str().map(str::to_owned);
        }
        Ok(rows)
    }

    #[allow(dead_code)]
    fn snipe_hardware_by_serial(&self, serial: &str) -> Result<Option<Value>> {
        let mut url = self.snipe_url(&["hardware"])?;
        url.query_pairs_mut().append_pair("search", serial);
        let result = self.snipe_get_url(url.as_str())?;
        let normalized_input = normalize_serial(serial);
        let found = result["rows"]
            .as_array()
            .and_then(|rows| {
                rows.iter()
                    .find(|row| {
                        text(row, "serial")
                            .map(|s| normalize_serial(&s))
                            .as_deref()
                            == Some(&normalized_input)
                    })
            })
            .cloned();
        Ok(found)
    }

    fn snipe_user_by_email(&self, email: &str) -> Result<Option<SnipeUser>> {
        let mut url = self.snipe_url(&["users"])?;
        url.query_pairs_mut().append_pair("search", email);
        let result = self.snipe_get_url(url.as_str())?;
        let found = result["rows"]
            .as_array()
            .ok_or_else(|| anyhow!("Snipe-IT user search response did not contain a rows array"))?
            .iter()
            .find(|row| text(row, "email").is_some_and(|candidate| candidate.eq_ignore_ascii_case(email)));
        found
            .map(|row| serde_json::from_value(row.clone()).context("invalid Snipe-IT user"))
            .transpose()
    }

    /// Resolve a Snipe-IT status label name to its ID (labels are fetched once).
    fn snipe_status_id(&self, name: &str) -> Result<u64> {
        if self.status_labels.get().is_none() {
            let response = self.snipe_get("statuslabels")?;
            let labels: Vec<SnipeStatusLabel> = serde_json::from_value(response["rows"].clone())
                .context("Snipe-IT status labels response did not contain a valid rows array")?;
            let _ = self.status_labels.set(labels);
        }
        self.status_labels
            .get()
            .into_iter()
            .flatten()
            .find(|label| label.name.as_deref().is_some_and(|n| n.trim().eq_ignore_ascii_case(name.trim())))
            .map(|label| label.id)
            .ok_or_else(|| anyhow!("Snipe-IT status label '{name}' not found"))
    }

    fn snipe_request<B: Serialize + ?Sized>(&self, method: &str, path: &str, body: Option<&B>) -> Result<Value> {
        let segments: Vec<&str> = path.split('/').collect();
        let url = self.snipe_url(&segments)?;
        let request = self.snipe_agent_request(method, url.as_str());
        send_json(request, body).with_context(|| format!("Snipe-IT {method} {path} request failed"))
    }

    fn snipe_get(&self, path: &str) -> Result<Value> {
        self.snipe_request("GET", path, None::<&()>)
    }

    fn snipe_get_url(&self, url: &str) -> Result<Value> {
        send_json(self.snipe_agent_request("GET", url), None::<&()>).context("Snipe-IT request failed")
    }

    fn snipe_agent_request(&self, method: &str, url: &str) -> Request {
        self.agent
            .request(method, url)
            .set(
                "Authorization",
                &format!("Bearer {}", self.config.snipe_it.api_token),
            )
            .set("Accept", "application/json")
    }

    fn snipe_url(&self, segments: &[&str]) -> Result<Url> {
        let base = self.config.snipe_it.url.trim_end_matches('/');
        let mut url = Url::parse(&format!("{base}/api/v1"))
            .context("snipe_it.url must be a valid absolute URL")?;
        url.path_segments_mut()
            .map_err(|_| anyhow!("snipe_it.url cannot be a base URL"))?
            .extend(segments.iter().copied());
        Ok(url)
    }
}

fn normalize_serial(serial: &str) -> String {
    serial
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect::<String>()
        .to_uppercase()
}

fn send_json<B: Serialize + ?Sized>(request: Request, body: Option<&B>) -> Result<Value> {
    let response = match body {
        Some(body) => request.send_json(body),
        None => request.call(),
    }
    .map_err(|error| match error {
        ureq::Error::Status(status, response) => {
            let details = response.into_json::<Value>().ok()
                .and_then(|value| value.get("messages").or_else(|| value.get("message")).cloned());
            match details {
                Some(details) => anyhow!("HTTP {status}: {details}"),
                None => anyhow!("HTTP {status}"),
            }
        }
        error => anyhow!("{error}"),
    })?;
    let value: Value = response
        .into_json()
        .context("Snipe-IT response was not valid JSON")?;
    if value["status"].as_str() == Some("error") {
        return Err(anyhow!("Snipe-IT API error: {}", value["messages"]));
    }
    Ok(value)
}

fn text(value: &Value, key: &str) -> Option<String> {
    value[key]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn generate_random_password(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

fn display_employee(employee: &Value) -> String {
    text(employee, "displayName").unwrap_or_else(|| "unnamed employee".to_owned())
}

fn employee_names(employee: &Value) -> (String, String) {
    let first = text(employee, "givenName");
    let last = text(employee, "surname");
    if first.is_some() || last.is_some() {
        return (first.unwrap_or_default(), last.unwrap_or_default());
    }

    let mut parts = display_employee(employee)
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if parts.len() > 1 {
        let last = parts.pop().unwrap_or_default();
        (parts.join(" "), last)
    } else {
        (
            parts.pop().unwrap_or_else(|| "Unknown".to_owned()),
            String::new(),
        )
    }
}

    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_json::json;
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::TcpListener;
        use std::thread;

        fn test_app(url: String) -> App {
            App {
                agent: ureq::AgentBuilder::new().build(),
                config: Config {
                    azure: AzureConfig {
                        tenant_id: String::new(),
                        client_id: String::new(),
                        client_secret: String::new(),
                        employee_group_id: String::new(),
                    },
                    snipe_it: SnipeConfig { url, api_token: "test".into() },
                    defaults: DefaultsConfig {
                        model_id: 1,
                        ready_to_deploy_status: "Ready to Deploy".into(),
                    },
                },
                graph_token: String::new(),
                status_labels: OnceCell::from(vec![
                    SnipeStatusLabel { id: 2, name: Some("Ready to Deploy".into()) },
                    SnipeStatusLabel { id: 4, name: Some("Deployed".into()) },
                    SnipeStatusLabel { id: 9, name: Some("Not In Intune".into()) },
                ]),
            }
        }

        fn mock_snipe(responses: Vec<(&'static str, &'static str)>) -> (App, thread::JoinHandle<Vec<(String, Value)>>) {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let app = test_app(format!("http://{}", listener.local_addr().unwrap()));
            let handle = thread::spawn(move || {
                let mut requests = Vec::new();
                for (status, response) in responses {
                    let (mut stream, _) = listener.accept().unwrap();
                    stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
                    let mut reader = BufReader::new(&stream);
                    let mut request_line = String::new();
                    reader.read_line(&mut request_line).unwrap();
                    let mut length = 0;
                    loop {
                        let mut line = String::new();
                        reader.read_line(&mut line).unwrap();
                        if line == "\r\n" {
                            break;
                        }
                        if let Some((name, value)) = line.split_once(':') {
                            if name.eq_ignore_ascii_case("content-length") {
                                length = value.trim().parse().unwrap();
                            }
                        }
                    }
                    let mut body = vec![0; length];
                    reader.read_exact(&mut body).unwrap();
                    let body = if body.is_empty() { Value::Null } else { serde_json::from_slice(&body).unwrap() };
                    requests.push((request_line.trim().to_owned(), body));
                    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).unwrap();
                }
                requests
            });
            (app, handle)
        }

        fn device(assigned_to: Option<SnipeUser>) -> SnipeDevice {
            SnipeDevice { id: 17, name: Some("Laptop".into()), asset_tag: None, serial: Some("serial".into()), assigned_to, status_label: None }
        }

        #[test]
        fn marks_device_not_in_intune_with_status_only() {
            let (app, server) = mock_snipe(vec![("200 OK", r#"{"status":"success"}"#)]);
            app.mark_not_in_intune(17).unwrap();
            let requests = server.join().unwrap();
            assert_eq!(requests[0].0, "PATCH /api/v1/hardware/17 HTTP/1.1");
            assert_eq!(requests[0].1, json!({"status_id": 9}));
        }

        #[test]
        fn finds_snipe_devices_missing_from_intune_and_detects_server_mode() {
            let snipe: Vec<SnipeDevice> = serde_json::from_value(json!([
                {"id": 1, "serial": "AB-12", "status_label": {"id": 4, "name": "Deployed"}},
                {"id": 2, "serial": "zz 99", "status_label": {"id": 5, "name": "server mode"}},
                {"id": 3, "serial": "CD34", "status_label": {"id": 4, "name": "Deployed"}},
                {"id": 4, "serial": "", "status_label": {"id": 4, "name": "Deployed"}},
            ])).unwrap();
            let mut intune = intune_device();
            intune.serial_number = Some("ab12".into());
            let missing = snipe_devices_missing_from_intune(&snipe, &[intune]);
            assert_eq!(missing.iter().map(|d| d.id).collect::<Vec<_>>(), vec![2, 3]);
            assert!(is_server_mode(missing[0]));
            assert!(!is_server_mode(missing[1]));
        }

        fn intune_device() -> IntuneDevice {
            IntuneDevice {
                id: "00000000-0000-0000-0000-000000000001".into(),
                device_name: Some("Laptop".into()),
                serial_number: Some("serial".into()),
                operating_system: Some("Windows".into()),
                user_principal_email: Some("user@example.com".into()),
            }
        }

        #[test]
        fn checks_out_unassigned_device_to_email_matched_user() {
            let (app, server) = mock_snipe(vec![
                ("200 OK", r#"{"rows":[{"id":42,"name":"User","email":"USER@example.com"}]}"#),
                ("200 OK", r#"{"status":"success","messages":"Asset checked out"}"#),
            ]);
            assert!(matches!(app.check_device_user_mismatch(&device(None), &intune_device()).unwrap(), UserCheckStatus::CorrectlyAssigned));
            let requests = server.join().unwrap();
            assert!(requests[0].0.starts_with("GET /api/v1/users?search="));
            assert_eq!(requests[1].0, "POST /api/v1/hardware/17/checkout HTTP/1.1");
            assert_eq!(requests[1].1, json!({"checkout_to_type":"user","assigned_user":42,"status_id":2}));
        }

        #[test]
        fn reports_checkout_failures_and_unexpected_responses_as_mismatches() {
            for (status, response) in [
                ("200 OK", r#"{"status":"error","messages":{"status_id":["Invalid status"]}}"#),
                ("422 Unprocessable Entity", r#"{"message":"Cannot checkout"}"#),
                ("200 OK", r#"{"rows":[]}"#),
            ] {
                let (app, server) = mock_snipe(vec![(status, response)]);
                let user = SnipeUser { id: 42, name: None, email: Some("user@example.com".into()) };
                assert!(matches!(app.assign_device_in_snipe(&device(None), &user, "user@example.com").unwrap(), UserCheckStatus::UserMismatch));
                server.join().unwrap();
            }
        }

        #[test]
        fn does_not_checkout_existing_assignment_without_email() {
            let app = test_app("http://127.0.0.1:9".into());
            let user = SnipeUser { id: 9, name: Some("Existing assignee".into()), email: None };
            assert!(matches!(app.check_device_user_mismatch(&device(Some(user)), &intune_device()).unwrap(), UserCheckStatus::UserMismatch));
        }

        #[test]
        fn compares_assigned_users_by_email_even_without_names() {
            let app = test_app("http://127.0.0.1:9".into());
            let user = SnipeUser { id: 9, name: None, email: Some("USER@example.com".into()) };
            assert!(matches!(app.check_device_user_mismatch(&device(Some(user)), &intune_device()).unwrap(), UserCheckStatus::CorrectlyAssigned));
            let other = SnipeUser { id: 10, name: None, email: Some("other@example.com".into()) };
            assert!(matches!(app.check_device_user_mismatch(&device(Some(other)), &intune_device()).unwrap(), UserCheckStatus::UserMismatch));
        }

        #[test]
        fn resolves_status_label_ids_from_api_once() {
            let (mut app, server) = mock_snipe(vec![
                ("200 OK", r#"{"rows":[{"id":2,"name":"Ready to Deploy"},{"id":7,"name":"Deployed"}]}"#),
            ]);
            app.status_labels = OnceCell::new();
            assert_eq!(app.snipe_status_id("deployed").unwrap(), 7);
            assert_eq!(app.snipe_status_id("Ready to Deploy").unwrap(), 2);
            assert!(app.snipe_status_id("Missing").is_err());
            let requests = server.join().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].0, "GET /api/v1/statuslabels HTTP/1.1");
        }

        #[test]
        fn includes_api_error_details() {
            for (status, response, expected) in [
                ("200 OK", r#"{"status":"error","messages":{"status_id":["Invalid status"]}}"#, "Invalid status"),
                ("422 Unprocessable Entity", r#"{"message":"Cannot checkout"}"#, "Cannot checkout"),
            ] {
                let (app, server) = mock_snipe(vec![(status, response)]);
                let error = app.snipe_request("POST", "hardware/17/checkout", Some(&json!({}))).unwrap_err();
                assert!(format!("{error:#}").contains(expected));
                server.join().unwrap();
            }
        }
    }
