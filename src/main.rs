use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use rand::Rng;
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
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
    #[serde(default, rename = "deviceName")]
    device_name: Option<String>,
    #[serde(default, rename = "serialNumber")]
    serial_number: Option<String>,
    #[serde(default, rename = "operatingSystem")]
    operating_system: Option<String>,
    #[serde(default, deserialize_with = "empty_string_as_none", rename = "userPrincipalName")]
    user_principal_email: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct SnipeUser {
    id: Option<u64>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct SnipeDevice {
    id: u64,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    asset_tag: Option<String>,
    #[serde(default)]
    serial: Option<String>,
    #[serde(default)]
    assigned_to: Option<SnipeUser>,
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
    #[serde(default = "default_ready_to_deploy_status_id")]
    ready_to_deploy_status_id: u64,
    #[serde(default = "default_assigned_status_id")]
    assigned_status_id: u64,
    #[serde(default = "default_asset_tag_prefix")]
    asset_tag_prefix: String,
}

fn default_asset_tag_prefix() -> String {
    "INTUNE-".to_owned()
}

fn default_ready_to_deploy_status_id() -> u64 {
    2
}

fn default_assigned_status_id() -> u64 {
    4
}

fn is_supported_os(device: &IntuneDevice) -> bool {
    let operating_system = device.operating_system.as_deref().unwrap_or_default();
    ["Windows", "Linux", "macOS"]
        .iter()
        .any(|supported| operating_system.eq_ignore_ascii_case(supported))
}

fn is_serial_number_present(device: &IntuneDevice) -> bool {
    device
        .serial_number
        .as_deref()
        .unwrap_or_default()
        .trim()
        .len() > 0
}

struct App {
    agent: Agent,
    config: Config,
    graph_token: String,
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
        })
    }

    fn get_snipe_devices(&self) -> Result<Vec<SnipeDevice>> {
        let snipe_hardware = self.snipe_request("GET", "hardware", None)?;
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
            "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=deviceName,serialNumber,operatingSystem,userPrincipalName,userDisplayName",
        )?;
        let devices = devices_json
            .iter()
            .filter_map(|v| serde_json::from_value(v.clone()).ok())
            .collect();

        Ok(devices)
    }

    fn create_device_in_snipe(&self, device: &IntuneDevice, serial: &str) -> Result<()> {
        let name = device
            .device_name
            .as_deref()
            .unwrap_or_else(|| serial);
        let asset_tag = format!("{}{}", self.config.defaults.asset_tag_prefix, serial);
        let payload = json!({
            "name": name,
            "asset_tag": asset_tag,
            "serial": serial,
            "model_id": self.config.defaults.model_id,
            "status_id": self.config.defaults.ready_to_deploy_status_id,
        });
        self.snipe_request("POST", "hardware", Some(&payload))?;
        println!("Created asset {asset_tag}");
        Ok(())
    }

    fn assign_device_in_snipe(&self, device_id: u64, device_name: &str, user: &SnipeUser, intune_email: &str) -> Result<UserCheckStatus> {
        if let Some(snipe_user_id) = user.id {
            let payload = json!({
                "assigned_to": snipe_user_id,
                "status_id": self.config.defaults.assigned_status_id,
            });
            match self.snipe_request("PATCH", &format!("hardware/{}", device_id), Some(&payload)) {
                Ok(_) => {
                    if let Some(snipe_name) = &user.name {
                        println!("✓ Updated {} assignment to '{}' ({})", device_name, snipe_name, intune_email);
                    } else {
                        println!("✓ Updated {} assignment to '{}'", device_name, intune_email);
                    }
                    Ok(UserCheckStatus::CorrectlyAssigned)
                }
                Err(_) => {
                    eprintln!("⚠️  Failed to update {} assignment from Intune user '{}'", device_name, intune_email);
                    Ok(UserCheckStatus::UserMismatch)
                }
            }
        } else {
            eprintln!("⚠️  Could not parse Snipe-IT user ID for Intune user '{}'", intune_email);
            Ok(UserCheckStatus::UserMismatch)
        }
    }

    fn sync_devices(&self) -> Result<()> {
        let devices = self.get_intune_devices()?;

        let snipe_devices = self.get_snipe_devices()?;
        
        let mut created = 0;
        let mut existing = 0;
        let mut skipped = 0;
        let mut user_mismatch = 0;
        let mut correctly_assigned = 0;

        for device in devices {

            /* Skip devices that are not running a supported operating system */
            if !is_supported_os(&device) {
                continue;
            }

            if !is_serial_number_present(&device) {
                let device_name = device.device_name.as_deref().unwrap_or("unnamed device");
                eprintln!("Skipping {}: no serial number", device_name);
                skipped += 1;
                continue;
            }

            let serial = device
                .serial_number
                .as_deref()
                .unwrap_or_default()
                .trim()
                .to_owned();

            // Look for device in Snipe-IT by normalized serial
            let normalized_input = normalize_serial(&serial);
            let existing_snipe_device = snipe_devices.iter().find(|row| {
                row.serial
                    .as_ref()
                    .map(|s| normalize_serial(s))
                    == Some(normalized_input.clone())
            });

            if let Some(snipe_dev) = existing_snipe_device {
                // Update asset name if not set and device name is available in Intune
                if (snipe_dev.name.is_none() || snipe_dev.name.as_deref() == Some("")) 
                    && device.device_name.is_some() 
                    && device.device_name.as_deref() != Some("") 
                {
                    if let Some(device_name) = &device.device_name {
                        let update_payload = json!({
                            "name": device_name,
                        });
                        match self.snipe_request("PATCH", &format!("hardware/{}", snipe_dev.id), Some(&update_payload)) {
                            Ok(_) => { 
                                println!("Updated asset name for {} to '{}'", snipe_dev.asset_tag.as_deref().unwrap_or("unknown"), device_name);
                            },
                            Err(e) => eprintln!("Failed to update asset name for {}: {}", snipe_dev.asset_tag.as_deref().unwrap_or("unknown"), e),
                        }
                    }
                }
                
                // Check if primary user from Intune matches assigned user in Snipe-IT
                match self.check_device_user_mismatch(snipe_dev, &device) {
                    Ok(status) => {
                        match status {
                            UserCheckStatus::CorrectlyAssigned => correctly_assigned += 1,
                            UserCheckStatus::UserMismatch => user_mismatch += 1,
                        }
                    }
                    Err(e) => eprintln!("Error checking device: {}", e),
                }
                existing += 1;
                continue;
            }

            self.create_device_in_snipe(&device, &serial)?;
            created += 1;
        }

        println!("Devices: {created} created, {existing} already present, {skipped} skipped");
        if existing > 0 {
            println!("  - {} correctly assigned", correctly_assigned);
            if user_mismatch > 0 {
                println!("  - {} have user mismatch (assigned ≠ checked out)", user_mismatch);
            }
        }
        Ok(())
    }

    fn check_device_user_mismatch(&self, snipe_device: &SnipeDevice, intune_device: &IntuneDevice) -> Result<UserCheckStatus> {
        let device_name = snipe_device
            .name
            .as_ref()
            .or(snipe_device.asset_tag.as_ref())
            .cloned()
            .unwrap_or_else(|| format!("ID {}", snipe_device.id));
        
        // Get primary user email from Intune (userPrincipalName is the user's email)
        let intune_primary_user_email = intune_device.user_principal_email.as_deref();
        
        // Get assigned user from Snipe-IT
        let snipe_assigned_user = snipe_device.assigned_to.as_ref();
        let snipe_assigned_email = snipe_assigned_user.and_then(|u| u.email.as_deref());
        let snipe_assigned_id: Option<u64> = snipe_assigned_user.and_then(|u| u.id);
        let snipe_assigned_name = snipe_assigned_user.and_then(|u| u.name.as_deref());
        
        match (intune_primary_user_email, snipe_assigned_email, snipe_assigned_id, snipe_assigned_name) {
            // Both have users and emails match
            (Some(intune_email), Some(snipe_email), _, Some(snipe_name)) 
                if intune_email.to_lowercase() == snipe_email.to_lowercase() => {
                println!("✓ {} is correctly assigned to '{}' ({})", device_name, snipe_name, snipe_email);
                Ok(UserCheckStatus::CorrectlyAssigned)
            }
            // Intune has user but Snipe-IT is empty - update Snipe-IT
            (Some(intune_email), None, _, _) => {
                // Look up user in Snipe-IT by email
                match self.snipe_user_by_email(intune_email)? {
                    Some(user) => {
                        self.assign_device_in_snipe(snipe_device.id, &device_name, &user, intune_email)
                    }
                    None => {
                        eprintln!("⚠️  Intune user '{}' not found in Snipe-IT for device {}", intune_email, device_name);
                        Ok(UserCheckStatus::UserMismatch)
                    }
                }
            }
            // Both have users but emails don't match - alert
            (Some(intune_email), Some(snipe_email), _, Some(snipe_name)) 
                if intune_email.to_lowercase() != snipe_email.to_lowercase() => {
                eprintln!("⚠️  User mismatch for {}: Intune user '{}', Snipe-IT assigned '{}' ({})", 
                    device_name, intune_email, snipe_name, snipe_email);
                Ok(UserCheckStatus::UserMismatch)
            }
            // Snipe-IT has user but Intune doesn't
            (None, Some(snipe_email), _, Some(snipe_name)) => {
                println!("✓ {} is assigned to '{}' ({})", device_name, snipe_name, snipe_email);
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
                    let user_id = user.id
                        .ok_or_else(|| anyhow!("Snipe-IT user has no numeric id"))?;
                    let (first_name, last_name) = employee_names(&employee);
                    let update_payload = json!({
                        "first_name": first_name,
                        "last_name": last_name,
                        "email": email,
                    });
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
            let payload = json!({
                "username": username,
                "first_name": first_name,
                "last_name": last_name,
                "email": email,
                "password": password,
                "password_confirmation": password,
                "activated": false,
            });
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
            let user_id = user.id
                .ok_or_else(|| anyhow!("Snipe-IT employee {email} has no numeric id"))?;
            let assets = self.snipe_request("GET", &format!("users/{user_id}/assets"), None)?;
            let rows = assets["rows"].as_array().cloned().unwrap_or_default();
            if rows.is_empty() {
                println!(
                    "No device assigned: {} ({email})",
                    display_employee(&employee)
                );
                without_device += 1;
            }
        }

        println!(
            "Check complete: {missing_employee} employees missing from Snipe-IT, {without_device} without a device"
        );
        Ok(())
    }

    fn normalise_serials(&self) -> Result<()> {
        let hardware = self.snipe_request("GET", "hardware", None)?;
        let rows: Vec<SnipeDevice> = hardware["rows"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter_map(|v| serde_json::from_value(v.clone()).ok())
                    .collect()
            })
            .unwrap_or_default();
        let mut updated = 0;
        let mut skipped = 0;

        for device in rows {
            if let Some(current_serial) = &device.serial {
                let trimmed = current_serial.trim();
                if trimmed.is_empty() {
                    skipped += 1;
                    continue;
                }

                let normalized = normalize_serial(trimmed);
                if normalized != trimmed {
                    let device_name = device
                        .name
                        .as_ref()
                        .cloned()
                        .unwrap_or_else(|| format!("ID {}", device.id));
                    let payload = json!({
                        "serial": normalized,
                    });
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
        let hardware = self.snipe_request("GET", "hardware", None)?;
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
        let payload = json!({
            "purchase_date": start_date,
        });
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
        let payload = json!({
            "productId": serial
        });

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
        let payload = json!({
            "serialNumber": serial,
            "machineType": machine_type,
            "country": "lu",
            "language": "en"
        });

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
            .and_then(|rows| {
                rows.iter()
                    .find(|row| text(row, "email").as_deref() == Some(email))
            })
            .and_then(|row| serde_json::from_value(row.clone()).ok());
        Ok(found)
    }

    fn snipe_request(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        let segments: Vec<&str> = path.split('/').collect();
        let url = self.snipe_url(&segments)?;
        let request = self.snipe_agent_request(method, url.as_str());
        send_json(request, body).with_context(|| format!("Snipe-IT {method} {path} request failed"))
    }

    fn snipe_get_url(&self, url: &str) -> Result<Value> {
        send_json(self.snipe_agent_request("GET", url), None).context("Snipe-IT request failed")
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

fn send_json(request: Request, body: Option<&Value>) -> Result<Value> {
    let response = match body {
        Some(body) => request.send_json(body),
        None => request.call(),
    }
    .map_err(|error| anyhow!("{error}"))?;
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
