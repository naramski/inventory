use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use rand::Rng;
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;
use ureq::{Agent, Request};
use url::Url;

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
    status_id: u64,
    #[serde(default = "default_asset_tag_prefix")]
    asset_tag_prefix: String,
}

fn default_asset_tag_prefix() -> String {
    "INTUNE-".to_owned()
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

    fn sync_devices(&self) -> Result<()> {
        let devices = self.graph_collection(
            "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=deviceName,serialNumber,operatingSystem",
        )?;
        let mut created = 0;
        let mut existing = 0;
        let mut skipped = 0;

        for device in devices {
            let operating_system = text(&device, "operatingSystem").unwrap_or_default();
            if !["Windows", "Linux", "macOS"]
                .iter()
                .any(|supported| operating_system.eq_ignore_ascii_case(supported))
            {
                continue;
            }

            let serial = text(&device, "serialNumber")
                .unwrap_or_default()
                .trim()
                .to_owned();
            if serial.is_empty() {
                eprintln!("Skipping {}: no serial number", display_device(&device));
                skipped += 1;
                continue;
            }

            if self.snipe_hardware_by_serial(&serial)?.is_some() {
                existing += 1;
                continue;
            }

            let name = text(&device, "deviceName").unwrap_or_else(|| serial.clone());
            let asset_tag = format!("{}{}", self.config.defaults.asset_tag_prefix, serial);
            let payload = json!({
                "name": name,
                "asset_tag": asset_tag,
                "serial": serial,
                "model_id": self.config.defaults.model_id,
                "status_id": self.config.defaults.status_id,
            });
            self.snipe_request("POST", "hardware", Some(&payload))?;
            println!("Created asset {asset_tag}");
            created += 1;
        }

        println!("Devices: {created} created, {existing} already present, {skipped} skipped");
        Ok(())
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
                let user_email = text(&user, "email");
                if user_email.is_none() || user_email.as_deref() == Some("") {
                    let user_id = user["id"]
                        .as_u64()
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
            let user_id = user["id"]
                .as_u64()
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
        let rows = hardware["rows"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let mut updated = 0;
        let mut skipped = 0;

        for device in rows {
            let device_id = device["id"]
                .as_u64()
                .ok_or_else(|| anyhow!("Device has no numeric id"))?;
            
            if let Some(current_serial) = text(&device, "serial") {
                let trimmed = current_serial.trim();
                if trimmed.is_empty() {
                    skipped += 1;
                    continue;
                }

                let normalized = normalize_serial(trimmed);
                if normalized != trimmed {
                    let device_name = text(&device, "name").unwrap_or_else(|| format!("ID {device_id}"));
                    let payload = json!({
                        "serial": normalized,
                    });
                    self.snipe_request("PUT", &format!("hardware/{device_id}"), Some(&payload))?;
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

    fn snipe_user_by_email(&self, email: &str) -> Result<Option<Value>> {
        let username = username_from_email(email);
        let mut url = self.snipe_url(&["users"])?;
        url.query_pairs_mut().append_pair("search", &username);
        let result = self.snipe_get_url(url.as_str())?;
        let found = result["rows"]
            .as_array()
            .and_then(|rows| {
                rows.iter()
                    .find(|row| text(row, "username").as_deref() == Some(&username))
            })
            .cloned();
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

fn username_from_email(email: &str) -> String {
    email.split('@').next().unwrap_or("").to_owned()
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

fn display_device(device: &Value) -> String {
    text(device, "deviceName").unwrap_or_else(|| "unnamed device".to_owned())
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
