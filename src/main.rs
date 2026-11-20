use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::cell::{OnceCell, RefCell};
use std::collections::{HashMap, HashSet};
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
    /// Set the Snipe-IT purchase date from the Lenovo warranty start date.
    Lenovo {
        /// Update every device with a serial number, not only those without a purchase date.
        #[arg(long)]
        all: bool,
    },
    /// Report laptops at end of life or to replace soon ("Server mode" excepted).
    Replace,
    /// Licence cashflow from this month to December of next year.
    Budget {
        /// Number of months shown side by side.
        #[arg(long, default_value_t = 3)]
        columns: usize,
    },
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
    /// Read only: never sent back to Snipe-IT.
    #[serde(default)]
    notes: Option<String>,
}

const KEYBOARD_NOTE_PREFIX: &str = "Keyboard:";

impl SnipeUser {
    /// Keyboard layout requested in the notes (`Keyboard: XXXX` line).
    fn get_keyboard_layout(&self) -> Option<&str> {
        self.notes
            .as_deref()?
            .split(['\n', '\r'])
            .flat_map(|line| line.split("<br>"))
            .find_map(|line| line.trim().strip_prefix(KEYBOARD_NOTE_PREFIX))
            .map(str::trim)
            .filter(|layout| !layout.is_empty())
    }
}

/// Custom field value returned by the Snipe-IT API.
#[derive(Debug, Clone, Deserialize)]
struct SnipeCustomField {
    #[serde(default)]
    value: Option<String>,
}

/// Snipe-IT returns `[]` instead of `{}` when an asset has no custom fields.
fn custom_fields_or_empty<'de, D>(deserializer: D) -> std::result::Result<HashMap<String, SnipeCustomField>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    Ok(serde_json::from_value(value).unwrap_or_default())
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
    #[serde(default)]
    purchase_date: Option<SnipeDate>,
    #[serde(default)]
    asset_eol_date: Option<SnipeDate>,
    #[serde(default)]
    model: Option<SnipeNamedRef>,
    #[serde(default)]
    category: Option<SnipeNamedRef>,
    #[serde(default, deserialize_with = "custom_fields_or_empty")]
    custom_fields: HashMap<String, SnipeCustomField>,
}

/// `{"id": ..., "name": ...}` reference (model, category, manufacturer...).
#[derive(Debug, Clone, Deserialize)]
struct SnipeNamedRef {
    id: u64,
    #[serde(default)]
    name: Option<String>,
}

/// Body of `POST models`.
#[derive(Debug, Serialize)]
struct NewSnipeModel<'a> {
    name: &'a str,
    category_id: u64,
    manufacturer_id: u64,
    fieldset_id: u64,
    depreciation_id: u64,
}

/// Date object returned by the Snipe-IT API (`{"date": ..., "formatted": ...}`).
#[derive(Debug, Clone, Deserialize)]
struct SnipeDate {
    #[serde(default)]
    date: Option<String>,
}

impl SnipeDevice {
    fn has_purchase_date(&self) -> bool {
        self.purchase_date
            .as_ref()
            .and_then(|d| d.date.as_deref())
            .is_some_and(|d| !d.trim().is_empty())
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    asset_eol_date: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model_id: Option<u64>,
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

/// Item returned by Lenovo `getproducts`.
#[derive(Debug, Deserialize)]
struct LenovoProductInfo {
    /// e.g. `LAPTOPS-AND-NETBOOKS/THINKPAD-T-SERIES-LAPTOPS/THINKPAD-T14-GEN-3-TYPE-21AH-21AJ/21AH/21AHCTO1WW/<serial>`
    #[serde(rename = "Id")]
    id: String,
}

impl LenovoProductInfo {
    fn machine_type(&self) -> Result<&str> {
        self.id
            .split('/')
            .nth(3)
            .ok_or_else(|| anyhow!("Cannot extract machine type from product id {}", self.id))
    }
}

/// Response of Lenovo `getIbaseInfo`.
#[derive(Debug, Default, Deserialize)]
struct LenovoIbaseResponse {
    #[serde(default)]
    data: Option<LenovoIbaseData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LenovoIbaseData {
    #[serde(default)]
    machine_info: Option<LenovoWarrantyInfo>,
}

/// `data.machineInfo` of Lenovo `getIbaseInfo`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LenovoWarrantyInfo {
    product_name: String,
    base_start_date: String,
}

impl LenovoWarrantyInfo {
    /// `product_name` up to the first `(`, trimmed.
    fn model_name(&self) -> Option<&str> {
        let name = self.product_name.split('(').next().unwrap_or_default().trim();
        (!name.is_empty()).then_some(name)
    }
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
    fn is_laptop(&self) -> bool {
        self.category
            .as_ref()
            .and_then(|c| c.name.as_deref())
            .is_some_and(|name| name.trim().eq_ignore_ascii_case(LAPTOP_CATEGORY))
    }
    /// Lowercase email of the assigned user, if any.
    fn assignee_email(&self) -> Option<String> {
        self.assigned_to
            .as_ref()
            .and_then(|u| u.email.as_deref())
            .map(|e| e.trim().to_lowercase())
            .filter(|e| !e.is_empty())
    }
    /// End-of-life date as `YYYY-MM-DD`, if set.
    fn eol_date(&self) -> Option<&str> {
        self.asset_eol_date
            .as_ref()
            .and_then(|d| d.date.as_deref())
            .and_then(|d| d.trim().get(..10))
    }
    /// Value of the "Keyboard" custom field, if set.
    fn keyboard_layout(&self) -> Option<&str> {
        self.custom_fields
            .iter()
            .find(|(name, _)| name.trim().eq_ignore_ascii_case(KEYBOARD_FIELD))
            .and_then(|(_, field)| field.value.as_deref())
            .map(str::trim)
            .filter(|layout| !layout.is_empty())
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
const LAPTOP_CATEGORY: &str = "Laptop";
const KEYBOARD_FIELD: &str = "Keyboard";

/// Snipe-IT laptops grouped by assignee email (lowercase).
fn laptops_by_assignee(snipe_devices: &[SnipeDevice]) -> HashMap<String, Vec<&SnipeDevice>> {
    let mut laptops: HashMap<String, Vec<&SnipeDevice>> = HashMap::new();
    for device in snipe_devices.iter().filter(|d| d.is_laptop()) {
        if let Some(email) = device.assignee_email() {
            laptops.entry(email).or_default().push(device);
        }
    }
    laptops
}

/// Snipe-IT laptops not checked out to anyone (ignoring "Server mode" assets).
fn unassigned_laptops(snipe_devices: &[SnipeDevice]) -> Vec<&SnipeDevice> {
    snipe_devices
        .iter()
        .filter(|d| d.is_laptop() && d.assigned_to.is_none() && !is_server_mode(d))
        .collect()
}

/// Assigned laptops (not in "Server mode") to replace, based on their end-of-life date.
struct ReplacementReport<'a> {
    /// End of life on or before today.
    end_of_life: Vec<&'a SnipeDevice>,
    /// End of life after today and within the next 90 days.
    within_three_months: Vec<&'a SnipeDevice>,
    /// End of life during the current year.
    current_year: usize,
    /// End of life during the next year.
    next_year: usize,
    /// Laptops without an end-of-life date.
    without_eol: usize,
}

const REPLACEMENT_NOTICE_DAYS: i64 = 90;

fn replacement_report<'a>(snipe_devices: &'a [SnipeDevice], today: &str) -> Result<ReplacementReport<'a>> {
    let horizon = add_days(today, REPLACEMENT_NOTICE_DAYS)?;
    let year: i32 = today[..4].parse()?;
    let (current_year, next_year) = (year.to_string(), (year + 1).to_string());
    let mut report = ReplacementReport {
        end_of_life: Vec::new(),
        within_three_months: Vec::new(),
        current_year: 0,
        next_year: 0,
        without_eol: 0,
    };
    let mut laptops: Vec<&SnipeDevice> = snipe_devices.iter().filter(|d| d.is_laptop() && d.assigned_to.is_some() && !is_server_mode(d)).collect();
    laptops.sort_by(|a, b| a.eol_date().cmp(&b.eol_date()));
    for device in laptops {
        let Some(eol) = device.eol_date() else {
            report.without_eol += 1;
            continue;
        };
        if eol <= today {
            report.end_of_life.push(device);
        } else if eol <= horizon.as_str() {
            report.within_three_months.push(device);
        }
        if eol.starts_with(&current_year) {
            report.current_year += 1;
        } else if eol.starts_with(&next_year) {
            report.next_year += 1;
        }
    }
    Ok(report)
}

/// Snipe-IT depreciation names giving the licence billing period.
const MONTHLY_LICENCE: &str = "Monthly Licence";
const ANNUAL_LICENCE: &str = "Annual Licence";

/// Snipe-IT returns amounts as formatted strings ("2,200.00" or "2.200,00") or numbers.
fn amount_or_none<'de, D>(deserializer: D) -> std::result::Result<Option<f64>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) => parse_amount(&s),
        _ => None,
    })
}

/// Parse an amount, the last `.` or `,` followed by 1 or 2 digits being the decimal separator.
fn parse_amount(text: &str) -> Option<f64> {
    let digits: String = text.chars().filter(|c| c.is_ascii_digit() || matches!(c, '.' | ',' | '-')).collect();
    let normalized = match digits.rfind(['.', ',']) {
        Some(pos) if (1..=2).contains(&(digits.len() - pos - 1)) => {
            format!("{}.{}", digits[..pos].replace(['.', ','], ""), &digits[pos + 1..])
        }
        _ => digits.replace(['.', ','], ""),
    };
    normalized.parse().ok()
}

#[derive(Debug, Clone, Deserialize)]
struct SnipeLicense {
    id: u64,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, deserialize_with = "amount_or_none")]
    purchase_cost: Option<f64>,
    #[serde(default, deserialize_with = "amount_or_none")]
    purchase_cost_numeric: Option<f64>,
    #[serde(default)]
    depreciation: Option<SnipeNamedRef>,
    #[serde(default)]
    purchase_date: Option<SnipeDate>,
    #[serde(default)]
    expiration_date: Option<SnipeDate>,
    #[serde(default)]
    termination_date: Option<SnipeDate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Billing {
    Monthly,
    Annual,
}

impl SnipeLicense {
    fn display_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| format!("licence #{}", self.id))
    }

    fn cost(&self) -> Option<f64> {
        self.purchase_cost_numeric.or(self.purchase_cost)
    }

    fn depreciation_name(&self) -> Option<&str> {
        self.depreciation.as_ref().and_then(|d| d.name.as_deref()).map(str::trim)
    }

    /// Billing period from the depreciation name ("Licence" or "License").
    fn billing(&self) -> Option<Billing> {
        let name = self.depreciation_name()?.replace("License", "Licence");
        if name.eq_ignore_ascii_case(MONTHLY_LICENCE) {
            Some(Billing::Monthly)
        } else if name.eq_ignore_ascii_case(ANNUAL_LICENCE) {
            Some(Billing::Annual)
        } else {
            None
        }
    }
}

/// A month, as `year * 12 + (month - 1)` so that months compare and increment simply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Month(i32);

impl Month {
    fn new(year: i32, month: u32) -> Self {
        Month(year * 12 + month as i32 - 1)
    }

    /// Month of a `YYYY-MM-DD` date.
    fn of(date: &str) -> Option<Self> {
        let year = date.get(..4)?.parse().ok()?;
        let month: u32 = date.get(5..7)?.parse().ok()?;
        (1..=12).contains(&month).then(|| Month::new(year, month))
    }

    fn of_snipe(date: Option<&SnipeDate>) -> Option<Self> {
        date.and_then(|d| d.date.as_deref()).and_then(Month::of)
    }

    fn year(self) -> i32 {
        self.0.div_euclid(12)
    }

    /// 1 to 12.
    fn number(self) -> u32 {
        self.0.rem_euclid(12) as u32 + 1
    }

    fn next(self) -> Self {
        Month(self.0 + 1)
    }
}

impl std::fmt::Display for Month {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const NAMES: [&str; 12] = [
            "January", "February", "March", "April", "May", "June",
            "July", "August", "September", "October", "November", "December",
        ];
        write!(f, "{} {}", NAMES[self.number() as usize - 1], self.year())
    }
}

struct BudgetLine {
    name: String,
    amount: f64,
}

struct BudgetMonth {
    month: Month,
    lines: Vec<BudgetLine>,
}

impl BudgetMonth {
    fn total(&self) -> f64 {
        self.lines.iter().fold(0.0, |total, l| total + l.amount)
    }
}

struct Cashflow {
    months: Vec<BudgetMonth>,
    warnings: Vec<String>,
}

/// Licence payments from the month of `today` to December of the next year.
/// Monthly licences are due every month from their purchase date; annual licences
/// in the month of their expiration date (renewal), else of their purchase date.
/// Nothing is due after the termination date.
fn license_cashflow(licenses: &[SnipeLicense], today: &str) -> Result<Cashflow> {
    let first = Month::of(today).ok_or_else(|| anyhow!("invalid date '{today}'"))?;
    let last = Month::new(first.year() + 1, 12);
    let mut months = Vec::new();
    let mut month = first;
    while month <= last {
        months.push(BudgetMonth { month, lines: Vec::new() });
        month = month.next();
    }

    let mut warnings = Vec::new();
    for license in licenses {
        let name = license.display_name();
        let Some(billing) = license.billing() else {
            match license.depreciation_name() {
                Some(value) => warnings.push(format!("{name}: depreciation '{value}' is not recognized")),
                None => warnings.push(format!("{name}: no depreciation, expected '{MONTHLY_LICENCE}' or '{ANNUAL_LICENCE}'")),
            }
            continue;
        };
        let Some(amount) = license.cost() else {
            warnings.push(format!("{name}: no purchase cost"));
            continue;
        };
        let start = Month::of_snipe(license.purchase_date.as_ref());
        let end = Month::of_snipe(license.termination_date.as_ref());
        let due_month = match billing {
            Billing::Monthly => None,
            Billing::Annual => match Month::of_snipe(license.expiration_date.as_ref()).or(start) {
                Some(due) => Some(due.number()),
                None => {
                    warnings.push(format!("{name}: annual licence without expiration or purchase date"));
                    continue;
                }
            },
        };
        for budget_month in &mut months {
            let month = budget_month.month;
            let active = start.is_none_or(|s| s <= month) && end.is_none_or(|e| month <= e);
            if active && due_month.is_none_or(|due| due == month.number()) {
                budget_month.lines.push(BudgetLine { name: name.clone(), amount });
            }
        }
    }
    for month in &mut months {
        month.lines.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    }
    Ok(Cashflow { months, warnings })
}

const LAPTOP_REPLACEMENT: &str = "Laptop replacement";
const LATE_REPLACEMENT: &str = "Late replacement";

/// Add the replacement of assigned laptops ("Server mode" excepted) at `price` each:
/// in their end-of-life month, or in the first month when it has already passed.
/// Laptops of the same month are grouped on one line.
fn add_laptop_replacements(cashflow: &mut Cashflow, devices: &[SnipeDevice], price: f64) {
    let Some(first) = cashflow.months.first().map(|m| m.month) else {
        return;
    };
    let mut counts: HashMap<(Month, &str), usize> = HashMap::new();
    let mut without_eol = 0;
    for device in devices.iter().filter(|d| d.is_laptop() && d.assigned_to.is_some() && !is_server_mode(d)) {
        match device.eol_date().and_then(Month::of) {
            Some(eol) if eol < first => *counts.entry((first, LATE_REPLACEMENT)).or_default() += 1,
            Some(eol) => *counts.entry((eol, LAPTOP_REPLACEMENT)).or_default() += 1,
            None => without_eol += 1,
        }
    }
    if without_eol > 0 {
        cashflow.warnings.push(format!("{without_eol} assigned laptops have no end-of-life date, not budgeted"));
    }
    for month in &mut cashflow.months {
        for name in [LATE_REPLACEMENT, LAPTOP_REPLACEMENT] {
            if let Some(&count) = counts.get(&(month.month, name)) {
                month.lines.push(BudgetLine { name: format!("{name} ({count})"), amount: count as f64 * price });
            }
        }
        month.lines.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    }
}

/// `2200 €`, or `19.99 €` when there are cents.
fn format_euros(amount: f64) -> String {
    if amount.fract().abs() < 0.005 {
        format!("{amount:.0} €")
    } else {
        format!("{amount:.2} €")
    }
}

/// Lines of one month block: title, underline, licences, total.
fn month_block(month: &BudgetMonth) -> Vec<String> {
    let title = month.month.to_string();
    let mut lines = vec![title.clone(), "=".repeat(title.chars().count())];
    lines.extend(month.lines.iter().map(|l| format!("* {}: {}", l.name, format_euros(l.amount))));
    lines.push(format!("Total: {}", format_euros(month.total())));
    lines
}

/// Month blocks laid out side by side, `columns` per row.
fn render_cashflow(months: &[BudgetMonth], columns: usize) -> String {
    const GAP: usize = 4;
    let blocks: Vec<Vec<String>> = months.iter().map(month_block).collect();
    let width = blocks.iter().flatten().map(|l| l.chars().count()).max().unwrap_or(0);
    let mut out = String::new();
    for row in blocks.chunks(columns.max(1)) {
        let height = row.iter().map(Vec::len).max().unwrap_or(0);
        for i in 0..height {
            // The total goes on the last line of every block, so totals align.
            let cells: Vec<&str> = row
                .iter()
                .map(|block| {
                    if i == height - 1 {
                        block[block.len() - 1].as_str()
                    } else if i < block.len() - 1 {
                        block[i].as_str()
                    } else {
                        ""
                    }
                })
                .collect();
            let line = cells
                .iter()
                .map(|c| format!("{c:<width$}{}", " ".repeat(GAP)))
                .collect::<String>();
            out.push_str(line.trim_end());
            out.push('\n');
        }
        out.push('\n');
    }
    out
}

/// Amount represented by one cell of the bar chart.
const BAR_STEP: f64 = 1000.0;

/// Vertical ASCII bar chart of the monthly totals, one column per month and one
/// cell per started `BAR_STEP`, so that any amount due is visible.
fn render_bar_chart(months: &[BudgetMonth]) -> String {
    const NAMES: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let heights: Vec<usize> = months.iter().map(|m| (m.total().max(0.0) / BAR_STEP).ceil() as usize).collect();
    let max = heights.iter().copied().max().unwrap_or(0);
    let label_width = format!("{:.0}", max.max(1) as f64 * BAR_STEP).len();
    let mut out = String::new();
    for level in (1..=max).rev() {
        let mut line = format!("{:>label_width$.0} € |", level as f64 * BAR_STEP);
        for &height in &heights {
            line.push_str(if height >= level { " ###" } else { "    " });
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    let indent = " ".repeat(label_width + 3);
    out.push_str(&format!("{indent}+{}\n", "-".repeat(4 * months.len())));
    let names: String = months.iter().map(|m| format!(" {}", NAMES[m.month.number() as usize - 1])).collect();
    let years: String = months.iter().map(|m| format!(" {:>3}", format!("'{:02}", m.month.year() % 100))).collect();
    out.push_str(&format!("{indent} {names}\n{indent} {years}\n"));
    out
}

/// Sum of the monthly totals of a year.
fn year_total(months: &[BudgetMonth], year: i32) -> f64 {
    months.iter().filter(|m| m.month.year() == year).fold(0.0, |total, m| total + m.total())
}

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
/// deserialization), else by asset tag = Intune device ID.
fn find_snipe_device<'a>(snipe_devices: &'a [SnipeDevice], device: &IntuneDevice) -> Option<&'a SnipeDevice> {
    device
        .serial_number
        .as_deref()
        .and_then(|serial| snipe_devices.iter().find(|d| d.serial.as_deref() == Some(serial)))
        .or_else(|| snipe_devices.iter().find(|d| d.match_asset_tag(&device.id)))
}

/// Snipe-IT devices with a serial number that no Intune device reports,
/// neither by serial number nor by asset tag = Intune device ID.
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
            !serial.is_empty()
                && !intune_serials.contains(&serial)
                && !intune_devices.iter().any(|i| d.match_asset_tag(&i.id))
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
    /// Estimated price of a replacement laptop, in euros (budget).
    #[serde(default = "default_laptop_budget")]
    laptop_budget: f64,
}

fn default_ready_to_deploy_status() -> String {
    "Ready to Deploy".to_owned()
}

fn default_laptop_budget() -> f64 {
    1900.0
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
    /// Snipe-IT model IDs by lowercase name.
    model_ids: RefCell<HashMap<String, u64>>,
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
        Command::Lenovo { all } => app.check_lenovo_warranty(all),
        Command::Replace => app.report_replacements(),
        Command::Budget { columns } => app.report_budget(columns),
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
            model_ids: RefCell::new(HashMap::new()),
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

    /// Every Snipe-IT user (paginated).
    fn get_snipe_users(&self) -> Result<Vec<SnipeUser>> {
        const PAGE: usize = 500;
        let mut users = Vec::new();
        loop {
            let mut url = self.snipe_url(&["users"])?;
            url.query_pairs_mut()
                .append_pair("limit", &PAGE.to_string())
                .append_pair("offset", &users.len().to_string());
            let result = self.snipe_get_url(url.as_str())?;
            let rows = result["rows"]
                .as_array()
                .ok_or_else(|| anyhow!("Snipe-IT users response did not contain a rows array"))?;
            let count = rows.len();
            for row in rows {
                users.push(serde_json::from_value(row.clone()).context("invalid Snipe-IT user")?);
            }
            let total = result["total"].as_u64().unwrap_or(0) as usize;
            if count < PAGE || users.len() >= total {
                return Ok(users);
            }
        }
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
        let intune_devices = self.get_intune_devices()?;
        let snipe_devices = self.get_snipe_devices()?;
        let laptops = laptops_by_assignee(&snipe_devices);
        let mut missing_employee = 0;
        let mut without_laptop = 0;
        let mut several_laptops = 0;

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

            if self.snipe_user_by_email(&email)?.is_none() {
                println!(
                    "Missing Snipe-IT employee: {} ({email})",
                    display_employee(&employee)
                );
                missing_employee += 1;
                continue;
            }
            match laptops.get(&email.trim().to_lowercase()).map(Vec::as_slice).unwrap_or_default() {
                [] => {
                    eprintln!("⚠️  {} ({email}) has no laptop assigned", display_employee(&employee));
                    without_laptop += 1;
                }
                [_] => {}
                several => {
                    let names: Vec<String> = several.iter().map(|d| d.display_name()).collect();
                    eprintln!(
                        "⚠️  {} ({email}) has {} laptops assigned: {}",
                        display_employee(&employee),
                        several.len(),
                        names.join(", ")
                    );
                    several_laptops += 1;
                }
            }
        }

        let unassigned = unassigned_laptops(&snipe_devices);
        for device in &unassigned {
            let status = device
                .status_label
                .as_ref()
                .and_then(|label| label.name.as_deref())
                .unwrap_or("unknown");
            eprintln!("⚠️  Laptop {} is not assigned to anyone, status '{status}'", device.display_name());
        }

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
            "Check complete: {missing_employee} employees missing from Snipe-IT, {without_laptop} without a laptop, {several_laptops} with several laptops, {} unassigned laptops, {missing_from_intune} devices missing from Intune ({marked} marked '{NOT_IN_INTUNE_STATUS}', {server_mode} in '{SERVER_MODE_STATUS}' ignored)",
            unassigned.len()
        );
        Ok(())
    }

    fn report_replacements(&self) -> Result<()> {
        let snipe_devices = self.get_snipe_devices()?;
        let users: HashMap<u64, SnipeUser> = self.get_snipe_users()?.into_iter().map(|u| (u.id, u)).collect();
        let today = today();
        let report = replacement_report(&snipe_devices, &today)?;
        let line = |device: &SnipeDevice| {
            let user = device.assignee_email().unwrap_or_default();
            let requested = device
                .assigned_to
                .as_ref()
                .and_then(|u| users.get(&u.id))
                .and_then(SnipeUser::get_keyboard_layout)
                .unwrap_or("-");
            println!(
                "  {} | EOL {} | {user} | keyboard {} | requested {requested}",
                device.display_name(),
                device.eol_date().unwrap_or_default(),
                device.keyboard_layout().unwrap_or("-"),
            );
        };

        println!("Laptops at end of life ({}):", report.end_of_life.len());
        report.end_of_life.iter().for_each(|d| line(d));
        println!("Laptops to replace within {REPLACEMENT_NOTICE_DAYS} days ({}):", report.within_three_months.len());
        report.within_three_months.iter().for_each(|d| line(d));
        let year: i32 = today[..4].parse()?;
        println!("Laptops reaching end of life in {year}: {}", report.current_year);
        println!("Laptops reaching end of life in {}: {}", year + 1, report.next_year);
        if report.without_eol > 0 {
            eprintln!("⚠️  {} laptops have no end-of-life date", report.without_eol);
        }
        Ok(())
    }

    /// Every Snipe-IT licence (paginated).
    fn get_snipe_licenses(&self) -> Result<Vec<SnipeLicense>> {
        const PAGE: usize = 500;
        let mut licenses = Vec::new();
        loop {
            let mut url = self.snipe_url(&["licenses"])?;
            url.query_pairs_mut()
                .append_pair("limit", &PAGE.to_string())
                .append_pair("offset", &licenses.len().to_string());
            let result = self.snipe_get_url(url.as_str())?;
            let rows = result["rows"]
                .as_array()
                .ok_or_else(|| anyhow!("Snipe-IT licenses response did not contain a rows array"))?;
            let count = rows.len();
            for row in rows {
                licenses.push(serde_json::from_value(row.clone()).context("invalid Snipe-IT licence")?);
            }
            let total = result["total"].as_u64().unwrap_or(0) as usize;
            if count < PAGE || licenses.len() >= total {
                return Ok(licenses);
            }
        }
    }

    fn report_budget(&self, columns: usize) -> Result<()> {
        let licenses = self.get_snipe_licenses()?;
        let mut cashflow = license_cashflow(&licenses, &today())?;
        add_laptop_replacements(&mut cashflow, &self.get_snipe_devices()?, self.config.defaults.laptop_budget);
        for warning in &cashflow.warnings {
            eprintln!("⚠️  {warning}");
        }
        print!("{}", render_cashflow(&cashflow.months, columns));
        print!("{}", render_bar_chart(&cashflow.months));
        let year = cashflow.months.first().map_or(0, |m| m.month.year());
        println!();
        println!("Remaining committed for {year}: {}", format_euros(year_total(&cashflow.months, year)));
        println!("To commit for {}: {}", year + 1, format_euros(year_total(&cashflow.months, year + 1)));
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

    fn check_lenovo_warranty(&self, all: bool) -> Result<()> {
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
            if !all && device.has_purchase_date() {
                continue;
            }
            if let Some(serial) = &device.serial {
                let device_name = device
                    .name
                    .as_ref()
                    .cloned()
                    .unwrap_or_else(|| serial.clone());
                match self.get_lenovo_warranty_info(serial) {
                    Ok(warranty_info) => {
                        if let Some(warranty) = warranty_info {
                            println!(
                                "{}: {} - Warranty start date: {}",
                                device_name, warranty.product_name, warranty.base_start_date
                            );

                            if let Err(e) = self.update_snipe_from_lenovo(&device, &warranty) {
                                eprintln!("Failed to update {} from Lenovo: {}", device_name, e);
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

        println!("Lenovo warranty check: {checked} checked, {updated} assets updated, {failed} failed");
        Ok(())
    }

    /// Update purchase date and model from Lenovo data (only the changed fields).
    fn update_snipe_from_lenovo(&self, device: &SnipeDevice, warranty: &LenovoWarrantyInfo) -> Result<()> {
        let current_date = device.purchase_date.as_ref().and_then(|d| d.date.as_deref());
        let purchase_date = (current_date != Some(warranty.base_start_date.as_str()))
            .then_some(warranty.base_start_date.as_str());

        let eol_date = add_years(&warranty.base_start_date, LAPTOP_LIFETIME_YEARS)?;
        let current_eol = device.asset_eol_date.as_ref().and_then(|d| d.date.as_deref());
        let asset_eol_date = (current_eol != Some(eol_date.as_str())).then_some(eol_date.as_str());

        let model_id = match warranty.model_name() {
            Some(name) => Some(self.snipe_model_id(name)?),
            None => None,
        }
        .filter(|id| device.model.as_ref().map(|m| m.id) != Some(*id));

        if purchase_date.is_none() && asset_eol_date.is_none() && model_id.is_none() {
            return Ok(());
        }
        let payload = SnipeAssetUpdate {
            purchase_date,
            asset_eol_date,
            model_id,
            ..Default::default()
        };
        self.snipe_request("PUT", &format!("hardware/{}", device.id), Some(&payload))?;
        Ok(())
    }

    /// Find a Snipe-IT model by name, creating it if missing
    /// (category Laptop, manufacturer Lenovo, fieldset Laptop, depreciation Laptop Standard).
    fn snipe_model_id(&self, name: &str) -> Result<u64> {
        let key = name.to_lowercase();
        if let Some(id) = self.model_ids.borrow().get(&key) {
            return Ok(*id);
        }
        let id = match self.snipe_find_by_name("models", name)? {
            Some(model) => model.id,
            None => {
                let category = self
                    .snipe_find_by_name("categories", "Laptop")?
                    .ok_or_else(|| anyhow!("Snipe-IT category 'Laptop' not found"))?;
                let manufacturer = self
                    .snipe_find_by_name("manufacturers", "Lenovo")?
                    .ok_or_else(|| anyhow!("Snipe-IT manufacturer 'Lenovo' not found"))?;
                let fieldset = self
                    .snipe_find_by_name("fieldsets", "Laptop")?
                    .ok_or_else(|| anyhow!("Snipe-IT custom fieldset 'Laptop' not found"))?;
                let depreciation = self
                    .snipe_find_by_name("depreciations", "Laptop Standard")?
                    .ok_or_else(|| anyhow!("Snipe-IT depreciation 'Laptop Standard' not found"))?;
                let payload = NewSnipeModel {
                    name,
                    category_id: category.id,
                    manufacturer_id: manufacturer.id,
                    fieldset_id: fieldset.id,
                    depreciation_id: depreciation.id,
                };
                let response = self.snipe_request("POST", "models", Some(&payload))?;
                let created: SnipeNamedRef = serde_json::from_value(response["payload"].clone())
                    .context("Snipe-IT model creation response did not contain a payload")?;
                println!("Created Snipe-IT model '{name}'");
                created.id
            }
        };
        self.model_ids.borrow_mut().insert(key, id);
        Ok(id)
    }

    /// Search a Snipe-IT collection and return the row whose name matches exactly (case-insensitive).
    fn snipe_find_by_name(&self, collection: &str, name: &str) -> Result<Option<SnipeNamedRef>> {
        let mut url = self.snipe_url(&[collection])?;
        url.query_pairs_mut().append_pair("search", name);
        let result = self.snipe_get_url(url.as_str())?;
        let rows: Vec<SnipeNamedRef> = serde_json::from_value(result["rows"].clone())
            .with_context(|| format!("Snipe-IT {collection} search response did not contain a valid rows array"))?;
        Ok(rows
            .into_iter()
            .find(|row| row.name.as_deref().is_some_and(|n| n.trim().eq_ignore_ascii_case(name.trim()))))
    }

    fn get_lenovo_warranty_info(&self, serial: &str) -> Result<Option<LenovoWarrantyInfo>> {
        let normalized_serial = normalize_serial(serial).to_uppercase();

        let Some(product) = self.get_lenovo_product_info(&normalized_serial)? else {
            return Ok(None);
        };
        let machine_type = product.machine_type()?;

        self.get_lenovo_ibase_info(&normalized_serial, machine_type)
    }

    fn get_lenovo_product_info(&self, serial: &str) -> Result<Option<LenovoProductInfo>> {
        let payload = LenovoProductQuery { product_id: serial };

        let url = "https://pcsupport.lenovo.com/lu/en/api/v4/mse/v2/getproducts";
        let request = self.agent
            .post(url)
            .set("Content-Type", "application/json")
            .set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");

        let response = send_json(request, Some(&payload))
            .context("Failed to get Lenovo product info")?;

        let products: Vec<LenovoProductInfo> = if response.is_array() {
            serde_json::from_value(response).context("invalid Lenovo product info")?
        } else {
            Vec::new()
        };
        Ok(products.into_iter().next())
    }

    fn get_lenovo_ibase_info(&self, serial: &str, machine_type: &str) -> Result<Option<LenovoWarrantyInfo>> {
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

        let response: LenovoIbaseResponse =
            serde_json::from_value(response).context("invalid Lenovo warranty info")?;
        Ok(response.data.and_then(|data| data.machine_info))
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

/// Asset end of life = purchase date + this many years.
const LAPTOP_LIFETIME_YEARS: i32 = 4;

/// Add years to a `YYYY-MM-DD` date (29 Feb becomes 28 Feb on non-leap years).
fn add_years(date: &str, years: i32) -> Result<String> {
    let invalid = || anyhow!("invalid date '{date}', expected YYYY-MM-DD");
    let date_part = date.get(..10).ok_or_else(invalid)?;
    let mut parts = date_part.split('-').map(|p| p.parse::<i32>());
    let (Some(Ok(year)), Some(Ok(month)), Some(Ok(day)), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid());
    };
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(invalid());
    }
    let year = year + years;
    let is_leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let day = if month == 2 && day == 29 && !is_leap { 28 } else { day };
    Ok(format!("{year:04}-{month:02}-{day:02}"))
}

/// Days since 1970-01-01 for a civil date (proleptic Gregorian).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// `YYYY-MM-DD` for a number of days since 1970-01-01.
fn civil_from_days(days: i64) -> String {
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Add days to a `YYYY-MM-DD` date.
fn add_days(date: &str, days: i64) -> Result<String> {
    let invalid = || anyhow!("invalid date '{date}', expected YYYY-MM-DD");
    let mut parts = date.get(..10).ok_or_else(invalid)?.split('-').map(|p| p.parse::<i64>());
    let (Some(Ok(year)), Some(Ok(month)), Some(Ok(day)), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(invalid());
    };
    Ok(civil_from_days(days_from_civil(year, month, day) + days))
}

/// Today's date (UTC) as `YYYY-MM-DD`.
fn today() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    civil_from_days((seconds / 86_400) as i64)
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
                        laptop_budget: 1900.0,
                    },
                },
                graph_token: String::new(),
                status_labels: OnceCell::from(vec![
                    SnipeStatusLabel { id: 2, name: Some("Ready to Deploy".into()) },
                    SnipeStatusLabel { id: 4, name: Some("Deployed".into()) },
                    SnipeStatusLabel { id: 9, name: Some("Not In Intune".into()) },
                ]),
                model_ids: RefCell::new(HashMap::new()),
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
            SnipeDevice { id: 17, name: Some("Laptop".into()), asset_tag: None, serial: Some("serial".into()), assigned_to, status_label: None, purchase_date: None, asset_eol_date: None, model: None, category: None, custom_fields: HashMap::new() }
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
                {"id": 5, "serial": "OTHER", "asset_tag": "00000000-0000-0000-0000-000000000001"},
            ])).unwrap();
            let mut intune = intune_device();
            intune.serial_number = Some("ab12".into());
            let missing = snipe_devices_missing_from_intune(&snipe, &[intune]);
            assert_eq!(missing.iter().map(|d| d.id).collect::<Vec<_>>(), vec![2, 3]);
            assert!(is_server_mode(missing[0]));
            assert!(!is_server_mode(missing[1]));
        }

        #[test]
        fn groups_laptops_by_assignee_email_and_finds_unassigned_ones() {
            let snipe: Vec<SnipeDevice> = serde_json::from_value(json!([
                {"id": 1, "category": {"id": 1, "name": "Laptop"}, "assigned_to": {"id": 5, "email": "A@example.com"}},
                {"id": 2, "category": {"id": 1, "name": "laptop"}, "assigned_to": {"id": 5, "email": "a@example.com"}},
                {"id": 3, "category": {"id": 1, "name": "Laptop"}, "assigned_to": {"id": 6, "email": "b@example.com"}},
                {"id": 4, "category": {"id": 1, "name": "Laptop"}},
                {"id": 5, "category": {"id": 1, "name": "Laptop"}, "status_label": {"id": 5, "name": "Server mode"}},
                {"id": 6, "category": {"id": 2, "name": "Monitor"}, "assigned_to": {"id": 6, "email": "b@example.com"}},
                {"id": 7, "category": {"id": 2, "name": "Monitor"}},
            ])).unwrap();
            let laptops = laptops_by_assignee(&snipe);
            assert_eq!(laptops["a@example.com"].iter().map(|d| d.id).collect::<Vec<_>>(), vec![1, 2]);
            assert_eq!(laptops["b@example.com"].iter().map(|d| d.id).collect::<Vec<_>>(), vec![3]);
            assert_eq!(unassigned_laptops(&snipe).iter().map(|d| d.id).collect::<Vec<_>>(), vec![4]);
        }

        #[test]
        fn matches_device_by_serial_then_by_asset_tag() {
            let snipe: Vec<SnipeDevice> = serde_json::from_value(json!([
                {"id": 1, "serial": "OTHER", "asset_tag": "00000000-0000-0000-0000-000000000001"},
                {"id": 2, "serial": "SERIAL"},
            ])).unwrap();
            let mut intune = intune_device();
            intune.serial_number = Some("SERIAL".into());
            assert_eq!(find_snipe_device(&snipe, &intune).map(|d| d.id), Some(2));
            intune.serial_number = Some("UNKNOWN".into());
            assert_eq!(find_snipe_device(&snipe, &intune).map(|d| d.id), Some(1));
            intune.serial_number = None;
            assert_eq!(find_snipe_device(&snipe, &intune).map(|d| d.id), Some(1));
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
                let user = SnipeUser { id: 42, name: None, email: Some("user@example.com".into()), notes: None };
                assert!(matches!(app.assign_device_in_snipe(&device(None), &user, "user@example.com").unwrap(), UserCheckStatus::UserMismatch));
                server.join().unwrap();
            }
        }

        #[test]
        fn does_not_checkout_existing_assignment_without_email() {
            let app = test_app("http://127.0.0.1:9".into());
            let user = SnipeUser { id: 9, name: Some("Existing assignee".into()), email: None, notes: None };
            assert!(matches!(app.check_device_user_mismatch(&device(Some(user)), &intune_device()).unwrap(), UserCheckStatus::UserMismatch));
        }

        #[test]
        fn compares_assigned_users_by_email_even_without_names() {
            let app = test_app("http://127.0.0.1:9".into());
            let user = SnipeUser { id: 9, name: None, email: Some("USER@example.com".into()), notes: None };
            assert!(matches!(app.check_device_user_mismatch(&device(Some(user)), &intune_device()).unwrap(), UserCheckStatus::CorrectlyAssigned));
            let other = SnipeUser { id: 10, name: None, email: Some("other@example.com".into()), notes: None };
            assert!(matches!(app.check_device_user_mismatch(&device(Some(other)), &intune_device()).unwrap(), UserCheckStatus::UserMismatch));
        }

        #[test]
        fn adds_years_to_dates() {
            assert_eq!(add_years("2022-03-15", 4).unwrap(), "2026-03-15");
            assert_eq!(add_years("2024-02-29", 4).unwrap(), "2028-02-29");
            assert_eq!(add_years("2020-02-29", 1).unwrap(), "2021-02-28");
            assert!(add_years("15/03/2022", 4).is_err());
        }

        #[test]
        fn adds_days_to_dates() {
            assert_eq!(add_days("2026-11-19", 90).unwrap(), "2027-02-17");
            assert_eq!(add_days("2024-02-28", 1).unwrap(), "2024-02-29");
            assert_eq!(civil_from_days(0), "1970-01-01");
        }

        #[test]
        fn reports_laptops_to_replace() {
            let snipe: Vec<SnipeDevice> = serde_json::from_value(json!([
                {"id": 1, "category": {"id": 1, "name": "Laptop"}, "assigned_to": {"id": 1}, "asset_eol_date": {"date": "2025-06-01"}},
                {"id": 2, "category": {"id": 1, "name": "Laptop"}, "assigned_to": {"id": 1}, "asset_eol_date": {"date": "2026-03-01"}},
                {"id": 3, "category": {"id": 1, "name": "Laptop"}, "assigned_to": {"id": 1}, "asset_eol_date": {"date": "2026-12-15"}},
                {"id": 4, "category": {"id": 1, "name": "Laptop"}, "assigned_to": {"id": 1}, "asset_eol_date": {"date": "2027-02-10"}},
                {"id": 5, "category": {"id": 1, "name": "Laptop"}, "assigned_to": {"id": 1}, "asset_eol_date": {"date": "2027-09-01"}},
                {"id": 6, "category": {"id": 1, "name": "Laptop"}, "assigned_to": {"id": 1}, "asset_eol_date": {"date": "2026-01-01"}, "status_label": {"id": 5, "name": "Server mode"}},
                {"id": 7, "category": {"id": 2, "name": "Monitor"}, "assigned_to": {"id": 1}, "asset_eol_date": {"date": "2026-01-01"}},
                {"id": 8, "category": {"id": 1, "name": "Laptop"}, "assigned_to": {"id": 1}},
                {"id": 9, "category": {"id": 1, "name": "Laptop"}, "asset_eol_date": {"date": "2026-01-01"}},
            ])).unwrap();
            let report = replacement_report(&snipe, "2026-11-19").unwrap();
            assert_eq!(report.end_of_life.iter().map(|d| d.id).collect::<Vec<_>>(), vec![1, 2]);
            assert_eq!(report.within_three_months.iter().map(|d| d.id).collect::<Vec<_>>(), vec![3, 4]);
            assert_eq!((report.current_year, report.next_year, report.without_eol), (2, 2, 1));
        }

        #[test]
        fn parses_snipe_amounts() {
            assert_eq!(parse_amount("2,200.00"), Some(2200.0));
            assert_eq!(parse_amount("2.200,50"), Some(2200.5));
            assert_eq!(parse_amount("1 234,5 €"), Some(1234.5));
            assert_eq!(parse_amount("19.99"), Some(19.99));
            assert_eq!(parse_amount("1,000"), Some(1000.0));
            assert_eq!(parse_amount(""), None);
        }

        #[test]
        fn builds_license_cashflow() {
            let licenses: Vec<SnipeLicense> = serde_json::from_value(json!([
                {"id": 1, "name": "Microsoft 365", "purchase_cost": "100.00", "depreciation": {"id": 1, "name": "Monthly Licence"}, "purchase_date": {"date": "2026-01-01"}},
                {"id": 2, "name": "Amazon", "purchase_cost": "2,200.00", "purchase_cost_numeric": 2200, "depreciation": {"id": 2, "name": "Annual Licence"}, "expiration_date": {"date": "2027-01-15"}},
                {"id": 3, "name": "Late start", "purchase_cost": "10", "depreciation": {"id": 1, "name": "monthly licence"}, "purchase_date": {"date": "2027-11-03"}},
                {"id": 4, "name": "Stopped", "purchase_cost": "5", "depreciation": {"id": 1, "name": "Monthly Licence"}, "termination_date": {"date": "2026-12-31"}},
                {"id": 5, "name": "Unknown", "purchase_cost": "5", "depreciation": {"id": 3, "name": "3 years"}},
                {"id": 6, "name": "No cost", "depreciation": {"id": 2, "name": "Annual Licence"}, "purchase_date": {"date": "2025-03-01"}},
                {"id": 7, "name": "No date", "purchase_cost": "1", "depreciation": {"id": 2, "name": "Annual Licence"}},
                {"id": 8, "name": "No depreciation", "purchase_cost": "1", "depreciation": null},
            ])).unwrap();
            let cashflow = license_cashflow(&licenses, "2026-11-20").unwrap();
            assert_eq!(cashflow.months.len(), 14);
            assert_eq!(cashflow.months[0].month.to_string(), "November 2026");
            assert_eq!(cashflow.months[13].month.to_string(), "December 2027");
            let names = |i: usize| cashflow.months[i].lines.iter().map(|l| l.name.as_str()).collect::<Vec<_>>();
            assert_eq!(names(0), vec!["Microsoft 365", "Stopped"]);
            assert_eq!(names(2), vec!["Amazon", "Microsoft 365"]);
            assert_eq!(cashflow.months[2].total(), 2300.0);
            assert_eq!(names(12), vec!["Late start", "Microsoft 365"]);
            assert_eq!(cashflow.warnings, vec![
                "Unknown: depreciation '3 years' is not recognized",
                "No cost: no purchase cost",
                "No date: annual licence without expiration or purchase date",
                "No depreciation: no depreciation, expected 'Monthly Licence' or 'Annual Licence'",
            ]);
            assert_eq!(format_euros(2200.0), "2200 €");
            assert_eq!(format_euros(19.9), "19.90 €");
        }

        #[test]
        fn budgets_laptop_replacements() {
            let devices: Vec<SnipeDevice> = serde_json::from_value(json!([
                {"id": 1, "category": {"id": 1, "name": "Laptop"}, "assigned_to": {"id": 1}, "asset_eol_date": {"date": "2025-06-01"}},
                {"id": 2, "category": {"id": 1, "name": "Laptop"}, "assigned_to": {"id": 1}, "asset_eol_date": {"date": "2026-10-31"}},
                {"id": 3, "category": {"id": 1, "name": "Laptop"}, "assigned_to": {"id": 1}, "asset_eol_date": {"date": "2026-11-25"}},
                {"id": 4, "category": {"id": 1, "name": "Laptop"}, "assigned_to": {"id": 1}, "asset_eol_date": {"date": "2027-03-10"}},
                {"id": 5, "category": {"id": 1, "name": "Laptop"}, "assigned_to": {"id": 1}, "asset_eol_date": {"date": "2027-03-20"}},
                {"id": 6, "category": {"id": 1, "name": "Laptop"}, "assigned_to": {"id": 1}, "asset_eol_date": {"date": "2028-01-01"}},
                {"id": 7, "category": {"id": 1, "name": "Laptop"}, "assigned_to": {"id": 1}, "asset_eol_date": {"date": "2026-01-01"}, "status_label": {"id": 5, "name": "Server mode"}},
                {"id": 8, "category": {"id": 1, "name": "Laptop"}, "asset_eol_date": {"date": "2026-01-01"}},
                {"id": 9, "category": {"id": 2, "name": "Monitor"}, "assigned_to": {"id": 1}, "asset_eol_date": {"date": "2026-01-01"}},
                {"id": 10, "category": {"id": 1, "name": "Laptop"}, "assigned_to": {"id": 1}},
            ])).unwrap();
            let mut cashflow = license_cashflow(&[], "2026-11-20").unwrap();
            add_laptop_replacements(&mut cashflow, &devices, 1900.0);
            let lines = |i: usize| cashflow.months[i].lines.iter().map(|l| (l.name.as_str(), l.amount)).collect::<Vec<_>>();
            assert_eq!(lines(0), vec![("Laptop replacement (1)", 1900.0), ("Late replacement (2)", 3800.0)]);
            assert_eq!(lines(4), vec![("Laptop replacement (2)", 3800.0)]);
            assert_eq!(cashflow.months.iter().map(|m| m.lines.len()).sum::<usize>(), 3);
            assert_eq!(cashflow.warnings, vec!["1 assigned laptops have no end-of-life date, not budgeted"]);
        }

        #[test]
        fn renders_cashflow_in_columns() {
            let month = |m: u32, lines: &[(&str, f64)]| BudgetMonth {
                month: Month::new(2027, m),
                lines: lines.iter().map(|(n, a)| BudgetLine { name: (*n).into(), amount: *a }).collect(),
            };
            let months = vec![month(1, &[("Amazon", 2200.0), ("M365", 100.0)]), month(2, &[("M365", 100.0)]), month(3, &[])];
            let expected = "\
January 2027        February 2027
============        =============
* Amazon: 2200 €    * M365: 100 €
* M365: 100 €
Total: 2300 €       Total: 100 €

March 2027
==========
Total: 0 €

";
            assert_eq!(render_cashflow(&months, 2), expected);
        }

        #[test]
        fn renders_bar_chart_and_year_totals() {
            let month = |y: i32, m: u32, amount: f64| BudgetMonth {
                month: Month::new(y, m),
                lines: vec![BudgetLine { name: "x".into(), amount }],
            };
            let months = vec![month(2026, 12, 2200.0), month(2027, 1, 100.0), month(2027, 2, 0.0), month(2027, 3, 1000.0)];
            let expected = "\
3000 € | ###
2000 € | ###
1000 € | ### ###     ###
       +----------------
         Dec Jan Feb Mar
         '26 '27 '27 '27
";
            assert_eq!(render_bar_chart(&months), expected);
            assert_eq!(year_total(&months, 2026), 2200.0);
            assert_eq!(year_total(&months, 2027), 1100.0);
        }

        #[test]
        fn reads_keyboard_layouts() {
            let user = |notes: Option<&str>| SnipeUser { id: 1, name: None, email: None, notes: notes.map(Into::into) };
            assert_eq!(user(Some("Bureau 3\nKeyboard: AZERTY BE\nautre")).get_keyboard_layout(), Some("AZERTY BE"));
            assert_eq!(user(Some("Bureau 3<br>Keyboard: QWERTZ CH")).get_keyboard_layout(), Some("QWERTZ CH"));
            assert_eq!(user(Some("Keyboard:")).get_keyboard_layout(), None);
            assert_eq!(user(None).get_keyboard_layout(), None);
            let laptops: Vec<SnipeDevice> = serde_json::from_value(json!([
                {"id": 1, "custom_fields": {"Keyboard": {"field": "_snipeit_keyboard_3", "value": "QWERTY US"}}},
                {"id": 2, "custom_fields": []},
            ])).unwrap();
            assert_eq!(laptops[0].keyboard_layout(), Some("QWERTY US"));
            assert_eq!(laptops[1].keyboard_layout(), None);
        }

        #[test]
        fn lenovo_model_name_stops_at_first_parenthesis() {
            let warranty = |name: &str| LenovoWarrantyInfo { product_name: name.into(), base_start_date: String::new() };
            assert_eq!(warranty("ThinkPad T14 Gen 3 (Type 21AH, 21AJ) - Type 21AH").model_name(), Some("ThinkPad T14 Gen 3"));
            assert_eq!(warranty(" ThinkPad X1 ").model_name(), Some("ThinkPad X1"));
            assert_eq!(warranty(" (Type 21AH)").model_name(), None);
        }

        #[test]
        fn creates_missing_snipe_model_as_lenovo_laptop() {
            let (app, server) = mock_snipe(vec![
                ("200 OK", r#"{"rows":[{"id":3,"name":"ThinkPad T14 Gen 3 AMD"}]}"#),
                ("200 OK", r#"{"rows":[{"id":5,"name":"Laptop"}]}"#),
                ("200 OK", r#"{"rows":[{"id":6,"name":"Lenovo"}]}"#),
                ("200 OK", r#"{"total":2,"rows":[{"id":7,"name":"Desktop"},{"id":8,"name":"Laptop"}]}"#),
                ("200 OK", r#"{"rows":[{"id":9,"name":"Laptop Standard"}]}"#),
                ("200 OK", r#"{"status":"success","payload":{"id":42,"name":"ThinkPad T14 Gen 3"}}"#),
            ]);
            assert_eq!(app.snipe_model_id("ThinkPad T14 Gen 3").unwrap(), 42);
            assert_eq!(app.snipe_model_id("thinkpad t14 gen 3").unwrap(), 42);
            let requests = server.join().unwrap();
            assert_eq!(requests.len(), 6);
            assert!(requests[5].0.starts_with("POST /api/v1/models "));
            assert_eq!(
                requests[5].1,
                json!({"name": "ThinkPad T14 Gen 3", "category_id": 5, "manufacturer_id": 6, "fieldset_id": 8, "depreciation_id": 9})
            );
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
