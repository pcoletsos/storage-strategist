use std::collections::HashMap;
#[cfg(any(target_os = "windows", target_os = "linux"))]
use std::process::Command;

use crate::model::{DiskInfo, DiskKind, DiskStorageType, LocalityClass, PerformanceClass};
#[cfg(any(target_os = "windows", target_os = "linux"))]
use serde::Deserialize;

#[cfg(windows)]
use std::env;

#[derive(Debug, Clone)]
pub struct DiskProbe {
    pub name: String,
    pub mount_point: String,
    pub total_space_bytes: u64,
    pub free_space_bytes: u64,
    pub disk_kind: DiskKind,
    pub file_system: Option<String>,
    pub is_removable: bool,
}

#[derive(Debug, Clone, Default)]
struct PlatformDiskHint {
    vendor: Option<String>,
    model: Option<String>,
    interface: Option<String>,
    rotational: Option<bool>,
    confidence: f32,
    source: String,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Default)]
struct PlatformHintSeed {
    vendor: Option<String>,
    model: Option<String>,
    interface: Option<String>,
    rotational: Option<bool>,
}

pub fn detect_os_mount() -> Option<String> {
    #[cfg(windows)]
    {
        env::var("SystemDrive")
            .ok()
            .map(|system_drive| normalize_windows_mount(&system_drive))
    }
    #[cfg(not(windows))]
    {
        Some("/".to_string())
    }
}

pub fn enrich_disks(probes: Vec<DiskProbe>) -> Vec<DiskInfo> {
    let os_mount = detect_os_mount();
    let platform_hints = collect_platform_hints();
    let mut disks = probes
        .into_iter()
        .map(|probe| {
            let hint_key = normalize_mount_for_hint_lookup(&probe.mount_point);
            let hint = platform_hints.get(&hint_key);
            enrich_disk(probe, os_mount.as_deref(), hint)
        })
        .collect::<Vec<_>>();
    disks.sort_by(|a, b| a.mount_point.cmp(&b.mount_point));
    disks
}

fn enrich_disk(
    probe: DiskProbe,
    os_mount: Option<&str>,
    platform_hint: Option<&PlatformDiskHint>,
) -> DiskInfo {
    let fs_value = probe.file_system.clone().unwrap_or_default();
    let fs = fs_value.to_lowercase();
    let name = probe.name.to_lowercase();
    let mount = probe.mount_point.to_lowercase();

    let (locality_class, locality_confidence, locality_rationale) =
        classify_locality(&name, &mount, &fs);
    let (mut interface, interface_note) = infer_interface(&name, &mount, &fs, probe.is_removable);
    let (mut vendor, mut model, model_note) = infer_vendor_model(&probe.name);
    let mut provider_notes = Vec::new();

    if let Some(hint) = platform_hint {
        if let Some(hint_interface) = normalize_interface_hint(hint.interface.as_deref()) {
            interface = Some(hint_interface.to_string());
            provider_notes.push(format!(
                "OS provider ({}) supplied interface hint '{}' (confidence {:.2}).",
                hint.source, hint_interface, hint.confidence
            ));
        }

        if let Some(hint_vendor) = normalize_optional_field(hint.vendor.as_deref()) {
            vendor = Some(hint_vendor.to_string());
            provider_notes.push(format!(
                "OS provider ({}) supplied vendor hint (confidence {:.2}).",
                hint.source, hint.confidence
            ));
        }

        if let Some(hint_model) = normalize_optional_field(hint.model.as_deref()) {
            model = Some(hint_model.to_string());
            provider_notes.push(format!(
                "OS provider ({}) supplied model hint (confidence {:.2}).",
                hint.source, hint.confidence
            ));
        }
    }

    let (mut storage_type, mut storage_note) = classify_storage_type(
        probe.disk_kind.clone(),
        locality_class.clone(),
        &name,
        interface.as_deref(),
        probe.is_removable,
    );
    let (mut rotational, hybrid) = infer_rotation_and_hybrid(probe.disk_kind.clone(), &name);

    if matches!(storage_type, DiskStorageType::Unknown) {
        if let Some(hint) = platform_hint {
            match hint.rotational {
                Some(true) => {
                    storage_type = DiskStorageType::Hdd;
                    storage_note =
                        "OS provider inferred rotational media; classified as HDD.".to_string();
                }
                Some(false) => {
                    storage_type = DiskStorageType::Ssd;
                    storage_note =
                        "OS provider inferred non-rotational media; classified as SSD.".to_string();
                }
                None => {}
            }
        }
    }

    if let Some(hint) = platform_hint {
        if let Some(hint_rotational) = hint.rotational {
            rotational = Some(hint_rotational);
            provider_notes.push(format!(
                "OS provider ({}) supplied rotational hint '{}' (confidence {:.2}).",
                hint.source,
                if hint_rotational { "true" } else { "false" },
                hint.confidence
            ));
        }
    }

    let (performance_class, performance_confidence, performance_rationale) =
        classify_performance(&storage_type, &locality_class);

    let is_os_drive = is_os_mount(os_mount, &probe.mount_point);
    let (eligible_for_local_target, ineligible_reasons) =
        infer_target_eligibility(is_os_drive, &locality_class, &storage_type);

    let mut metadata_notes = vec![
        locality_rationale.clone(),
        storage_note,
        interface_note,
        model_note,
    ];
    metadata_notes.extend(provider_notes);
    metadata_notes.retain(|note| !note.is_empty());

    DiskInfo {
        name: probe.name,
        mount_point: probe.mount_point,
        total_space_bytes: probe.total_space_bytes,
        free_space_bytes: probe.free_space_bytes,
        disk_kind: probe.disk_kind,
        file_system: probe.file_system,
        storage_type,
        locality_class,
        locality_confidence,
        locality_rationale,
        is_os_drive,
        is_removable: probe.is_removable,
        vendor,
        model,
        interface,
        rotational,
        hybrid,
        performance_class,
        performance_confidence,
        performance_rationale,
        eligible_for_local_target,
        ineligible_reasons,
        metadata_notes,
        role_hint: Default::default(),
        target_role_eligibility: Vec::new(),
    }
}

fn collect_platform_hints() -> HashMap<String, PlatformDiskHint> {
    if cfg!(test) {
        return HashMap::new();
    }

    #[cfg(target_os = "windows")]
    {
        collect_windows_platform_hints()
    }

    #[cfg(target_os = "linux")]
    {
        collect_linux_platform_hints()
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        HashMap::new()
    }
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Deserialize)]
struct WindowsDiskBridgeRecord {
    #[serde(default, alias = "mount", alias = "mountPoint")]
    mount_point: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default, alias = "manufacturer")]
    vendor: Option<String>,
    #[serde(default, alias = "interfaceType")]
    interface: Option<String>,
    #[serde(default)]
    rotational: Option<bool>,
    #[serde(default, alias = "mediaType")]
    media_type: Option<String>,
}

#[cfg(target_os = "windows")]
fn collect_windows_platform_hints() -> HashMap<String, PlatformDiskHint> {
    let script = r#"
$ErrorActionPreference = 'SilentlyContinue'
$records = @()
$drives = Get-CimInstance Win32_DiskDrive
foreach ($drive in $drives) {
  $parts = @(Get-CimAssociatedInstance -InputObject $drive -ResultClassName Win32_DiskPartition)
  foreach ($part in $parts) {
    $logical = @(Get-CimAssociatedInstance -InputObject $part -ResultClassName Win32_LogicalDisk)
    foreach ($ld in $logical) {
      $rot = $null
      if ($drive.MediaType -match 'SSD|Solid State') { $rot = $false }
      elseif ($drive.MediaType -match 'HDD|Hard Disk|Fixed hard') { $rot = $true }
      $records += [pscustomobject]@{
        mount_point = "$($ld.DeviceID)\"
        model = $drive.Model
        vendor = $drive.Manufacturer
        interface = $drive.InterfaceType
        rotational = $rot
        media_type = $drive.MediaType
      }
    }
  }
}
$records | ConvertTo-Json -Compress
"#;

    let output = match Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return HashMap::new(),
    };

    let records = parse_windows_bridge_records(&output.stdout);
    if records.is_empty() {
        return HashMap::new();
    }

    let mut hints = HashMap::new();
    for record in records {
        let Some(mount_point) = normalize_optional_field(record.mount_point.as_deref()) else {
            continue;
        };

        let rotational = record
            .rotational
            .or_else(|| infer_rotational_from_media_type(record.media_type.as_deref()));
        let interface = normalize_interface_hint(record.interface.as_deref()).map(str::to_string);
        let vendor = normalize_optional_field(record.vendor.as_deref()).map(str::to_string);
        let model = normalize_optional_field(record.model.as_deref()).map(str::to_string);

        let known_fields = [interface.is_some(), rotational.is_some(), model.is_some()]
            .iter()
            .filter(|known| **known)
            .count();
        let confidence = (0.72 + (known_fields as f32 * 0.06)).min(0.9);

        upsert_platform_hint(
            &mut hints,
            mount_point,
            PlatformDiskHint {
                vendor,
                model,
                interface,
                rotational,
                confidence,
                source: "windows_wmi".to_string(),
            },
        );
    }

    hints
}

#[cfg(target_os = "windows")]
fn parse_windows_bridge_records(raw: &[u8]) -> Vec<WindowsDiskBridgeRecord> {
    if let Ok(records) = serde_json::from_slice::<Vec<WindowsDiskBridgeRecord>>(raw) {
        return records;
    }
    if let Ok(record) = serde_json::from_slice::<WindowsDiskBridgeRecord>(raw) {
        return vec![record];
    }
    Vec::new()
}

#[cfg(target_os = "windows")]
fn infer_rotational_from_media_type(media_type: Option<&str>) -> Option<bool> {
    let media_type = media_type?.to_ascii_lowercase();
    if media_type.contains("ssd") || media_type.contains("solid state") {
        return Some(false);
    }
    if media_type.contains("hdd") || media_type.contains("hard disk") {
        return Some(true);
    }
    None
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Deserialize)]
struct LinuxLsblkRoot {
    #[serde(default)]
    blockdevices: Vec<LinuxLsblkNode>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Deserialize)]
struct LinuxLsblkNode {
    #[serde(default)]
    mountpoint: Option<String>,
    #[serde(default)]
    mountpoints: Option<Vec<Option<String>>>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    vendor: Option<String>,
    #[serde(default)]
    tran: Option<String>,
    #[serde(default)]
    rota: Option<serde_json::Value>,
    #[serde(default)]
    children: Vec<LinuxLsblkNode>,
}

#[cfg(target_os = "linux")]
fn collect_linux_platform_hints() -> HashMap<String, PlatformDiskHint> {
    let output = match Command::new("lsblk")
        .args(["-J", "-o", "MOUNTPOINT,MOUNTPOINTS,MODEL,VENDOR,ROTA,TRAN"])
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return HashMap::new(),
    };

    let root = match serde_json::from_slice::<LinuxLsblkRoot>(&output.stdout) {
        Ok(root) => root,
        Err(_) => return HashMap::new(),
    };

    let mut hints = HashMap::new();
    for device in root.blockdevices {
        collect_linux_hints_recursive(&mut hints, &device, PlatformHintSeed::default());
    }
    hints
}

#[cfg(target_os = "linux")]
fn collect_linux_hints_recursive(
    hints: &mut HashMap<String, PlatformDiskHint>,
    node: &LinuxLsblkNode,
    seed: PlatformHintSeed,
) {
    let mut current = seed;
    if let Some(model) = normalize_optional_field(node.model.as_deref()) {
        current.model = Some(model.to_string());
    }
    if let Some(vendor) = normalize_optional_field(node.vendor.as_deref()) {
        current.vendor = Some(vendor.to_string());
    }
    if let Some(interface) = normalize_interface_hint(node.tran.as_deref()) {
        current.interface = Some(interface.to_string());
    }
    if let Some(rotational) = parse_rotational_hint(node.rota.as_ref()) {
        current.rotational = Some(rotational);
    }

    for mount in extract_linux_mount_points(node) {
        let known_fields = [
            current.model.is_some(),
            current.vendor.is_some(),
            current.interface.is_some(),
            current.rotational.is_some(),
        ]
        .iter()
        .filter(|known| **known)
        .count();
        let confidence = (0.70 + (known_fields as f32 * 0.05)).min(0.9);

        upsert_platform_hint(
            hints,
            mount.as_str(),
            PlatformDiskHint {
                vendor: current.vendor.clone(),
                model: current.model.clone(),
                interface: current.interface.clone(),
                rotational: current.rotational,
                confidence,
                source: "linux_lsblk".to_string(),
            },
        );
    }

    for child in &node.children {
        collect_linux_hints_recursive(hints, child, current.clone());
    }
}

#[cfg(target_os = "linux")]
fn extract_linux_mount_points(node: &LinuxLsblkNode) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(mount) = normalize_optional_field(node.mountpoint.as_deref()) {
        out.push(mount.to_string());
    }
    if let Some(mounts) = &node.mountpoints {
        for mount in mounts {
            if let Some(mount) = normalize_optional_field(mount.as_deref()) {
                if !out.iter().any(|entry| entry == mount) {
                    out.push(mount.to_string());
                }
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn parse_rotational_hint(value: Option<&serde_json::Value>) -> Option<bool> {
    match value? {
        serde_json::Value::Bool(flag) => Some(*flag),
        serde_json::Value::Number(number) => number
            .as_i64()
            .map(|value| value != 0)
            .or_else(|| number.as_u64().map(|value| value != 0)),
        serde_json::Value::String(raw) => {
            let normalized = raw.trim().to_ascii_lowercase();
            match normalized.as_str() {
                "1" | "true" | "yes" => Some(true),
                "0" | "false" | "no" => Some(false),
                _ => None,
            }
        }
        _ => None,
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
fn upsert_platform_hint(
    hints: &mut HashMap<String, PlatformDiskHint>,
    mount_point: &str,
    candidate: PlatformDiskHint,
) {
    let key = normalize_mount_for_hint_lookup(mount_point);
    if key.is_empty() {
        return;
    }

    hints
        .entry(key)
        .and_modify(|current| {
            if candidate.confidence > current.confidence {
                *current = candidate.clone();
            } else {
                if current.vendor.is_none() && candidate.vendor.is_some() {
                    current.vendor = candidate.vendor.clone();
                }
                if current.model.is_none() && candidate.model.is_some() {
                    current.model = candidate.model.clone();
                }
                if current.interface.is_none() && candidate.interface.is_some() {
                    current.interface = candidate.interface.clone();
                }
                if current.rotational.is_none() && candidate.rotational.is_some() {
                    current.rotational = candidate.rotational;
                }
            }
        })
        .or_insert(candidate);
}

fn normalize_mount_for_hint_lookup(value: &str) -> String {
    #[cfg(windows)]
    {
        normalize_windows_mount(value)
    }

    #[cfg(not(windows))]
    {
        normalize_unix_mount(value)
    }
}

fn normalize_optional_field(value: Option<&str>) -> Option<&str> {
    let value = value?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn normalize_interface_hint(raw: Option<&str>) -> Option<&str> {
    let raw = normalize_optional_field(raw)?.to_ascii_lowercase();
    if raw.contains("nvme") {
        return Some("nvme");
    }
    if raw.contains("usb") {
        return Some("usb");
    }
    if raw.contains("sata")
        || raw.contains("ata")
        || raw.contains("sas")
        || raw.contains("scsi")
        || raw.contains("pcie")
    {
        return Some("sata");
    }
    if raw.contains("virtio") {
        return Some("virtio");
    }
    if raw.contains("network")
        || raw.contains("iscsi")
        || raw.contains("nfs")
        || raw.contains("smb")
    {
        return Some("network");
    }
    None
}

fn classify_locality(name: &str, mount: &str, fs: &str) -> (LocalityClass, f32, String) {
    if looks_google_drive_label(name)
        || contains_any(name, CLOUD_KEYWORDS)
        || contains_any(mount, CLOUD_KEYWORDS)
        || (contains_any(fs, &["google", "drivefs", "onedrive"]) && !fs.is_empty())
    {
        return (
            LocalityClass::CloudBacked,
            0.95,
            "Cloud-provider indicators detected in disk name/mount/file system.".to_string(),
        );
    }

    if looks_network_mount(mount, fs) {
        return (
            LocalityClass::Network,
            0.9,
            "Mount and/or file system matches network share patterns.".to_string(),
        );
    }

    if looks_virtual_mount(name, mount, fs) {
        return (
            LocalityClass::LocalVirtual,
            0.8,
            "Virtual/substituted mount indicators detected.".to_string(),
        );
    }

    if !mount.is_empty() {
        return (
            LocalityClass::LocalPhysical,
            0.7,
            "No cloud/network/virtual indicators detected for this mount.".to_string(),
        );
    }

    (
        LocalityClass::Unknown,
        0.4,
        "Insufficient signals to classify mount locality.".to_string(),
    )
}

fn classify_storage_type(
    disk_kind: DiskKind,
    locality: LocalityClass,
    name: &str,
    interface: Option<&str>,
    is_removable: bool,
) -> (DiskStorageType, String) {
    if matches!(locality, LocalityClass::CloudBacked) {
        return (
            DiskStorageType::CloudBacked,
            "Classified as cloud-backed because locality indicates non-local storage.".to_string(),
        );
    }

    if matches!(locality, LocalityClass::Network) {
        return (
            DiskStorageType::Network,
            "Classified as network storage due to mount/file-system characteristics.".to_string(),
        );
    }

    if matches!(locality, LocalityClass::LocalVirtual) {
        return (
            DiskStorageType::Virtual,
            "Classified as virtual due to local virtual mount indicators.".to_string(),
        );
    }

    if contains_any(name, &["nvme"]) || matches!(interface, Some("nvme")) {
        return (
            DiskStorageType::Nvme,
            "NVMe indicators detected from disk naming/interface hints.".to_string(),
        );
    }

    if is_removable || matches!(interface, Some("usb")) || contains_any(name, &["usb"]) {
        return (
            DiskStorageType::Usb,
            "Removable/USB indicators detected for this disk.".to_string(),
        );
    }

    match disk_kind {
        DiskKind::Ssd => (
            DiskStorageType::Ssd,
            "sysinfo reported this disk as SSD.".to_string(),
        ),
        DiskKind::Hdd => (
            DiskStorageType::Hdd,
            "sysinfo reported this disk as HDD.".to_string(),
        ),
        DiskKind::Unknown => (
            DiskStorageType::Unknown,
            "Insufficient signals to infer storage type.".to_string(),
        ),
    }
}

fn infer_interface(
    name: &str,
    mount: &str,
    fs: &str,
    is_removable: bool,
) -> (Option<String>, String) {
    if contains_any(name, &["nvme"]) || contains_any(fs, &["nvme"]) {
        return (
            Some("nvme".to_string()),
            "Interface inferred as NVMe from naming signals.".to_string(),
        );
    }

    if is_removable || contains_any(name, &["usb"]) {
        return (
            Some("usb".to_string()),
            "Interface inferred as USB due to removable/media hints.".to_string(),
        );
    }

    if looks_network_mount(mount, fs) {
        return (
            Some("network".to_string()),
            "Interface inferred as network from mount/file-system signals.".to_string(),
        );
    }

    (
        None,
        "Interface unavailable from cross-platform runtime signals.".to_string(),
    )
}

fn infer_vendor_model(raw_name: &str) -> (Option<String>, Option<String>, String) {
    let name = raw_name.trim();
    if name.is_empty() {
        return (
            None,
            None,
            "Disk name is empty; vendor/model unavailable.".to_string(),
        );
    }

    let lowered = name.to_lowercase();
    for vendor in KNOWN_VENDORS {
        if lowered.contains(vendor.0) {
            return (
                Some(vendor.1.to_string()),
                Some(name.to_string()),
                "Vendor/model inferred from disk name string.".to_string(),
            );
        }
    }

    (
        None,
        Some(name.to_string()),
        "Disk label is available but vendor could not be inferred reliably.".to_string(),
    )
}

fn infer_rotation_and_hybrid(disk_kind: DiskKind, name: &str) -> (Option<bool>, Option<bool>) {
    let hybrid = if contains_any(name, &["sshd", "hybrid"]) {
        Some(true)
    } else {
        Some(false)
    };
    match disk_kind {
        DiskKind::Hdd => (Some(true), hybrid),
        DiskKind::Ssd => (Some(false), hybrid),
        DiskKind::Unknown => (None, if hybrid == Some(true) { hybrid } else { None }),
    }
}

fn classify_performance(
    storage_type: &DiskStorageType,
    locality: &LocalityClass,
) -> (PerformanceClass, f32, String) {
    match storage_type {
        DiskStorageType::Nvme => (
            PerformanceClass::Fast,
            0.9,
            "NVMe storage generally provides high random and sequential throughput.".to_string(),
        ),
        DiskStorageType::Ssd => (
            PerformanceClass::Fast,
            0.8,
            "SSD classification indicates fast local access characteristics.".to_string(),
        ),
        DiskStorageType::Hdd => (
            PerformanceClass::Slow,
            0.75,
            "HDD classification indicates higher latency than solid-state media.".to_string(),
        ),
        DiskStorageType::Usb => (
            PerformanceClass::Balanced,
            0.55,
            "USB devices vary widely; conservative balanced performance estimate applied."
                .to_string(),
        ),
        DiskStorageType::Network | DiskStorageType::CloudBacked => (
            PerformanceClass::Slow,
            0.65,
            "Network/cloud-backed storage is typically latency sensitive for active workloads."
                .to_string(),
        ),
        DiskStorageType::Virtual => (
            PerformanceClass::Unknown,
            0.45,
            "Virtual storage performance depends on backing medium and cannot be inferred safely."
                .to_string(),
        ),
        DiskStorageType::Unknown => {
            if matches!(locality, LocalityClass::LocalPhysical) {
                (
                    PerformanceClass::Balanced,
                    0.4,
                    "Local physical mount detected, but storage type is unknown.".to_string(),
                )
            } else {
                (
                    PerformanceClass::Unknown,
                    0.35,
                    "Insufficient data to infer performance class.".to_string(),
                )
            }
        }
    }
}

fn infer_target_eligibility(
    is_os_drive: bool,
    locality_class: &LocalityClass,
    storage_type: &DiskStorageType,
) -> (bool, Vec<String>) {
    let mut reasons = Vec::new();

    if is_os_drive {
        reasons
            .push("OS/system drive is excluded from optimization targets by default.".to_string());
    }
    match locality_class {
        LocalityClass::CloudBacked => {
            reasons.push("Cloud-backed drive is excluded as a local placement target.".to_string())
        }
        LocalityClass::Network => {
            reasons.push("Network share is excluded as a local placement target.".to_string())
        }
        LocalityClass::LocalVirtual => {
            reasons.push("Virtual drive is excluded as a local placement target.".to_string())
        }
        LocalityClass::Unknown => {
            reasons.push("Locality is unknown; target eligibility disabled for safety.".to_string())
        }
        LocalityClass::LocalPhysical => {}
    }

    match storage_type {
        DiskStorageType::CloudBacked | DiskStorageType::Network | DiskStorageType::Virtual => {
            reasons.push("Storage type is non-local for optimization purposes.".to_string())
        }
        _ => {}
    }

    let eligible = reasons.is_empty();
    (eligible, reasons)
}

fn is_os_mount(os_mount: Option<&str>, mount_point: &str) -> bool {
    let Some(os_mount) = os_mount else {
        return false;
    };

    #[cfg(windows)]
    {
        normalize_windows_mount(os_mount)
            .eq_ignore_ascii_case(&normalize_windows_mount(mount_point))
    }

    #[cfg(not(windows))]
    {
        normalize_unix_mount(os_mount) == normalize_unix_mount(mount_point)
    }
}

fn looks_network_mount(mount: &str, fs: &str) -> bool {
    mount.starts_with("\\\\")
        || mount.starts_with("//")
        || contains_any(
            fs,
            &[
                "nfs",
                "cifs",
                "smb",
                "afp",
                "fuse.sshfs",
                "davfs",
                "webdav",
                "sshfs",
            ],
        )
}

fn looks_virtual_mount(name: &str, mount: &str, fs: &str) -> bool {
    contains_any(name, &["virtual", "subst", "imdisk", "ramdisk"])
        || contains_any(mount, &["/volumes/com.apple.time-machine.localsnapshots"])
        || contains_any(
            fs,
            &[
                "tmpfs",
                "overlay",
                "proc",
                "sysfs",
                "devfs",
                "fuse.portal",
                "ramfs",
            ],
        )
}

fn contains_any(value: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| value.contains(pattern))
}

fn looks_google_drive_label(name: &str) -> bool {
    (name.contains("@gmail.com") || name.contains("@googlemail.com") || name.contains("@"))
        && (name.contains("googl") || name.contains("drive"))
}

#[cfg(windows)]
fn normalize_windows_mount(value: &str) -> String {
    let mut normalized = value.trim().replace('/', "\\");
    if normalized.len() == 2 && normalized.ends_with(':') {
        normalized.push('\\');
    }
    if normalized.len() >= 2 && normalized.as_bytes()[1] == b':' {
        let drive = normalized[..1].to_ascii_uppercase();
        normalized.replace_range(..1, &drive);
    }
    normalized
}

#[cfg(not(windows))]
fn normalize_unix_mount(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed == "/" {
        "/".to_string()
    } else {
        trimmed.trim_end_matches('/').to_string()
    }
}

const CLOUD_KEYWORDS: &[&str] = &[
    "google drive",
    "googledrive",
    "drivefs",
    "onedrive",
    "dropbox",
    "icloud",
    "box",
    "pcloud",
    "sync.com",
    "mega",
    "webdav",
];

const KNOWN_VENDORS: &[(&str, &str)] = &[
    ("samsung", "Samsung"),
    ("seagate", "Seagate"),
    ("western digital", "Western Digital"),
    ("wd ", "Western Digital"),
    ("toshiba", "Toshiba"),
    ("kingston", "Kingston"),
    ("sandisk", "SanDisk"),
    ("crucial", "Crucial"),
    ("intel", "Intel"),
    ("hynix", "SK hynix"),
    ("micron", "Micron"),
];

#[cfg(test)]
mod tests {
    use crate::model::{DiskStorageType, LocalityClass};

    use super::{detect_os_mount, enrich_disks, DiskProbe};
    use crate::model::DiskKind;

    #[test]
    fn classifies_google_drive_as_cloud_and_ineligible() {
        let probe = DiskProbe {
            name: "takjar@gmail.com - Google Drive".to_string(),
            mount_point: "J:\\".to_string(),
            total_space_bytes: 1000,
            free_space_bytes: 100,
            disk_kind: DiskKind::Unknown,
            file_system: Some("google".to_string()),
            is_removable: false,
        };

        let disks = enrich_disks(vec![probe]);
        let disk = &disks[0];
        assert_eq!(disk.locality_class, LocalityClass::CloudBacked);
        assert_eq!(disk.storage_type, DiskStorageType::CloudBacked);
        assert!(!disk.eligible_for_local_target);
    }

    #[test]
    fn classifies_nvme_as_fast_local_physical() {
        let probe = DiskProbe {
            name: "Samsung NVMe SSD 980".to_string(),
            mount_point: "D:\\".to_string(),
            total_space_bytes: 10_000,
            free_space_bytes: 1_000,
            disk_kind: DiskKind::Ssd,
            file_system: Some("ntfs".to_string()),
            is_removable: false,
        };
        let disks = enrich_disks(vec![probe]);
        let disk = &disks[0];
        assert_eq!(disk.storage_type, DiskStorageType::Nvme);
        assert_eq!(disk.locality_class, LocalityClass::LocalPhysical);
        assert!(disk.eligible_for_local_target || disk.is_os_drive);
    }

    #[test]
    fn marks_detected_os_mount_as_os_drive() {
        let Some(os_mount) = detect_os_mount() else {
            return;
        };

        let probe_os = DiskProbe {
            name: "OS".to_string(),
            mount_point: os_mount.clone(),
            total_space_bytes: 10_000,
            free_space_bytes: 5_000,
            disk_kind: DiskKind::Ssd,
            file_system: Some("ntfs".to_string()),
            is_removable: false,
        };
        let probe_other = DiskProbe {
            name: "Data".to_string(),
            mount_point: if cfg!(windows) {
                "Z:\\".to_string()
            } else {
                "/mnt/data".to_string()
            },
            total_space_bytes: 20_000,
            free_space_bytes: 7_000,
            disk_kind: DiskKind::Hdd,
            file_system: Some("ext4".to_string()),
            is_removable: false,
        };

        let disks = enrich_disks(vec![probe_os, probe_other]);
        assert!(disks.iter().any(|disk| disk.is_os_drive));
        assert!(disks
            .iter()
            .any(|disk| disk.is_os_drive && disk.mount_point.eq_ignore_ascii_case(&os_mount)));
    }
}
