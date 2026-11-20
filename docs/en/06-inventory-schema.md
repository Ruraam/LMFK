# LMFK Hardware Inventory JSON Schema v1.0

*Status: active output contract for Phase 1. The scanner builds this inventory in memory and can serialize it to terminal output; persistent file export is not implemented.*

> An **Inventory** is the immutable snapshot produced by the scanner (`05-hw-scanner-spec.md`) and consumed by the manager and user interfaces (`04-driver-manager-spec.md`). This document is the canonical definition of its JSON representation.

---

## 1. Conventions and compatibility rules

- **`schema_version` is a compatibility contract.** It is the literal string `"1.0"`. Readers must check it before interpreting any other field. A future incompatible change requires a new major version; compatible additions may bump the minor version.
- **Unknown fields must be ignored by readers.** A reader encountering a field it does not recognise must skip it without error. This allows producers to add optional fields without breaking older consumers.
- **All IDs are stable strings.** An `id` is a stable, human-readable identifier that is consistent across runs on the same hardware. It is not a numeric handle and not a kernel-internal pointer.
- **No absolute host-specific paths in the public `id`.** `id` values are logical identifiers such as `pci:0000:00:02.0` or `usb:1-4:1.0`. Absolute filesystem paths belong in the `path` field, never in `id`.
- **Arrays may be empty.** Any array field (`devices`, `interfaces`, `modules`, `firmwares`, `package_suggestions`, `diagnosis`, `dependencies`, `sources`, `errors`, `paths`) may legitimately be empty `[]`. An empty array is not an error.
- **An empty `package_suggestions` must be accompanied by a `PACKAGE_UNKNOWN` diagnosis.** If no backend can justify a package, the device's `diagnosis` array must contain a `PACKAGE_UNKNOWN` entry explaining the absence. Silence is not acceptable.
- **Serialized output, no persistent export.** The scanner creates the inventory in memory and may serialize it to stdout as text or JSON. It does not write an inventory file, create a cache, or create temporary files. Persistent export is a separate future feature and is not part of Phase 1.

### 1.1 Enumerations (closed value sets)

| Field | Allowed values |
|---|---|
| `schema_version` | `"1.0"` |
| `host.secure_boot` | `"enabled"`, `"disabled"`, `"unknown"` |
| `device.bus` | `"pci"`, `"usb"`, `"dt"` |
| `device.driver.state` / usb `driver.state` | `"bound"`, `"unbound"`, `"unknown"` |
| `module.match_source` | `"modules.alias"`, `"modules.builtin"`, `"driver_link"`, `"modalias"` |
| `module.state` | `"loaded"`, `"available"`, `"builtin"`, `"missing"`, `"unknown"` |
| `suggestion.backend` | Open string. Conventional values include `"apt"`, `"dnf"`, `"pacman"`, `"zypper"`, but any distribution backend identifier is valid. |
| `suggestion.confidence` | `"high"`, `"medium"`, `"low"` |
| `diagnosis.code` | Open string; the full catalogue with stable codes is defined in §12.2 |
| `diagnosis.severity` | `"error"`, `"warning"`, `"info"` |

---

## 2. Top-level object

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | Compatibility contract; must be `"1.0"` for this version. |
| `generated_at` | string | Timestamp of inventory creation in RFC 3339 format (e.g. `2026-11-19T10:42:00Z`). |
| `host` | object | Information about the host the scan ran on (see §3). |
| `scan` | object | Metadata about the scan itself, including sources and errors (see §4). |
| `devices` | array of device | The discovered devices (see §5). May be empty. |
| `summary` | object | Aggregate counts over `devices` and `scan.errors` (see §12). |

---

## 3. `host` object

| Field | Type | Description |
|---|---|---|
| `kernel_release` | string | Running kernel release (`uname -r`), e.g. `6.1.0-13-amd64`. Determines the `/lib/modules/<release>` path used. |
| `kernel_version` | string | Full kernel version string (`uname -v`), including distribution build information. |
| `arch` | string | Architecture name, e.g. `x86_64` or `aarch64`. |
| `distro_id` | string | Distribution identifier from `/etc/os-release` `ID`, e.g. `example-distro`. Open string; not tied to any particular distribution. |
| `distro_version` | string | Distribution version from `/etc/os-release` `VERSION_ID`, e.g. `13`. |
| `secure_boot` | string | `"enabled"`, `"disabled"` or `"unknown"`. `"unknown"` must be used when it could not be determined (Secure Boot evaluation is a future policy concern; see §4.7 of `05-hw-scanner-spec.md`). |

---

## 4. `scan` object

| Field | Type | Description |
|---|---|---|
| `sources` | array of string | Names of every data source actually consulted (e.g. `/sys/bus/pci/devices`, `/proc/modules`, `modinfo`, `package-manager query`). Backend-specific commands are reported generically so this field stays distribution-neutral. Lets consumers audit how facts were obtained. |
| `read_only` | boolean | Must be `true`. Declares that the scan performed no writes and no side-effecting commands. |
| `errors` | array of scan-error | Non-fatal problems encountered during the scan (see §4.1). The scan still returns a valid inventory. |

### 4.1 `scan-error` object

| Field | Type | Description |
|---|---|---|
| `source` | string | The source that produced the error (file path or command name). |
| `message` | string | Plain-language description of the problem, e.g. `permission denied; fell back to modules.alias`. |

---

## 5. `device` object

| Field | Type | Description |
|---|---|---|
| `id` | string | Stable public identifier, e.g. `pci:0000:00:02.0`, `usb:1-4` or `dt:/soc/serial@1000`. Never an absolute path. |
| `bus` | string | `"pci"`, `"usb"` or `"dt"` (Device Tree). |
| `class` | object | Device class with `code` and `name` (see §6). |
| `vendor` | object | Vendor with `id` and `name` (see §6). |
| `device` | object | Device with `id` and `name` (see §6). |
| `subsystem` | object | Subsystem identifiers with `vendor` and `device` (see §6). |
| `modalias` | string | The device's modalias, used for module matching. Empty string if none. |
| `path` | string | Filesystem path in sysfs, e.g. `/sys/bus/pci/devices/0000:00:02.0`. This is allowed here (it is not the `id`). |
| `parent` | string or null | `id` of the parent device, or `null` for a root device. |
| `interfaces` | array of usb-interface | Present for USB devices; one entry per interface (see §7). Empty for non-USB devices. |
| `driver` | object | The driver bound at this device level with `bound` and `state` (see §8). |
| `modules` | array of module | Modules matched to this device (see §9). May be empty. |
| `firmwares` | array of firmware | Firmware relevant to this device (see §10). May be empty. |
| `package_suggestions` | array of suggestion | Candidate packages from distribution backends (see §11). May be empty, but see the `PACKAGE_UNKNOWN` rule in §1. |
| `diagnosis` | array of diagnosis | Human-readable findings for this device (see §12.1). May be empty when nothing is wrong. |

> **USB reminder:** a USB device and its interfaces are distinct records. Each interface has its own `modalias` and its own `driver`; do not copy an interface's driver onto the parent device.

---

## 6. Identifier value objects

These small objects appear as `class`, `vendor`, `device` and `subsystem` on a device and on USB interfaces.

| Object | Field | Type | Description |
|---|---|---|---|
| `class` | `code` | string | Class code, e.g. `0x030000` (VGA) or `0x0a00` (wireless). |
| `class` | `name` | string | Human-readable class name, e.g. `VGA compatible controller`. |
| `vendor` | `id` | string | Vendor ID, e.g. `0x8086`. |
| `vendor` | `name` | string | Human-readable vendor name, e.g. `Intel Corporation`. |
| `device` | `id` | string | Device ID, e.g. `0x9bc4`. |
| `device` | `name` | string | Human-readable device name, e.g. `UHD Graphics 630`. |
| `subsystem` | `vendor` | string | Subsystem vendor ID. |
| `subsystem` | `device` | string | Subsystem device ID. |

When a name cannot be resolved, it should be an empty string or a neutral placeholder; it must never be guessed from the ID.

---

## 7. USB `interface` object

| Field | Type | Description |
|---|---|---|
| `id` | string | Stable identifier of the interface, e.g. `usb:1-4:1.0`. |
| `device_id` | string | `id` of the parent USB device to which this interface belongs. |
| `interface_number` | integer | Interface number as reported by USB, e.g. `0` or `1`. |
| `class` | object | Interface class with `code` and `name` (see §6). |
| `modalias` | string | The interface's own modalias (distinct from the device's modalias). |
| `driver` | object | Driver bound to this interface with `bound` and `state` (see §8). |

---

## 8. `driver` object

| Field | Type | Description |
|---|---|---|
| `bound` | string or null | Name of the bound driver (e.g. `i915`), or `null` when no driver is bound. |
| `state` | string | `"bound"`, `"unbound"` or `"unknown"`. |

---

## 9. `module` object

| Field | Type | Description |
|---|---|---|
| `name` | string | Module name as found in kernel metadata, e.g. `i915`. Never guessed. |
| `match_source` | string | How the module was matched to the device: `"modules.alias"`, `"modules.builtin"`, `"driver_link"` or `"modalias"`. |
| `state` | string | `"loaded"`, `"available"`, `"builtin"`, `"missing"` or `"unknown"` (see §4.3 of `05-hw-scanner-spec.md`). |
| `dependencies` | array of string | Names of modules this module depends on, from `modules.dep`. May be empty. |
| `firmwares` | array of firmware | Firmware declared by this module (see §10). Declared firmware may or may not be present. |

---

## 10. `firmware` object

| Field | Type | Description |
|---|---|---|
| `alias` | string | Firmware alias/path declared by the module, e.g. `rtlwifi/rtl8812aufw.bin`. |
| `present` | boolean | `true` if a matching file exists on disk, `false` otherwise. |
| `paths` | array of string | Absolute paths where the firmware was found. Empty when `present` is `false`. |

> Declared-but-absent firmware is reported with `present: false` and an empty `paths` array; it produces a `FIRMWARE_MISSING` diagnosis. This is distinct from a missing module.

---

## 11. `suggestion` object

| Field | Type | Description |
|---|---|---|
| `backend` | open string | Identifier of the distribution backend that produced the suggestion. Conventional values are `"apt"`, `"dnf"`, `"pacman"` and `"zypper"`, but a new distribution may use any other identifier without changing this schema. |
| `package` | string | Suggested package name. |
| `reason` | string | Plain-language justification, e.g. `owns /lib/modules/6.1.0-13-amd64/kernel/drivers/gpu/drm/i915/i915.ko`. |
| `confidence` | string | `"high"`, `"medium"` or `"low"`. Heuristic results must not be marked `high` without justification. |

A backend may return an empty array; in that case the device must carry a `PACKAGE_UNKNOWN` diagnosis (§1).

---

## 12. `summary` object

| Field | Type | Description |
|---|---|---|
| `devices` | integer | Total number of entries in `devices`. |
| `with_driver` | integer | Number of devices with at least one bound driver at device level **or** on any of their USB interfaces. |
| `without_driver` | integer | Number of devices with no bound driver at any level (`devices - with_driver`). |
| `missing_firmware` | integer | Number of devices with at least one firmware entry whose `present` is `false`. |
| `errors` | integer | Number of entries in `scan.errors`. |

### 12.1 `diagnosis` object

| Field | Type | Description |
|---|---|---|
| `code` | stable string | Machine-readable code from the catalogue in §12.2. Codes are stable; new codes may be added without changing the schema. |
| `title` | string | Short headline shown to the user, e.g. "No driver found for this device". |
| `explanation` | string | Simple-language explanation of what LMFK observed and why it matters. No kernel jargon as the only explanation. |
| `severity` | string | `"error"`, `"warning"` or `"info"`. |
| `evidence` | array of string | The facts that led to the diagnosis (for example the modalias, the module name, the firmware alias, the consulted source). |
| `advised_action` | string | One concrete next step for the user. It is a **suggestion only**: LMFK must never perform the action automatically. |
| `message` | string | Full beginner-readable sentence combining title, explanation, consequences and advised action; suitable for terminal display. |

### 12.2 Diagnostic catalogue

Every diagnosis uses a stable code and the fields above. These six situations are mandatory; additional codes may be introduced in later schema versions.

| Code | Title | Simple explanation | Severity | Evidence | Advised action (never automatic) |
|---|---|---|---|---|---|
| `MODULE_MISSING` | No driver found for this device | The device's hardware ID does not match any module available for the running kernel, so Linux cannot drive it right now. | `error` | modalias, kernel release, consulted `modules.alias` | Check whether your distribution offers a driver package for this device, or whether a newer kernel supports it. |
| `MODULE_AVAILABLE_NOT_LOADED` | Driver available but not active | A matching driver exists on this system but is not currently loaded, so the device may not be usable yet. | `warning` | module name, match source, `state: available` | The driver can be loaded by the system; ask an administrator or check your distribution's driver settings. LMFK will not load it. |
| `MODULE_BUILTIN` | Driver built into the kernel | The driver is already part of the running kernel, so no separate module or package is needed for it. | `info` | module name, `state: builtin`, bound driver | No action needed. If the device still fails, check configuration rather than installing a module. |
| `FIRMWARE_MISSING` | Required firmware file is missing | The driver is present, but the firmware file it needs at startup was not found on disk. | `warning` | firmware alias, searched firmware directories, module name | Install the firmware package provided by your distribution for this device. LMFK will not download it. |
| `PACKAGE_UNKNOWN` | No package could be identified | LMFK could not confidently find a distribution package that provides this driver or firmware. | `info` | module name, backend queried, reason for uncertainty | Check your distribution's package search with the hardware ID or module name, or ask your distributor. |
| `INSUFFICIENT_INFORMATION` | Not enough information to conclude | Some system files were missing or unreadable, so LMFK cannot say whether a driver problem exists. | `info` | unreadable source, error message | Re-run with the missing information available; nothing has been changed on your system. |

The codes `DRIVER_UNBOUND` and any future code follow the same field contract. All messages must satisfy the four-part acceptance checklist in `04-driver-manager-spec.md` §7.1: clarity, explanation, consequences and advised action.

---

## 13. Complete example

The following example shows one PCI VGA device with a built-in, bound driver and present firmware, and one USB composite device with two interfaces where the Wi-Fi interface's module and firmware are missing and no package can be justified. The `PACKAGE_UNKNOWN` diagnosis accompanies the empty `package_suggestions` array, as required.

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-11-19T10:42:00Z",
  "host": {
    "kernel_release": "6.1.0-13-amd64",
    "kernel_version": "#1 SMP 6.1.52-1 (2023-09-07)",
    "arch": "x86_64",
    "distro_id": "example-distro",
    "distro_version": "1",
    "secure_boot": "enabled"
  },
  "scan": {
    "sources": [
      "/sys/bus/pci/devices",
      "/sys/bus/usb/devices",
      "/sys/class",
      "/proc/modules",
      "/lib/modules/6.1.0-13-amd64/modules.alias",
      "/lib/modules/6.1.0-13-amd64/modules.builtin",
      "/lib/modules/6.1.0-13-amd64/modules.dep",
      "modinfo",
      "/lib/firmware",
      "/etc/os-release",
      "package-manager query"
    ],
    "read_only": true,
    "errors": [
      {
        "source": "/lib/modules/6.1.0-13-amd64/modules.alias.bin",
        "message": "permission denied; fell back to modules.alias"
      }
    ]
  },
  "devices": [
    {
      "id": "pci:0000:00:02.0",
      "bus": "pci",
      "class": { "code": "0x030000", "name": "VGA compatible controller" },
      "vendor": { "id": "0x8086", "name": "Intel Corporation" },
      "device": { "id": "0x9bc4", "name": "UHD Graphics 630" },
      "subsystem": { "vendor": "0x8086", "device": "0x0000" },
      "modalias": "pci:v00008086d00009BC4sv00008086sd00000000bc03sc00i00",
      "path": "/sys/bus/pci/devices/0000:00:02.0",
      "parent": null,
      "interfaces": [],
      "driver": { "bound": "i915", "state": "bound" },
      "modules": [
        {
          "name": "i915",
          "match_source": "modules.alias",
          "state": "builtin",
          "dependencies": ["drm", "drm_kms_helper"],
          "firmwares": [
            {
              "alias": "i915/kbl_dmc_ver1_04.bin",
              "present": true,
              "paths": ["/lib/firmware/i915/kbl_dmc_ver1_04.bin"]
            }
          ]
        }
      ],
      "firmwares": [
        {
          "alias": "i915/kbl_dmc_ver1_04.bin",
          "present": true,
          "paths": ["/lib/firmware/i915/kbl_dmc_ver1_04.bin"]
        }
      ],
      "package_suggestions": [
        {
          "backend": "example-package-manager",
          "package": "linux-image-amd64",
          "reason": "provides the running kernel that contains the built-in i915 driver",
          "confidence": "low"
        }
      ],
      "diagnosis": []
    },
    {
      "id": "usb:1-4",
      "bus": "usb",
      "class": { "code": "0x000000", "name": "Unspecified" },
      "vendor": { "id": "0x0bda", "name": "Realtek Semiconductor Corp." },
      "device": { "id": "0x8812", "name": "RTL8812AU 802.11ac WLAN Adapter" },
      "subsystem": { "vendor": "0x0bda", "device": "0x8812" },
      "modalias": "usb:v0BDAp8812d0000dc00dsc00dp00ic00isc00if00",
      "path": "/sys/bus/usb/devices/1-4",
      "parent": "usb:1-0",
      "interfaces": [
        {
          "id": "usb:1-4:1.0",
          "device_id": "usb:1-4",
          "interface_number": 0,
          "class": { "code": "0x000200", "name": "Communications" },
          "modalias": "usb:v0BDAp8812d0000dc02dsc00dp00ic02isc00if00",
          "driver": { "bound": "cdc_acm", "state": "bound" }
        },
        {
          "id": "usb:1-4:1.1",
          "device_id": "usb:1-4",
          "interface_number": 1,
          "class": { "code": "0x000a00", "name": "Wireless" },
          "modalias": "usb:v0BDAp8812d0000dc0adsc00dp00ic0aisc00if00",
          "driver": { "bound": null, "state": "unbound" }
        }
      ],
      "driver": { "bound": null, "state": "unbound" },
      "modules": [
        {
          "name": "rtl8812au",
          "match_source": "modules.alias",
          "state": "missing",
          "dependencies": [],
          "firmwares": [
            {
              "alias": "rtlwifi/rtl8812aufw.bin",
              "present": false,
              "paths": []
            }
          ]
        }
      ],
      "firmwares": [
        {
          "alias": "rtlwifi/rtl8812aufw.bin",
          "present": false,
          "paths": []
        }
      ],
      "package_suggestions": [],
      "diagnosis": [
        {
          "code": "MODULE_MISSING",
          "title": "No driver found for this device",
          "explanation": "The wireless interface has a hardware ID that matches no module available for the running kernel, so Linux cannot drive it right now.",
          "severity": "error",
          "evidence": [
            "modalias usb:v0BDAp8812d0000dc0adsc00dp00ic0aisc00if00",
            "kernel 6.1.0-13-amd64",
            "/lib/modules/6.1.0-13-amd64/modules.alias"
          ],
          "advised_action": "Check whether your distribution offers a driver package for this device, or whether a newer kernel supports it.",
          "message": "No driver found for this device. The wireless interface matches no module for this kernel, so it cannot be used. Check your distribution's driver packages or a newer kernel. LMFK will not install anything automatically."
        },
        {
          "code": "FIRMWARE_MISSING",
          "title": "Required firmware file is missing",
          "explanation": "The driver is present, but the firmware file it needs at startup was not found on disk.",
          "severity": "warning",
          "evidence": [
            "firmware rtlwifi/rtl8812aufw.bin",
            "/lib/firmware",
            "module rtl8812au"
          ],
          "advised_action": "Install the firmware package provided by your distribution for this device.",
          "message": "Required firmware file is missing. The driver needs rtlwifi/rtl8812aufw.bin, which is not present under /lib/firmware, so the device may not start. Install the matching firmware package from your distribution; LMFK will not download it."
        },
        {
          "code": "DRIVER_UNBOUND",
          "title": "Interface has no driver bound",
          "explanation": "The wireless interface is present but no driver is currently attached to it.",
          "severity": "warning",
          "evidence": ["interface usb:1-4:1.1", "driver.bound is null"],
          "advised_action": "Check that the correct driver is available for this interface; LMFK does not load or bind drivers.",
          "message": "Interface has no driver bound. The wireless interface usb:1-4:1.1 has no active driver, so it cannot be used yet. Check that its driver is available; LMFK will not load it."
        },
        {
          "code": "PACKAGE_UNKNOWN",
          "title": "No package could be identified",
          "explanation": "LMFK could not confidently find a distribution package that provides this driver or firmware.",
          "severity": "info",
          "evidence": ["module rtl8812au", "package-manager query returned no match"],
          "advised_action": "Search your distribution's packages using the hardware ID or module name, or ask your distributor.",
          "message": "No package could be identified. No distribution package could be confidently matched to rtl8812au, so no installation is suggested. Search your distribution's packages with the hardware ID or module name."
        }
      ]
    }
  ],
  "summary": {
    "devices": 2,
    "with_driver": 2,
    "without_driver": 0,
    "missing_firmware": 1,
    "errors": 1
  }
}
```

The values `distro_id`, `distro_version` and `suggestion.backend` in this example are **illustrative only**. The schema accepts any string for them; a new distribution can be added without changing the structure.

---

## 14. Reproducible validation (Phase 0 exit criterion)

Phase 0 provides a repeatable validation procedure rather than a code artifact. The command below checks that the example is valid JSON, has the required top-level fields and uses the declared `schema_version`:

```sh
python3 - <<'PY'
import json, re, sys, pathlib
doc = pathlib.Path('docs/en/06-inventory-schema.md').read_text()
block = re.search(r'```json\n(.*?)\n```', doc, re.S).group(1)
data = json.loads(block)
required = {'schema_version','generated_at','host','scan','devices','summary'}
assert required <= data.keys(), required - data.keys()
assert data['schema_version'] == '1.0'
assert data['scan']['read_only'] is True
assert data['summary']['devices'] == len(data['devices'])
print('valid example OK')
PY
```

Invalid examples that the validator or implementer must reject, each with its reason:

| Invalid example | Expected rejection reason |
|---|---|
| `schema_version` missing or not `"1.0"` | Compatibility contract violated |
| `scan.read_only` set to `false` | A read-only scan must declare `read_only: true` |
| `device.id` containing an absolute path such as `/sys/bus/pci/...` | Public IDs must be logical, not host paths |
| `package_suggestions: []` with no `PACKAGE_UNKNOWN` diagnosis | Empty suggestions require an explicit diagnosis |
| `module.state` value `"installed"` | Not in the closed module-state set |
| `diagnosis` entry missing `title`, `explanation`, `evidence` or `advised_action` | Beginner-facing diagnostic contract incomplete |

---

## 15. Future extension points (non-normative, not in v1.0)

The binary-first resolution strategy of `04-driver-manager-spec.md` §3.1 requires information that is **not part of schema v1.0**. Later versions may add, without changing the v1.0 contract:

- `host.kernel_arch` and `host.kernel_features` — exact architecture and relevant kernel configuration;
- `module.origin` — one of `builtin`, `precompiled`, `dkms`, `local_build` or `unknown`, so precompiled modules can be distinguished from DKMS and locally built ones;
- `module.abi_compatible` — whether the module metadata matches the running kernel;
- a `resolution` object — ordered candidates, selected option, package names, reason, whether local compilation would be required, and a plain-language explanation when no compatible binary exists;
- dependency and firmware availability flags, and an indicator that a kernel update invalidated a previously working module.

These fields are **not valid in `"1.0"`** and readers must continue to ignore unknown fields. Their introduction requires a schema version bump. Nothing in this section authorises compilation, installation or privileged work; the MVP remains read-only and terminal-only.

---

Companion documents: `04-driver-manager-spec.md`, `05-hw-scanner-spec.md`.
