from __future__ import annotations

import inspect
import json
import runpy
import shutil
import struct
import subprocess
import tempfile
from contextlib import nullcontext
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import Mock, patch

from kvm_aavm import build, cli, hooks, host, kernel, offline, state, vm
from kvm_aavm.build import (
    _adapt_qemu_script,
    _validate_generated_vars,
    _validate_ovmf_firmware_identity,
    _validate_ovmf_measured_boot,
    _validate_qemu_firmware_hardening,
    _validate_qemu_kvm_hypercall_hardening,
)
from kvm_aavm.hardware import (
    PciDevice, device_identity, kvm_capabilities, parse_usb_line, vm_cpu_layout,
)
from kvm_aavm.host import _managed_kvm_module_config, _replace_grub_args, _set_nested_module_option
from kvm_aavm.identity import apply_board_identity, generate, mac_address, rerandomize
from kvm_aavm.util import AppError
from kvm_aavm.vm import _ensure_disk, _ensure_install_ovmf_code, _stage_install_media
from kvm_aavm.xmlgen import (
    AAVM_NS, INSTALL_MACHINE_TYPE, INSTALL_OVMF_CODE, INSTALL_OVMF_VARS, INSTALL_QEMU,
    build_domain_xml, update_artifact_paths, update_identity,
    update_passthrough, validate_required,
)
from tools import prune_superseded_debs


def profile() -> dict:
    cpu = {"vendor": "amd", "model": "AMD Test CPU", "virtualization": "svm", "threads_per_core": 2}
    identity = generate(cpu)
    return {
        "name": "test-vm", "owner_uid": 1000,
        "host": {"cpu": cpu}, "identity": identity,
        "resources": {"disk_gib": 240, "memory_gib": 8, "vcpus": 4, "threads_per_core": 2},
        "paths": {
            "disk": "/var/lib/libvirt/images/test-vm.qcow2", "windows_iso": "/iso/windows.iso",
            "qemu": "/vm/current/bin/qemu-system-x86_64", "ovmf_code": "/vm/current/ovmf/code.qcow2",
            "ovmf_vars": "/vm/current/ovmf/vars.qcow2", "ssdt": ["/vm/ssdt1.aml", "/vm/ssdt2.aml"],
        },
        "passthrough": {"mode": "manual", "pci": []},
    }


class IdentityTests(unittest.TestCase):
    def test_mac_is_local_unicast(self):
        value = mac_address()
        first = int(value.split(":")[0], 16)
        self.assertEqual(first & 1, 0)
        self.assertEqual(first & 2, 2)

    def test_generation_changes(self):
        before = profile()
        after = rerandomize(before)
        self.assertEqual(after["identity"]["generation"], before["identity"]["generation"] + 1)
        self.assertNotEqual(after["identity"]["domain_uuid"], before["identity"]["domain_uuid"])

    def test_identity_platform_matches_cpu_vendor(self):
        amd = generate({"vendor": "amd", "model": "AMD Test CPU"})
        intel = generate({"vendor": "intel", "model": "Intel Test CPU"})
        self.assertNotIn(amd["manufacturer"], {"Dell Inc.", "LENOVO"})
        self.assertNotIn(
            intel["product"],
            {"TUF GAMING B850-PLUS WIFI", "B650 AORUS ELITE AX", "PRO B650-P WIFI"},
        )

    def test_board_pin_preserves_randomized_serials_and_future_identity_rotation(self):
        before = profile()
        serials = {
            key: before["identity"][key]
            for key in ("system_serial", "baseboard_serial", "chassis_serial")
        }
        board = {
            "manufacturer": "ASUSTeK COMPUTER INC.",
            "product": "TUF GAMING B850-PLUS WIFI",
            "version": "Rev 1.xx",
        }
        aligned = apply_board_identity(before["identity"], board)
        self.assertEqual(aligned["manufacturer"], board["manufacturer"])
        self.assertEqual(aligned["product"], board["product"])
        self.assertEqual(aligned["baseboard_product"], board["product"])
        self.assertEqual(aligned["version"], board["version"])
        self.assertEqual(
            {key: aligned[key] for key in serials}, serials,
        )
        before["identity_board"] = board
        rotated = rerandomize(before)
        self.assertEqual(rotated["identity"]["manufacturer"], board["manufacturer"])
        self.assertEqual(rotated["identity"]["product"], board["product"])
        self.assertEqual(rotated["identity"]["baseboard_product"], board["product"])
        self.assertEqual(rotated["identity"]["version"], board["version"])


class HardwareTests(unittest.TestCase):
    def test_device_identity_uses_real_class_matched_bridge_fallbacks(self):
        memory_controller = PciDevice(
            "00:18.0", "0500", "1022", "14e0", "Data Fabric memory controller",
        )
        identity = device_identity([memory_controller], "amd")
        self.assertEqual(identity["pcibridge"], "1633")
        self.assertEqual(identity["xhci"], "7914")

        bridge = PciDevice(
            "00:01.1", "0604", "1022", "14db", "PCIe GPP Bridge",
        )
        identity = device_identity([memory_controller, bridge], "amd")
        self.assertEqual(identity["pcibridge"], "14db")

    def test_older_amd_capabilities_do_not_require_missing_accelerators(self):
        cpu = {
            "vendor": "amd", "virtualization": "svm",
            "x86_features": ["svm", "npt"],
        }
        with patch(
            "kvm_aavm.hardware._module_parameter_enabled", return_value=True,
        ):
            capabilities = kvm_capabilities(cpu)
        self.assertTrue(capabilities["nested"])
        self.assertTrue(capabilities["npt"])
        self.assertFalse(capabilities["avic"])
        self.assertTrue(capabilities["gmet"])

    def test_layout_reserves_two_smt_cores_and_pairs_guest_threads(self):
        info = {
            "threads_per_core": 2,
            "thread_siblings": [[0, 8], [1, 9], [2, 10], [3, 11], [4, 12], [5, 13], [6, 14], [7, 15]],
        }
        layout = vm_cpu_layout(info, 12)
        self.assertEqual(layout["threads_per_core"], 2)
        self.assertEqual(layout["cores"], 6)
        self.assertEqual(layout["vcpu_pins"], [2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15])
        self.assertEqual(layout["emulator_cpus"], [0, 1, 8, 9])

    def test_amd_native_cpuid_layout_aligns_vcpu_and_physical_apic_ids(self):
        info = {
            "vendor": "amd",
            "threads_per_core": 2,
            "thread_siblings": [
                [0, 8], [1, 9], [2, 10], [3, 11],
                [4, 12], [5, 13], [6, 14], [7, 15],
            ],
            "native_apic_ids": {
                "0": 0, "8": 1, "1": 2, "9": 3,
                "2": 4, "10": 5, "3": 6, "11": 7,
                "4": 8, "12": 9, "5": 10, "13": 11,
                "6": 12, "14": 13, "7": 14, "15": 15,
            },
        }
        layout = vm_cpu_layout(info, 12)
        self.assertEqual(
            layout["vcpu_pins"],
            [0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13],
        )
        self.assertEqual(layout["emulator_cpus"], [6, 7, 14, 15])

    def test_amd_full_native_cpuid_layout_shares_final_two_host_cores(self):
        info = {
            "vendor": "amd",
            "threads_per_core": 2,
            "thread_siblings": [
                [0, 8], [1, 9], [2, 10], [3, 11],
                [4, 12], [5, 13], [6, 14], [7, 15],
            ],
            "native_apic_ids": {
                "0": 0, "8": 1, "1": 2, "9": 3,
                "2": 4, "10": 5, "3": 6, "11": 7,
                "4": 8, "12": 9, "5": 10, "13": 11,
                "6": 12, "14": 13, "7": 14, "15": 15,
            },
        }
        layout = vm_cpu_layout(info, 16, shared_emulator_cores=2)
        self.assertEqual(
            layout["vcpu_pins"],
            [0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15],
        )
        self.assertEqual(layout["emulator_cpus"], [6, 7, 14, 15])
        self.assertTrue(layout["emulator_shared"])

class XmlTests(unittest.TestCase):
    def test_older_amd_without_topoext_keeps_same_host_passthrough_logic(self):
        value = profile()
        value["host"]["cpu"]["x86_features"] = ["svm", "npt"]
        root = ET.fromstring(build_domain_xml(value, stage="final"))
        self.assertIsNone(root.find("./cpu/feature[@name='topoext']"))
        self.assertEqual(root.find("./cpu").get("mode"), "host-passthrough")

    def test_tpm_backends_use_supported_libvirt_xml(self):
        emulated = profile()
        emulated["tpm"] = {"mode": "emulator", "model": "tpm-crb"}
        root = ET.fromstring(build_domain_xml(emulated, stage="final"))
        self.assertIsNotNone(
            root.find("./devices/tpm[@model='tpm-crb']/backend"
                      "[@type='emulator'][@version='2.0'][@persistent_state='yes']")
        )
        self.assertEqual(validate_required(ET.tostring(root, encoding="unicode")), [])

    def test_amd_ftpm_profile_requires_crb_and_is_persisted_in_metadata(self):
        value = profile()
        value["tpm"] = {
            "mode": "emulator", "model": "tpm-crb", "version": "2.0",
            "profile": "amd-ftpm",
        }
        root = ET.fromstring(build_domain_xml(value, stage="final"))
        stage = root.find("./metadata/{https://kvm-aavm.local/xmlns/domain/1.0}stage")
        self.assertEqual(stage.get("tpm-profile"), "amd-ftpm")
        self.assertIsNotNone(root.find("./devices/tpm[@model='tpm-crb']/backend[@type='emulator']"))
        self.assertEqual(validate_required(ET.tostring(root, encoding="unicode")), [])

        value["tpm"]["model"] = "tpm-tis"
        with self.assertRaisesRegex(AppError, "requires the tpm-crb"):
            build_domain_xml(value, stage="final")

    def test_unsupported_tpm_mode_is_rejected(self):
        value = profile()
        value["tpm"] = {"mode": "passthrough", "device": "/dev/tpm0"}
        with self.assertRaisesRegex(AppError, "Unsupported TPM mode"):
            build_domain_xml(value, stage="final")

    def test_smt_topology_and_cpu_pinning_are_emitted(self):
        value = profile()
        value["resources"].update({
            "vcpus": 12,
            "threads_per_core": 2,
            "cpu_pinning": {
                "vcpus": [2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15],
                "emulator": [0, 1, 8, 9],
            },
        })
        root = ET.fromstring(build_domain_xml(value, stage="final"))
        topology = root.find("./cpu/topology")
        self.assertEqual(topology.attrib, {"sockets": "1", "cores": "6", "threads": "2"})
        pins = root.findall("./cputune/vcpupin")
        self.assertEqual(len(pins), 12)
        self.assertEqual(pins[0].attrib, {"vcpu": "0", "cpuset": "2"})
        self.assertEqual(pins[1].attrib, {"vcpu": "1", "cpuset": "10"})
        self.assertEqual(root.find("./cputune/emulatorpin").get("cpuset"), "0,1,8,9")

    def test_svme_gated_native_cpuid_accepts_contiguous_native_apic_subset(self):
        value = profile()
        value["host"]["cpu"].update({
            "logical_cpus": 4,
            "native_apic_ids": {"0": 0, "2": 1, "1": 2, "3": 3},
        })
        value["resources"].update({
            "vcpus": 4,
            "threads_per_core": 2,
            "cpuid_policy": "svme-gated-native",
            "cpu_pinning": {
                "vcpus": [0, 2, 1, 3],
                "emulator": [1, 3],
            },
        })
        root = ET.fromstring(build_domain_xml(value, stage="final"))
        stage = root.find(f"./metadata/{{{AAVM_NS}}}stage")
        self.assertEqual(stage.get("cpuid-policy"), "svme-gated-native")
        self.assertEqual(root.findtext("./vcpu"), "4")
        value["resources"]["vcpus"] = 2
        value["resources"]["cpu_pinning"] = {
            "vcpus": [0, 2],
            "emulator": [1, 3],
        }
        subset = ET.fromstring(build_domain_xml(value, stage="final"))
        self.assertEqual(subset.findtext("./vcpu"), "2")
        value["resources"]["cpu_pinning"]["vcpus"] = [0, 1]
        with self.assertRaisesRegex(AppError, "same native APIC ID"):
            build_domain_xml(value, stage="final")

    def test_required_vtd_xml_is_delayed_until_patched_stage(self):
        xml = build_domain_xml(profile())
        self.assertEqual(validate_required(xml), [])
        root = ET.fromstring(xml)
        self.assertEqual(root.find("./os/type").get("machine"), INSTALL_MACHINE_TYPE)
        self.assertEqual(root.findtext("./devices/emulator"), INSTALL_QEMU)
        self.assertEqual(root.findtext("./os/loader"), INSTALL_OVMF_CODE)
        self.assertEqual(root.find("./os/loader").get("format"), "raw")
        self.assertIsNotNone(root.find("./cpu/feature[@name='svm'][@policy='disable']"))
        self.assertIsNone(root.find("./cpu/feature[@name='vmx']"))
        self.assertIsNone(root.find("./devices/disk[@device='disk']/wwn"))
        self.assertIsNone(root.find("./features/ioapic"))
        self.assertIsNone(root.find("./devices/iommu"))

        qemu_args = [
            arg.get("value", "")
            for arg in root.findall(
                "./{http://libvirt.org/schemas/domain/qemu/1.0}commandline/"
                "{http://libvirt.org/schemas/domain/qemu/1.0}arg"
            )
        ]
        type17 = next(value for value in qemu_args if value.startswith("type=17,"))
        self.assertNotIn(",size=", type17)
        self.assertFalse(any(value.startswith("type=9,") for value in qemu_args))
        self.assertIsNotNone(root.find("./devices/sound[@model='ich9']/codec[@type='duplex']"))
        self.assertIsNotNone(root.find("./devices/audio[@type='spice']"))
        self.assertIsNone(root.find("./devices/audio[@type='pipewire']"))
        self.assertFalse(any(
            "ssdt" in (arg.get("value") or "").lower()
            for arg in root.findall(
                "./{http://libvirt.org/schemas/domain/qemu/1.0}commandline/"
                "{http://libvirt.org/schemas/domain/qemu/1.0}arg"
            )
        ))

        patched = ET.fromstring(build_domain_xml(profile(), stage="final"))
        self.assertEqual(patched.find("./os/type").get("machine"), "pc-q35-11.0")
        self.assertEqual(
            patched.findtext("./devices/emulator"),
            "/vm/current/bin/qemu-system-x86_64",
        )
        self.assertEqual(patched.find("./os/loader").get("format"), "qcow2")
        self.assertIsNotNone(patched.find("./features/ioapic[@driver='qemu']"))
        self.assertIsNone(patched.find("./devices/iommu"))

        vtd_profile = profile()
        vtd_profile["guest_vtd"] = True
        vtd_profile["guest_secure_boot"] = True
        vtd_profile["guest_dma_protection"] = True
        vtd_root = ET.fromstring(build_domain_xml(vtd_profile, stage="final"))
        iommu_driver = vtd_root.find(
            "./devices/iommu[@model='intel']/driver"
            "[@intremap='off'][@caching_mode='on']"
        )
        self.assertIsNotNone(iommu_driver)
        self.assertNotIn("aw_bits", iommu_driver.attrib)
        vtd_stage = vtd_root.find(
            "./metadata/{https://kvm-aavm.local/xmlns/domain/1.0}stage"
        )
        self.assertEqual(vtd_stage.get("guest-secure-boot"), "true")
        self.assertEqual(vtd_stage.get("guest-dma-protection"), "true")
        vtd_qemu_args = [
            arg.get("value", "") for arg in vtd_root.findall(
                "./{http://libvirt.org/schemas/domain/qemu/1.0}commandline/"
                "{http://libvirt.org/schemas/domain/qemu/1.0}arg"
            )
        ]
        self.assertIn("intel-iommu.dma-control-platform-opt-in=on", vtd_qemu_args)
        iommu_driver.attrib.pop("caching_mode")
        self.assertIn(
            "Missing required XML: Intel guest IOMMU",
            validate_required(ET.tostring(vtd_root, encoding="unicode")),
        )
        patched_qemu_args = [
            arg.get("value", "")
            for arg in patched.findall(
                "./{http://libvirt.org/schemas/domain/qemu/1.0}commandline/"
                "{http://libvirt.org/schemas/domain/qemu/1.0}arg"
            )
        ]
        self.assertTrue(any(value.startswith("type=9,") for value in patched_qemu_args))
        self.assertTrue(any(
            "ssdt1.aml" in (arg.get("value") or "")
            for arg in patched.findall(
                "./{http://libvirt.org/schemas/domain/qemu/1.0}commandline/"
                "{http://libvirt.org/schemas/domain/qemu/1.0}arg"
            )
        ))

    def test_validation_rejects_unsupported_smbios_type17_size(self):
        root = ET.fromstring(build_domain_xml(profile()))
        for arg in root.findall(
            "./{http://libvirt.org/schemas/domain/qemu/1.0}commandline/"
            "{http://libvirt.org/schemas/domain/qemu/1.0}arg"
        ):
            if arg.get("value", "").startswith("type=17,"):
                arg.set("value", arg.get("value") + ",size=8192")
                break
        errors = validate_required(ET.tostring(root, encoding="unicode"))
        self.assertIn("Unsupported QEMU SMBIOS type 17 option: size", errors)

    def test_validation_rejects_host_user_pipewire_backend(self):
        root = ET.fromstring(build_domain_xml(profile()))
        audio = root.find("./devices/audio")
        audio.set("type", "pipewire")
        audio.set("runtimeDir", "/run/user/1000")
        errors = validate_required(ET.tostring(root, encoding="unicode"))
        self.assertIn("Unsupported system-libvirt audio backend: pipewire", errors)

    def test_validation_rejects_spice_audio_without_spice_graphics(self):
        root = ET.fromstring(build_domain_xml(profile()))
        graphics = root.find("./devices/graphics")
        graphics.set("type", "vnc")
        errors = validate_required(ET.tostring(root, encoding="unicode"))
        self.assertIn("SPICE audio requires SPICE graphics", errors)

    def test_core_isolation_explicitly_exposes_only_the_host_virtualization_feature(self):
        value = profile()
        value["host"]["cpu"].update({"vendor": "intel", "virtualization": "vmx"})
        root = ET.fromstring(build_domain_xml(value))
        vmx = root.find("./cpu/feature[@name='vmx']")
        self.assertEqual(vmx.get("policy"), "disable")

        value["guest_core_isolation"] = True
        value["guest_secure_boot"] = True
        root = ET.fromstring(build_domain_xml(value, stage="final"))
        vmx = root.find("./cpu/feature[@name='vmx']")
        self.assertEqual(vmx.get("policy"), "require")
        self.assertIsNone(root.find("./cpu/feature[@name='svm']"))
        stage = root.find(
            "./metadata/{https://kvm-aavm.local/xmlns/domain/1.0}stage"
        )
        self.assertEqual(stage.get("guest-core-isolation"), "true")
        self.assertEqual(validate_required(ET.tostring(root, encoding="unicode")), [])

    def test_hvci_nested_hyperv_uses_amd_gmet_only_when_kvm_supports_it(self):
        value = profile()
        value["guest_secure_boot"] = True
        value["guest_core_isolation"] = True
        value["guest_hyperv_enlightenments"] = True
        value["host"]["kvm"] = {
            "nested": True, "npt": True, "avic": True, "gmet": True,
        }
        root = ET.fromstring(build_domain_xml(value, stage="final"))
        for feature in (
            "relaxed", "vapic", "spinlocks", "vpindex", "runtime", "synic",
            "stimer", "frequencies", "tlbflush", "ipi", "avic",
        ):
            self.assertIsNotNone(
                root.find(f"./features/hyperv/{feature}[@state='on']"), feature,
            )
        self.assertIsNotNone(
            root.find("./features/hyperv/spinlocks[@state='on'][@retries='8191']"),
        )
        self.assertIsNotNone(
            root.find("./features/hyperv/stimer/direct[@state='on']"),
        )
        self.assertIsNotNone(root.find("./clock/timer[@name='hypervclock'][@present='yes']"))
        args = {
            item.get("value") for item in root.findall(
                "./{http://libvirt.org/schemas/domain/qemu/1.0}commandline/"
                "{http://libvirt.org/schemas/domain/qemu/1.0}arg"
            )
        }
        self.assertTrue({
            "host-x86_64-cpu.gmet=on",
            "host-x86_64-cpu.hv-emsr-bitmap=on",
            "host-x86_64-cpu.hv-tlbflush-ext=on",
            "host-x86_64-cpu.hv-tlbflush-direct=on",
            "host-x86_64-cpu.cet-ss=off",
        }.issubset(args))
        self.assertEqual(validate_required(ET.tostring(root, encoding="unicode")), [])

    def test_hvci_nested_hyperv_omits_amd_globals_without_full_kvm_capabilities(self):
        value = profile()
        value["guest_secure_boot"] = True
        value["guest_core_isolation"] = True
        value["guest_hyperv_enlightenments"] = True
        value["host"]["kvm"] = {
            "nested": True, "npt": True, "avic": True, "gmet": False,
        }
        root = ET.fromstring(build_domain_xml(value, stage="final"))
        self.assertIsNotNone(root.find("./features/hyperv/stimer/direct[@state='on']"))
        self.assertIsNotNone(root.find("./features/hyperv/avic[@state='on']"))
        args = {
            item.get("value") for item in root.findall(
                "./{http://libvirt.org/schemas/domain/qemu/1.0}commandline/"
                "{http://libvirt.org/schemas/domain/qemu/1.0}arg"
            )
        }
        self.assertNotIn("host-x86_64-cpu.gmet=on", args)
        self.assertIn("host-x86_64-cpu.cet-ss=off", args)
        stage = root.find("./metadata/{https://kvm-aavm.local/xmlns/domain/1.0}stage")
        self.assertEqual(stage.get("guest-gmet"), "false")
        self.assertEqual(validate_required(ET.tostring(root, encoding="unicode")), [])

    def test_2m_hugepages_are_optional_and_validated(self):
        value = profile()
        value["resources"]["hugepages_2m"] = True
        root = ET.fromstring(build_domain_xml(value, stage="final"))
        self.assertIsNotNone(
            root.find("./memoryBacking/hugepages/page[@size='2048'][@unit='KiB']"),
        )
        self.assertIsNotNone(root.find("./memoryBacking/nosharepages"))
        self.assertEqual(validate_required(ET.tostring(root, encoding="unicode")), [])
        root.find("./memoryBacking").remove(root.find("./memoryBacking/nosharepages"))
        self.assertIn(
            "Hugepage memory must disable KSM sharing",
            validate_required(ET.tostring(root, encoding="unicode")),
        )

    def test_required_nested_virtualization_without_vbs_metadata_is_rejected(self):
        root = ET.fromstring(build_domain_xml(profile(), stage="final"))
        svm = root.find("./cpu/feature[@name='svm']")
        self.assertEqual(svm.get("policy"), "disable")
        svm.set("policy", "require")
        errors = validate_required(ET.tostring(root, encoding="unicode"))
        self.assertIn(
            "Guest SVM/VMX requires explicit Core Isolation/VBS metadata",
            errors,
        )

    def test_install_stage_keeps_nested_virtualization_hidden(self):
        value = profile()
        value["guest_core_isolation"] = True
        value["guest_secure_boot"] = True
        root = ET.fromstring(build_domain_xml(value, stage="install"))
        svm = root.find("./cpu/feature[@name='svm']")
        self.assertEqual(svm.get("policy"), "disable")
        self.assertEqual(validate_required(ET.tostring(root, encoding="unicode")), [])

    def test_core_isolation_requires_guest_secure_boot(self):
        value = profile()
        value["guest_core_isolation"] = True
        value["guest_secure_boot"] = False
        with self.assertRaisesRegex(AppError, "requires Guest UEFI Secure Boot"):
            build_domain_xml(value, stage="final")

    def test_odd_vcpu_uses_valid_topology(self):
        value = profile()
        value["resources"]["vcpus"] = 5
        root = ET.fromstring(build_domain_xml(value))
        topology = root.find("./cpu/topology")
        product = int(topology.get("sockets")) * int(topology.get("cores")) * int(topology.get("threads"))
        self.assertEqual(product, 5)

    def test_xml_identity_rotation_preserves_acpi_tables(self):
        original = profile()
        xml = build_domain_xml(original, stage="final")
        rotated = rerandomize(original)
        changed = update_identity(xml, rotated["identity"], 8)
        self.assertIn(rotated["identity"]["system_serial"], changed)
        self.assertIn("file=/vm/ssdt1.aml", changed)
        self.assertNotIn(",size=", changed)
        self.assertEqual(validate_required(changed), [])

    def test_install_identity_rotation_does_not_restore_patched_type9(self):
        original = profile()
        xml = build_domain_xml(original, stage="install")
        rotated = rerandomize(original)
        changed = update_identity(xml, rotated["identity"], 8)
        root = ET.fromstring(changed)
        qemu_args = [
            arg.get("value", "")
            for arg in root.findall(
                "./{http://libvirt.org/schemas/domain/qemu/1.0}commandline/"
                "{http://libvirt.org/schemas/domain/qemu/1.0}arg"
            )
        ]
        self.assertFalse(any(value.startswith("type=9,") for value in qemu_args))
        self.assertEqual(validate_required(changed), [])

    def test_identity_rotation_removes_unsupported_sata_wwn(self):
        original = profile()
        root = ET.fromstring(build_domain_xml(original))
        disk = root.find("./devices/disk[@device='disk']")
        ET.SubElement(disk, "wwn").text = "0123456789abcdef"
        rotated = rerandomize(original)
        changed = ET.fromstring(
            update_identity(ET.tostring(root, encoding="unicode"), rotated["identity"], 8)
        )
        self.assertIsNone(changed.find("./devices/disk[@device='disk']/wwn"))

        scsi_disk = changed.find("./devices/disk[@device='disk']")
        scsi_disk.find("target").set("bus", "scsi")
        changed_again = ET.fromstring(
            update_identity(ET.tostring(changed, encoding="unicode"), rotated["identity"], 8)
        )
        self.assertEqual(
            changed_again.find("./devices/disk[@device='disk']/wwn").text,
            rotated["identity"]["disk_wwn"].removeprefix("0x"),
        )

    def test_single_gpu_is_delayed_until_finalize(self):
        value = profile()
        value["passthrough"] = {
            "mode": "single-gpu",
            "pci": ["01:00.0", "01:00.1", "09:00.0"],
            "gpu_pci": ["01:00.0", "01:00.1"],
            "extra_pci": ["09:00.0"],
            "usb": [],
            "disable_virtual_network": False,
        }

        def addresses(xml_text):
            root = ET.fromstring(xml_text)
            result = []
            for source in root.findall("./devices/hostdev[@type='pci']/source/address"):
                result.append(
                    f"{int(source.get('bus'), 16):02x}:"
                    f"{int(source.get('slot'), 16):02x}."
                    f"{int(source.get('function'), 16)}"
                )
            return result, root

        install_addresses, install_root = addresses(build_domain_xml(value, install_stage=True))
        self.assertEqual(install_addresses, [])
        self.assertIsNotNone(install_root.find("./devices/graphics[@type='spice']"))
        self.assertIsNotNone(install_root.find("./devices/video"))

        value["host"]["pci"] = [
            {"address": "01:00.0", "class_code": "0300", "iommu_group": 12},
            {"address": "01:00.1", "class_code": "0403", "iommu_group": 12},
            {"address": "09:00.0", "class_code": "0200", "iommu_group": 19},
        ]
        devirt_addresses, devirt_root = addresses(
            build_domain_xml(value, stage="devirtualized")
        )
        self.assertEqual(devirt_addresses, [])
        self.assertIsNone(devirt_root.find("./devices/iommu"))
        value["guest_vtd"] = True
        guest_vtd_root = ET.fromstring(build_domain_xml(value, stage="devirtualized"))
        guest_vtd_driver = guest_vtd_root.find(
            "./devices/iommu[@model='intel']/driver"
            "[@intremap='off'][@caching_mode='on']"
        )
        self.assertIsNotNone(guest_vtd_driver)
        self.assertNotIn("aw_bits", guest_vtd_driver.attrib)
        value["guest_vtd_intremap"] = True
        full_vtd_root = ET.fromstring(build_domain_xml(value, stage="devirtualized"))
        self.assertIsNotNone(full_vtd_root.find(
            "./devices/iommu[@model='intel']/driver"
            "[@intremap='on'][@caching_mode='on']"
        ))
        stage_element = devirt_root.find(
            "./metadata/{https://kvm-aavm.local/xmlns/domain/1.0}stage"
        )
        self.assertEqual(stage_element.text, "devirtualized")
        self.assertIsNone(stage_element.get("single-gpu"))
        self.assertEqual(
            validate_required(ET.tostring(devirt_root, encoding="unicode")), []
        )
        self.assertEqual(devirt_root.findall("./devices/hostdev"), [])
        self.assertIsNotNone(devirt_root.find("./devices/graphics[@type='vnc']"))
        self.assertIsNotNone(devirt_root.find("./devices/video"))
        x_vga_path = (
            "./{http://libvirt.org/schemas/domain/qemu/1.0}override/"
            "{http://libvirt.org/schemas/domain/qemu/1.0}device/"
            "{http://libvirt.org/schemas/domain/qemu/1.0}frontend/"
            "{http://libvirt.org/schemas/domain/qemu/1.0}property"
            "[@name='x-vga'][@type='bool'][@value='true']"
        )
        self.assertIsNone(devirt_root.find(x_vga_path))
        self.assertEqual(devirt_root.findtext("./on_reboot"), "restart")
        self.assertIsNone(devirt_root.find("./devices/disk[@device='cdrom']"))
        self.assertIsNotNone(devirt_root.find("./devices/sound"))
        self.assertIsNotNone(devirt_root.find("./devices/audio[@type='none']"))
        self.assertIsNone(devirt_root.find("./devices/audio[@type='spice']"))

        maintenance_addresses, maintenance_root = addresses(
            build_domain_xml(value, stage="gpu-setup")
        )
        self.assertEqual(maintenance_addresses, ["01:00.0", "09:00.0"])
        maintenance_stage = maintenance_root.find(
            "./metadata/{https://kvm-aavm.local/xmlns/domain/1.0}stage"
        )
        self.assertEqual(maintenance_stage.text, "gpu-setup")
        self.assertIsNone(maintenance_stage.get("single-gpu"))
        self.assertIsNotNone(maintenance_root.find("./devices/graphics[@type='vnc']"))
        self.assertIsNotNone(maintenance_root.find("./devices/video"))
        self.assertIsNotNone(maintenance_root.find("./devices/audio[@type='none']"))
        self.assertIsNone(maintenance_root.find(x_vga_path))
        self.assertEqual(maintenance_root.findtext("./on_reboot"), "destroy")
        self.assertEqual(
            maintenance_root.find("./devices/hostdev[@type='pci']/rom").get("bar"),
            "off",
        )
        self.assertEqual(validate_required(
            ET.tostring(maintenance_root, encoding="unicode")
        ), [])

        value["guest_vtd_intremap"] = False
        final_addresses, final_root = addresses(build_domain_xml(value, stage="final"))
        # Old profiles without gpu_guest_pci preserve their display-only guest
        # exposure. Both functions remain in gpu_pci for
        # host isolation by the single-GPU hook.
        self.assertEqual(final_addresses, ["01:00.0", "09:00.0"])
        self.assertIsNotNone(final_root.find(
            "./devices/iommu[@model='intel']/driver"
            "[@intremap='off'][@caching_mode='on']"
        ))
        final_stage = final_root.find(
            "./metadata/{https://kvm-aavm.local/xmlns/domain/1.0}stage"
        )
        self.assertEqual(final_stage.get("guest-vtd"), "true")
        self.assertEqual(final_stage.get("guest-vtd-intremap"), "false")
        self.assertIsNone(final_root.find(
            "./devices/controller[@type='pci'][@model='pcie-to-pci-bridge']"
        ))
        self.assertIsNotNone(final_root.find(x_vga_path))
        self.assertEqual(
            final_root.find("./devices/hostdev[@type='pci']/rom").get("bar"), "off"
        )
        self.assertEqual(validate_required(
            ET.tostring(final_root, encoding="unicode")
        ), [])
        value["passthrough"]["gpu_rom_bar"] = True
        rom_on_root = ET.fromstring(build_domain_xml(value, stage="final"))
        self.assertEqual(
            rom_on_root.find("./devices/hostdev[@type='pci']/rom").get("bar"), "on"
        )
        self.assertEqual(validate_required(
            ET.tostring(rom_on_root, encoding="unicode")
        ), [])
        self.assertIsNone(final_root.find("./devices/graphics"))
        self.assertIsNone(final_root.find("./devices/video"))
        self.assertIsNone(final_root.find("./devices/sound"))
        self.assertIsNone(final_root.find("./devices/audio"))

        # When HDMI/DP audio is selected it shares the GPU's native PCIe slot
        # instead of the guest-vIOMMU bridge.
        value["passthrough"]["gpu_guest_pci"] = ["01:00.0", "01:00.1"]
        audio_addresses, audio_root = addresses(build_domain_xml(value, stage="final"))
        self.assertEqual(audio_addresses, ["01:00.0", "01:00.1", "09:00.0"])
        gpu_hostdevs = audio_root.findall("./devices/hostdev[@type='pci']")[:2]
        guest_addresses = [item.find("address") for item in gpu_hostdevs]
        self.assertEqual({item.get("bus") for item in guest_addresses}, {"0x01"})
        self.assertEqual([item.get("function") for item in guest_addresses], ["0x0", "0x1"])
        self.assertEqual(guest_addresses[0].get("multifunction"), "on")
        self.assertIsNone(audio_root.find(
            "./devices/controller[@type='pci'][@model='pcie-to-pci-bridge']"
        ))
        managed_root_ports = [
            controller
            for controller in audio_root.findall(
                "./devices/controller[@type='pci'][@model='pcie-root-port']"
            )
            if (
                controller.find("alias") is not None
                and controller.find("alias").get("name", "").startswith(
                    "ua-kvm-aavm-pcie-"
                )
            )
        ]
        self.assertTrue(managed_root_ports)
        self.assertTrue(all(
            controller.find("target").get("hotplug") == "off"
            for controller in managed_root_ports
        ))
        self.assertIsNotNone(audio_root.find(
            "./devices/iommu[@model='intel']/driver"
            "[@intremap='off'][@caching_mode='on']"
        ))
        self.assertIsNotNone(audio_root.find(x_vga_path))

    def test_minimal_devices_remove_only_optional_qemu_devices(self):
        value = profile()
        value["minimal_devices"] = True
        root = ET.fromstring(build_domain_xml(value, install_stage=True))
        self.assertIsNone(root.find("./features/ps2"))
        qemu_args = [arg.get("value") for arg in root.findall("./{http://libvirt.org/schemas/domain/qemu/1.0}commandline/{http://libvirt.org/schemas/domain/qemu/1.0}arg")]
        self.assertIn("i8042=off", qemu_args)
        self.assertEqual(root.findall("./devices/input"), [])
        self.assertIsNone(root.find("./devices/interface"))
        self.assertIsNone(root.find("./devices/audio"))
        self.assertIsNone(root.find("./devices/sound"))
        self.assertIsNotNone(
            root.find("./devices/controller[@type='usb'][@model='none']")
        )
        self.assertIsNotNone(root.find("./devices/controller[@type='pci']"))
        self.assertIsNotNone(root.find("./devices/controller[@type='sata']"))
        self.assertIsNotNone(root.find("./devices/disk[@device='disk']"))
        self.assertIsNotNone(root.find("./devices/graphics[@type='spice']"))
        self.assertEqual(validate_required(ET.tostring(root, encoding="unicode")), [])

        value["passthrough"]["usb"] = [{
            "vendor_id": "1234", "product_id": "5678", "match_address": False,
        }]
        with_usb = ET.fromstring(build_domain_xml(value, stage="final"))
        self.assertIsNotNone(with_usb.find("./devices/controller[@type='usb'][@model='qemu-xhci']"))
        self.assertIsNotNone(with_usb.find("./devices/hostdev[@type='usb']"))

    def test_artifact_rotation_updates_every_path(self):
        xml = build_domain_xml(profile(), stage="final")
        paths = {
            "qemu": "/new/qemu", "ovmf_code": "/new/code.qcow2",
            "ovmf_vars": "/new/vars.qcow2", "ssdt": ["/new/a.aml", "/new/b.aml"],
        }
        changed = update_artifact_paths(xml, paths)
        for value in ("/new/qemu", "/new/code.qcow2", "/new/vars.qcow2", "/new/a.aml", "/new/b.aml"):
            self.assertIn(value, changed)

    def test_install_stage_artifact_rotation_keeps_safe_qemu_and_code(self):
        xml = build_domain_xml(profile(), stage="install")
        changed = update_artifact_paths(xml, {
            "qemu": "/new/qemu", "ovmf_code": "/new/code.qcow2",
            "ovmf_vars": "/new/vars.qcow2", "ssdt": ["/new/a.aml", "/new/b.aml"],
        })
        root = ET.fromstring(changed)
        self.assertEqual(root.findtext("./devices/emulator"), INSTALL_QEMU)
        self.assertEqual(root.findtext("./os/loader"), INSTALL_OVMF_CODE)
        self.assertEqual(root.findtext("./os/nvram"), "/new/vars.qcow2")
        self.assertNotIn("/new/a.aml", changed)

    def test_persistent_install_nvram_survives_patched_artifact_rotation(self):
        value = profile()
        value["paths"]["install_ovmf_vars"] = "/persistent/vars.qcow2"
        xml = build_domain_xml(value, stage="final")
        self.assertEqual(
            ET.fromstring(xml).findtext("./os/nvram"),
            "/persistent/vars.qcow2",
        )
        changed = update_artifact_paths(xml, {
            "qemu": "/new/qemu", "ovmf_code": "/new/code.qcow2",
            "ovmf_vars": "/new/generated-vars.qcow2",
            "install_ovmf_vars": "/persistent/vars.qcow2",
            "ssdt": ["/new/a.aml", "/new/b.aml"],
        })
        self.assertEqual(
            ET.fromstring(changed).findtext("./os/nvram"),
            "/persistent/vars.qcow2",
        )


class OfflineTests(unittest.TestCase):
    def test_offline_install_temporarily_releases_only_managed_holds(self):
        runner = Mock()
        runner.run.return_value = Mock(
            stdout="linux-headers-generic\ncustom-kernel\n",
        )
        with patch.object(offline, "load_host_state", return_value={
            "update_protection_enabled": True,
            "update_protection_managed_holds": ["linux-headers-generic"],
        }):
            released = offline._release_managed_update_holds(runner)
        self.assertEqual(released, ["linux-headers-generic"])
        runner.run.assert_any_call(
            ["apt-mark", "unhold", "linux-headers-generic"],
        )
        self.assertNotIn("custom-kernel", str(runner.run.call_args_list))

        offline._restore_managed_update_holds(runner, released)
        runner.run.assert_any_call(
            ["apt-mark", "hold", "linux-headers-generic"],
        )

    def test_deb_resolver_uses_repository_version_not_local_kernel_version(self):
        resolver = runpy.run_path(
            str(Path(__file__).parents[1] / "tools" / "resolve_debs.py"),
            run_name="resolve_debs_test",
        )
        runner = Mock(side_effect=[
            Mock(stdout="linux-libc-dev\n"),
            Mock(stdout=(
                "linux-libc-dev | 6.8.0-138.138 | "
                "http://archive.example noble-updates/main amd64 Packages\n"
            )),
        ])
        with patch.object(resolver["subprocess"], "run", runner):
            self.assertEqual(
                resolver["dependencies"](["linux-libc-dev"]),
                ["linux-libc-dev=6.8.0-138.138"],
            )

    def test_deb_pruner_reads_unlabelled_control_fields(self):
        result = Mock(stdout="curl\n8.5.0-2ubuntu10.13\namd64\n")
        with patch.object(
            prune_superseded_debs.subprocess, "run", return_value=result,
        ) as run:
            self.assertEqual(
                prune_superseded_debs.metadata(Path("curl.deb")),
                ("curl", "8.5.0-2ubuntu10.13", "amd64"),
            )
        self.assertIn("--showformat=${Package}\\n${Version}\\n${Architecture}\\n", run.call_args.args[0])

    def test_deb_pruner_keeps_newest_debian_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            old = directory / "curl_old_amd64.deb"
            new = directory / "curl_new_amd64.deb"
            old.touch()
            new.touch()

            def package_metadata(path):
                version = "8.5.0-2ubuntu10.11" if path == old else "8.5.0-2ubuntu10.13"
                return "curl", version, "amd64"

            with patch.object(
                prune_superseded_debs, "metadata", side_effect=package_metadata,
            ):
                removed = prune_superseded_debs.prune(directory)
            self.assertEqual(removed, [old])
            self.assertFalse(old.exists())
            self.assertTrue(new.exists())

    def test_deb_pruner_removes_duplicate_same_version_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            first = directory / "curl_a_amd64.deb"
            duplicate = directory / "curl_b_amd64.deb"
            first.touch()
            duplicate.touch()
            with patch.object(
                prune_superseded_debs,
                "metadata",
                return_value=("curl", "8.5.0-2ubuntu10.13", "amd64"),
            ):
                removed = prune_superseded_debs.prune(directory)
            self.assertEqual(removed, [duplicate])
            self.assertTrue(first.exists())
            self.assertFalse(duplicate.exists())

    def test_offline_bundle_builder_includes_libtpms(self):
        script = (
            Path(__file__).parents[1] / "tools" / "prepare_offline_rootless.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("swtpm swtpm-tools libtpms0", script)
        self.assertIn('prune_superseded_debs.py" "$DEB_DIR"', script)

    def test_offline_bundle_retains_canonical_linux_722_tarball(self):
        script = (
            Path(__file__).parents[1] / "tools" / "prepare_offline_rootless.sh"
        ).read_text(encoding="utf-8")
        self.assertIn('KERNEL_TEST_VERSION="7.2.2"', script)
        self.assertIn(
            'KERNEL_TEST_ARCHIVE_NAME="linux-${KERNEL_TEST_VERSION}.tar.xz"', script
        )
        self.assertIn(
            'https://cdn.kernel.org/pub/linux/kernel/v7.x/${KERNEL_TEST_ARCHIVE_NAME}',
            script,
        )
        self.assertIn(
            (
                'KERNEL_TEST_ARCHIVE_SHA256='
                '"7d0e7ce14f98c43efe880cffbf354a59be45928fdf7170d7333c374ae91c0d83"'
            ),
            script,
        )
        self.assertIn('tar -xJOf "$archive" "${KERNEL_TEST_TOPDIR}/Makefile"', script)
        self.assertIn('tar -xJf "$KERNEL_TEST_ARCHIVE" --no-same-owner', script)
        self.assertNotIn('clone_or_reuse "$SOURCE_DIR/linux-7.2"', script)

    def test_amd_swtpm_runtime_profile_preserves_unrelated_settings(self):
        setup = offline._replace_managed_swtpm_setup(
            "# local setting\nactive_pcr_banks = sha256\ncreate_certs_tool = /custom/tool\n"
        )
        self.assertIn("create_certs_tool = /custom/tool", setup)
        self.assertIn("active_pcr_banks = sha1,sha256", setup)
        self.assertNotIn("active_pcr_banks = sha256", setup)

        localca = offline._replace_managed_localca_options(
            "--platform-manufacturer Fedora\n--platform-model QEMU\n--allow-signing\n"
        )
        self.assertIn("--allow-signing", localca)
        self.assertIn("--platform-manufacturer AMD", localca)
        self.assertIn("--platform-version 2.0", localca)
        self.assertIn("--platform-model fTPM", localca)
        self.assertNotIn("Fedora", localca)
        self.assertNotIn("QEMU", localca)

    def test_host_tpm_pcr_banks_fall_back_when_no_tpm_is_visible(self):
        with patch.object(offline, "TPM_SYSFS", Path("/tmp/no-such-tpm")):
            self.assertEqual(offline._host_tpm_pcr_banks(), "sha1,sha256")

    def test_host_tpm_pcr_banks_follow_active_sysfs_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "pcr-sha256").mkdir()
            (root / "pcr-sha1").mkdir()
            (root / "pcr-md5").mkdir()
            with patch.object(offline, "TPM_SYSFS", root):
                self.assertEqual(offline._host_tpm_pcr_banks(), "sha1,sha256")

    def test_local_apt_acquires_debs_instead_of_passing_relative_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            debs = bundle / "debs"
            debs.mkdir()
            package = debs / "example_1_amd64.deb"
            package.touch()
            (debs / "Packages").write_text(
                "Package: example\nVersion: 1\nArchitecture: amd64\n"
                "Filename: example_1_amd64.deb\n\n",
                encoding="utf-8",
            )
            (bundle / "roots.txt").write_text(
                "example\nlibtpms0\nopenssh-server\n", encoding="utf-8",
            )

            runner = Mock()

            def inspect_update(args):
                if args[-1] != "update":
                    return
                setting = next(value for value in args if value.startswith("Dir::Etc::sourcelist="))
                source = Path(setting.split("=", 1)[1])
                entry = source.read_text(encoding="utf-8").strip()
                repository = Path(entry.split("file:", 1)[1].rsplit(" ./", 1)[0])
                staged = repository / package.name
                self.assertFalse(staged.is_symlink())
                self.assertTrue(staged.is_file())
                self.assertEqual(staged.stat().st_ino, package.stat().st_ino)
                self.assertEqual(repository.parent.stat().st_mode & 0o777, 0o755)
                self.assertEqual(repository.stat().st_mode & 0o777, 0o755)
                archives = next(value for value in args if value.startswith("Dir::Cache::archives="))
                partial = Path(archives.split("=", 1)[1]) / "partial"
                self.assertEqual(partial.stat().st_mode & 0o777, 0o700)

            runner.run.side_effect = inspect_update
            with patch.object(offline, "OFFLINE_DIR", bundle), \
                    patch.object(offline, "require_root"), \
                    patch.object(offline, "validate", return_value=[]), \
                    patch.object(offline, "load_host_state", return_value={}), \
                    patch.object(offline, "_install_amd_ftpm_libtpms"), \
                    patch.object(offline, "configure_amd_ftpm_swtpm"), \
                    patch.object(offline.os, "chown"), \
                    patch.object(offline, "update_host_state"):
                offline.install_packages(runner)

            install = runner.run.call_args_list[1].args[0]
            self.assertNotIn("--no-download", install)
            self.assertTrue(any(value.startswith("Dir::Cache::archives=") for value in install))
            self.assertEqual(install[-3:], ["example", "libtpms0", "openssh-server"])
            runner.run.assert_any_call(
                ["systemctl", "enable", "--now", "ssh.service"]
            )


class BuildTests(unittest.TestCase):
    def test_ovmf_build_keeps_tpm2_measured_boot_and_tcg2_event_log(self):
        project = Path(__file__).parents[1]
        script = (project / "ovmfpatch.sh").read_text(encoding="utf-8")
        for flag in ("-D SECURE_BOOT_ENABLE", "-D SMM_REQUIRE", "-D TPM2_ENABLE"):
            self.assertIn(flag, script)
        _validate_ovmf_measured_boot(project / "offline/sources/edk2")

    def test_ovmf_firmware_identity_rejects_generic_defaults(self):
        with tempfile.TemporaryDirectory() as temporary:
            ovmf = Path(temporary) / "ovmf"
            declarations = ovmf / "MdeModulePkg"
            declarations.mkdir(parents=True)
            target = declarations / "MdeModulePkg.dec"
            target.write_text(
                'PcdFirmwareVendor|L"OVMF"|VOID*|0x1\n'
                'PcdFirmwareVersionString|L"1686"|VOID*|0x2\n'
                'PcdFirmwareReleaseDateString|L"06/25/2026"|VOID*|0x3\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(AppError, "EDK2/OVMF"):
                _validate_ovmf_firmware_identity(ovmf)

            target.write_text(
                'PcdFirmwareVendor|L"American Megatrends Inc."|VOID*|0x1\n'
                'PcdFirmwareVersionString|L""|VOID*|0x2\n'
                'PcdFirmwareReleaseDateString|L"06/25/2026"|VOID*|0x3\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(AppError, "generic 440"):
                _validate_ovmf_firmware_identity(ovmf)

    def test_ovmf_identity_replacements_escape_host_dmi_values(self):
        source = (Path(__file__).parents[1] / "ovmfpatch.sh").read_text(
            encoding="utf-8",
        )
        self.assertIn("escape_sed_replacement()", source)
        self.assertIn(
            'firmware_vendor_sed="$(escape_sed_replacement "$firmware_vendor")"',
            source,
        )
        self.assertIn(
            'hsti_platform_sed="$(escape_sed_replacement "$hsti_platform")"',
            source,
        )
        self.assertIn('s|OVMF Platform Configuration|${hsti_platform_sed}', source)
        self.assertNotIn(
            's/OVMF Platform Configuration/${hsti_platform}', source,
        )

    def test_hpet_firmware_hardening_uses_reverse_comparison(self):
        source = (Path(__file__).parents[1] / "qemupatch.sh").read_text(encoding="utf-8")
        self.assertIn("aml_lless(aml_int(41666666), period)", source)
        self.assertIn("Unsupported QEMU source: HPET period validation was not found", source)

        with tempfile.TemporaryDirectory() as temporary:
            qemu = Path(temporary) / "qemu"
            acpi = qemu / "hw/i386/acpi-build.c"
            acpi.parent.mkdir(parents=True)
            acpi.write_text("aml_lless(aml_int(41666666), period)\n", encoding="utf-8")
            _validate_qemu_firmware_hardening(qemu)
            acpi.write_text("aml_lgreater(period, aml_int(41666666))\n", encoding="utf-8")
            with self.assertRaisesRegex(AppError, "HPET"):
                _validate_qemu_firmware_hardening(qemu)

    def test_qemu_kvm_hypercall_hardening_disables_rewrite_quirk(self):
        source = (Path(__file__).parents[1] / "qemupatch.sh").read_text(encoding="utf-8")
        self.assertIn("KVM-AAVM: disable KVM hypercall rewrite quirk.", source)
        self.assertIn("sed -n '/^int kvm_arch_init(/,/^}$/p'", source)
        self.assertIn("sed -i '/^int kvm_arch_init(/,/^}$/ {", source)
        with tempfile.TemporaryDirectory() as temporary:
            qemu = Path(temporary) / "qemu"
            kvm = qemu / "target/i386/kvm/kvm.c"
            kvm.parent.mkdir(parents=True)
            kvm.write_text(
                "/* KVM-AAVM: disable KVM hypercall rewrite quirk. */\n"
                "ret = kvm_vm_enable_cap(s, KVM_CAP_DISABLE_QUIRKS2, 0,\n"
                "                         KVM_X86_QUIRK_FIX_HYPERCALL_INSN);\n",
                encoding="utf-8",
            )
            _validate_qemu_kvm_hypercall_hardening(qemu)
            kvm.write_text("int unchanged;\n", encoding="utf-8")
            with self.assertRaisesRegex(AppError, "hypercall"):
                _validate_qemu_kvm_hypercall_hardening(qemu)

    def test_q35_dmar_ioapic_uses_root_bus_requester_id(self):
        source = (Path(__file__).parents[1] / "qemupatch.sh").read_text(encoding="utf-8")
        self.assertIn("Q35_PSEUDO_BUS_PLATFORM         (0x00)", source)
        self.assertIn("Unsupported QEMU source: Q35 pseudo IOAPIC bus", source)

    def test_kernel_dma_protection_is_a_selectable_intel_iommu_property(self):
        source = (Path(__file__).parents[1] / "qemupatch.sh").read_text(encoding="utf-8")
        self.assertIn("DMA_CTRL_PLATFORM_OPT_IN", source)
        self.assertIn("dma-control-platform-opt-in", source)
        self.assertIn("dma_ctrl_platform_opt_in", source)

    def test_cpu_hotplug_base_generation_is_aligned_and_guarded(self):
        source = (Path(__file__).parents[1] / "qemupatch.sh").read_text(encoding="utf-8")
        self.assertIn("((RANDOM%6141)*4)", source)
        self.assertIn("cpu % 4 != 0", source)

    def test_type20_handle_avoids_type19_expansion_range(self):
        source = (Path(__file__).parents[1] / "qemupatch.sh").read_text(encoding="utf-8")
        self.assertEqual(source.count("#define T20_BASE 0x2E00"), 2)
        self.assertNotIn("#define T20_BASE 0x1400", source)

    def test_generated_vars_rejects_unaligned_cpu_hotplug_base(self):
        with tempfile.TemporaryDirectory() as temporary:
            vars_path = Path(temporary) / "vars.sh"
            vars_path.write_text('cpu="12298"\n', encoding="utf-8")
            with self.assertRaisesRegex(AppError, "CpuHotplugSmm"):
                _validate_generated_vars(vars_path)
            vars_path.write_text('cpu="12296"\n', encoding="utf-8")
            _validate_generated_vars(vars_path)

    def test_qemu_script_is_fail_fast_and_parallelism_is_bounded(self):
        hardware = {
            "cpu_vendor": "amd", "lpc": "1111", "smbus": "2222",
            "audio": "3333", "audio_name": "Test Audio", "storage": "4444",
            "rootport": "5555", "xhci": "6666", "hostbridge": "7777",
            "pcibridge": "8888",
        }
        source = (Path(__file__).parents[1] / "qemupatch.sh").read_text(encoding="utf-8")
        source = source.replace("cp -a qemubackup/. qemu", "cp -fr qemubackup/. qemu")
        source = source.replace(" --disable-rust", "")
        source = source.replace(
            'ninja -j"$KVM_AAVM_BUILD_JOBS" qemu-system-x86_64', "make -j"
        )
        adapted = _adapt_qemu_script(source, Path("/tmp/output"), hardware)

        self.assertTrue(adapted.startswith("#!/usr/bin/env bash\nset -e\n"))
        self.assertNotRegex(adapted, r"(?m)^make -j")
        self.assertIn(
            'ninja -j"${KVM_AAVM_BUILD_JOBS}" qemu-system-x86_64', adapted
        )
        self.assertIn("./configure --target-list=x86_64-softmmu --disable-rust", adapted)
        self.assertIn("cp -a qemubackup/. qemu", adapted)

    def test_qemu_pci_identity_uses_host_queries_and_matching_device_classes(self):
        source = (Path(__file__).parents[1] / "qemupatch.sh").read_text(
            encoding="utf-8",
        )
        self.assertNotIn("cpu_vendor:1", source)
        self.assertNotRegex(source, r"printf[^\n]+xhci")
        self.assertIn(
            's/XHCI        0x000d/XHCI        0x$xhci_1022/', source,
        )
        self.assertIn(
            's/PCIE_BRIDGE 0x000e/PCIE_BRIDGE 0x$pcibridge_1022/', source,
        )
        self.assertIn(
            'PCI_DEVICE_ID_INTEL_P35_MCH      0x$hostbridge_1022/', source,
        )
        self.assertIn(
            'edk2bridge_1022=\\"$hostbridge_1022\\"', source,
        )
        ovmf = (Path(__file__).parents[1] / "ovmfpatch.sh").read_text(
            encoding="utf-8",
        )
        self.assertNotIn("cpu_vendor:1", ovmf)
        self.assertIn('if [[ "$cpu_vendor" == "AuthenticAMD" ]]', ovmf)

    def test_hardware_name_is_shell_safe_and_sed_escaped_at_runtime(self):
        hardware = {
            "cpu_vendor": "amd", "lpc": "1111", "smbus": "2222",
            "audio": "3333", "audio_name": "Family 17h/19h A&B | $USER $(id)",
            "storage": "4444", "rootport": "5555", "xhci": "6666",
            "hostbridge": "7777", "pcibridge": "8888",
        }
        source = (Path(__file__).parents[1] / "qemupatch.sh").read_text(encoding="utf-8")
        adapted = _adapt_qemu_script(source, Path("/tmp/output"), hardware)
        self.assertIn("hdaname_1022='Family 17h/19h A&B | $USER $(id)'", adapted)
        self.assertIn('escape_sed_replacement "$hdaname_1022"', adapted)


class PassthroughTests(unittest.TestCase):
    def test_guest_vtd_passthrough_never_uses_igd_reserved_root_slot(self):
        value = profile()
        value["guest_vtd"] = True
        value["passthrough"] = {
            "mode": "manual",
            "pci": ["01:00.0"],
        }
        root = ET.fromstring(build_domain_xml(value, stage="final"))
        root_ports = root.findall(
            "./devices/controller[@type='pci'][@model='pcie-root-port']"
        )
        self.assertTrue(root_ports)
        for controller in root_ports:
            address = controller.find("address[@type='pci']")
            self.assertIsNotNone(address)
            self.assertNotEqual(int(address.get("slot"), 0), 2)

    def test_usb_parser_keeps_full_name_and_hides_root_hubs(self):
        device = parse_usb_line(
            "Bus 999 Device 042: ID 35b5:3500 Naxiang SZNX LAN 100M"
        )
        self.assertIsNotNone(device)
        self.assertEqual(device.description, "Naxiang SZNX LAN 100M")
        self.assertEqual((device.vendor_id, device.product_id), ("35b5", "3500"))
        self.assertTrue(device.is_network)
        self.assertIsNone(
            parse_usb_line("Bus 001 Device 001: ID 1d6b:0002 Linux Foundation root hub")
        )

    def test_pci_and_usb_hostdev_xml(self):
        value = profile()
        value["passthrough"] = {
            "mode": "manual",
            "pci": ["08:00.0"],
            "gpu_pci": [],
            "usb": [{
                "vendor_id": "35b5", "product_id": "3500",
                "bus": 1, "device": 9, "match_address": False,
            }],
            "disable_virtual_network": True,
        }
        root = ET.fromstring(build_domain_xml(value, install_stage=False))
        pci = root.find("./devices/hostdev[@type='pci']")
        usb = root.find("./devices/hostdev[@type='usb']")
        self.assertIsNone(pci.find("./source/address").get("type"))
        self.assertEqual(pci.find("alias").get("name"), "ua-kvm-aavm-pci-08-00-0")
        self.assertIsNone(pci.find("rom"))
        self.assertEqual(usb.find("./source/vendor").get("id"), "0x35b5")
        self.assertEqual(usb.find("./source/product").get("id"), "0x3500")
        self.assertIsNone(usb.find("./source/address"))
        self.assertIsNone(root.find("./devices/interface[@type='network']"))
        self.assertIsNotNone(root.find("./devices/graphics"))

    def test_standalone_nonzero_pci_function_is_guest_function_zero(self):
        value = profile()
        value["passthrough"] = {
            "mode": "manual",
            "pci": ["0c:00.4"],
            "gpu_pci": [],
            "usb": [],
        }
        root = ET.fromstring(build_domain_xml(value, stage="final"))
        hostdev = root.find("./devices/hostdev[@type='pci']")
        self.assertEqual(hostdev.find("./source/address").get("function"), "0x4")
        self.assertEqual(hostdev.find("./address").get("function"), "0x0")

    def test_minimal_passthrough_update_keeps_network_pruned_and_adds_usb_controller(self):
        value = profile()
        root = ET.fromstring(build_domain_xml(value))
        old = value["passthrough"]
        new = {
            "mode": "manual", "pci": [], "gpu_pci": [],
            "usb": [{"vendor_id": "1234", "product_id": "5678"}],
            "disable_virtual_network": False, "_minimal_devices": True,
        }
        changed = ET.fromstring(update_passthrough(
            ET.tostring(root, encoding="unicode"), old, new, value["identity"]
        ))
        self.assertIsNone(changed.find("./devices/interface"))
        self.assertIsNotNone(changed.find("./devices/controller[@type='usb'][@model='qemu-xhci']"))

    def test_passthrough_update_preserves_unmanaged_hostdev(self):
        value = profile()
        old = {
            "mode": "manual", "pci": ["08:00.0"], "network_pci": "08:00.0",
            "usb": [{"vendor_id": "35b5", "product_id": "3500"}],
            "disable_virtual_network": True,
        }
        value["passthrough"] = old
        root = ET.fromstring(build_domain_xml(value))
        devices = root.find("devices")
        manual = ET.SubElement(devices, "hostdev", {
            "mode": "subsystem", "type": "usb", "managed": "yes",
        })
        source = ET.SubElement(manual, "source")
        ET.SubElement(source, "vendor", {"id": "0x1234"})
        ET.SubElement(source, "product", {"id": "0xabcd"})
        ET.SubElement(manual, "alias", {"name": "ua-user-manual-usb"})

        new = {
            "mode": "manual", "pci": ["09:00.0"], "network_pci": None,
            "usb": [{"vendor_id": "36a7", "product_id": "a885"}],
            "disable_virtual_network": False,
        }
        changed = update_passthrough(
            ET.tostring(root, encoding="unicode"), old, new, value["identity"]
        )
        updated = ET.fromstring(changed)
        aliases = {
            alias.get("name")
            for alias in updated.findall("./devices/hostdev/alias")
        }
        self.assertIn("ua-user-manual-usb", aliases)
        self.assertIn("ua-kvm-aavm-pci-09-00-0", aliases)
        self.assertTrue(any(name.startswith("ua-kvm-aavm-usb-36a7-a885") for name in aliases))
        self.assertIsNotNone(updated.find("./devices/interface/source[@network='default']"))


class HookTests(unittest.TestCase):
    def test_performance_hook_saves_switches_and_restores_host_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            managed = Path(temporary) / "managed"
            with patch.object(hooks, "HOOK_ROOT", managed), \
                    patch.object(hooks, "require_root"):
                hooks.install_performance_hook("test")
            script = managed / "test" / "10-host-performance"
            text = script.read_text(encoding="utf-8")
            self.assertIn("scaling_governor", text)
            self.assertIn("energy_performance_preference", text)
            self.assertIn("prepare:begin", text)
            self.assertIn("stopped:end|release:end", text)
            self.assertIn("active-*", text)
            subprocess.run(["bash", "-n", str(script)], check=True)

    def test_single_gpu_hook_uses_dispatcher_without_libvirt_callback(self):
        with tempfile.TemporaryDirectory() as temporary:
            managed = Path(temporary) / "managed"
            legacy = Path(temporary) / "qemu.d"
            for relative in (
                "test/prepare/begin/20-single-gpu",
                "test/release/end/20-single-gpu",
            ):
                path = legacy / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("legacy\n", encoding="utf-8")
            device = PciDevice(
                "01:00.0", "0300", "10de", "1234", "Test GPU", driver="nvidia"
            )
            with patch.object(hooks, "HOOK_ROOT", managed), \
                    patch.object(hooks, "LEGACY_HOOK_ROOT", legacy), \
                    patch.object(hooks, "require_root"):
                hooks.install_single_gpu_hooks("test", [device], force_bus_reset=True)
            script = managed / "test" / "20-single-gpu"
            script_text = script.read_text(encoding="utf-8")
            self.assertNotIn("virsh", script_text)
            self.assertIn("prepare:begin", script_text)
            self.assertIn("release:end", script_text)
            self.assertNotIn("kvm_aavm_oneshot", script_text)
            self.assertNotIn("systemctl reboot", script_text)
            self.assertIn(
                "unload_gpu_modules nvidia_drm nvidia_modeset nvidia_uvm",
                script_text,
            )
            self.assertIn("unload_gpu_modules nvidia", script_text)
            self.assertIn("driver_override", script_text)
            self.assertIn("echo vfio-pci", script_text)
            self.assertIn("loginctl terminate-seat seat0", script_text)
            self.assertIn("for attempt in {1..8}", script_text)
            self.assertIn('[[ -d "/sys/module/$module" ]] || continue', script_text)
            self.assertIn(
                "timeout --signal=TERM --kill-after=2s 5s modprobe -r",
                script_text,
            )
            self.assertIn(
                "GPU client modules remain loaded; continuing with PCI unbind",
                script_text,
            )
            self.assertIn(
                "GPU vendor modules remain loaded after PCI unbind; continuing with VFIO",
                script_text,
            )
            self.assertIn(
                "timeout --signal=TERM --kill-after=2s 15s",
                script_text,
            )
            self.assertNotIn("nvidia_refcnt", script_text)
            self.assertNotIn("NVIDIA core module is still referenced", script_text)
            prepare_offset = script_text.index("prepare:begin)")
            client_unload_offset = script_text.index(
                "unload_gpu_modules nvidia_drm nvidia_modeset nvidia_uvm",
                prepare_offset,
            )
            unbind_offset = script_text.index(
                "unbind_pci_driver 0000:01:00.0",
                prepare_offset,
            )
            core_unload_offset = script_text.index(
                "unload_gpu_modules nvidia",
                client_unload_offset + 1,
            )
            self.assertLess(
                client_unload_offset,
                unbind_offset,
            )
            self.assertLess(unbind_offset, core_unload_offset)
            self.assertIn("GPU device unbind failed", script_text)
            self.assertIn('echo bus > "$dev/reset_method"', script_text)
            self.assertIn('echo 1 > "$dev/reset"', script_text)
            self.assertIn("Requested PCIe bus reset is unavailable", script_text)
            self.assertIn("aborting VM start and restoring the host", script_text)
            self.assertIn("systemctl daemon-reload", script_text)
            self.assertIn("reactivate_graphical_seat", script_text)
            self.assertIn("deactivate_graphical_outputs", script_text)
            self.assertIn("trap rollback_handoff EXIT", script_text)
            self.assertIn(
                "GPU handoff failed; running automatic host display rollback",
                script_text,
            )
            self.assertIn(
                "bounded 30s systemctl stop display-manager.service",
                script_text,
            )
            self.assertIn(
                "bounded 15s loginctl terminate-seat seat0",
                script_text,
            )
            self.assertIn("handoff_committed=1", script_text)
            self.assertLess(
                script_text.index(
                    "deactivate_graphical_outputs\n    bounded 30s systemctl stop display-manager.service",
                    prepare_offset,
                ),
                unbind_offset,
            )
            self.assertIn('xrandr --output "$output" --off', script_text)
            self.assertIn('xrandr --output "$output" --preferred', script_text)
            self.assertNotIn("xrandr --auto", script_text)
            subprocess.run(["bash", "-n", str(script)], check=True)
            self.assertFalse((legacy / "test").exists())

    def test_recover_single_gpu_restarts_display_manager(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vt_root = root / "vtconsole"
            bind = vt_root / "vtcon0" / "bind"
            bind.parent.mkdir(parents=True)
            bind.write_text("0", encoding="utf-8")
            framebuffer = root / "efi-framebuffer" / "bind"
            framebuffer.parent.mkdir(parents=True)
            framebuffer.write_text("", encoding="utf-8")
            device = PciDevice(
                "01:00.0", "0300", "10de", "1234", "Test GPU", driver="nvidia"
            )
            runner = Mock()
            with patch.object(hooks, "require_root"), \
                    patch.object(hooks, "_qemu_running", return_value=False), \
                    patch.object(hooks, "_restore_device", return_value="nvidia"), \
                    patch.object(hooks, "VTCON_ROOT", vt_root), \
                    patch.object(hooks, "EFI_FRAMEBUFFER_BIND", framebuffer), \
                    patch.object(hooks, "SYS_MODULE_ROOT", root / "modules"):
                hooks.recover_single_gpu("test", [device], runner)
            self.assertEqual(bind.read_text(encoding="utf-8"), "1")
            self.assertEqual(framebuffer.read_text(encoding="utf-8"), "efi-framebuffer.0")
            self.assertIn(
                ((["systemctl", "stop", "display-manager.service"],), {"check": False}),
                [(call.args, call.kwargs) for call in runner.run.call_args_list],
            )
            self.assertIn(
                ((["systemctl", "restart", "display-manager.service"],), {"check": False}),
                [(call.args, call.kwargs) for call in runner.run.call_args_list],
            )
            self.assertIn(
                ((["systemctl", "daemon-reload"],), {"check": False}),
                [(call.args, call.kwargs) for call in runner.run.call_args_list],
            )
            self.assertTrue(any(
                call.args[0][:2] == ["bash", "-lc"]
                for call in runner.run.call_args_list
            ))


    def test_recover_refuses_hot_rebind_for_stale_nvidia(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pci_root = root / "pci"
            device_root = pci_root / "0000:01:00.0"
            device_root.mkdir(parents=True)
            override = device_root / "driver_override"
            override.write_text("vfio-pci", encoding="utf-8")
            modules = root / "modules"
            (modules / "nvidia").mkdir(parents=True)
            device = PciDevice(
                "01:00.0", "0300", "10de", "1234", "Test GPU", driver="nvidia"
            )
            runner = Mock()
            with patch.object(hooks, "require_root"), \
                    patch.object(hooks, "_qemu_running", return_value=False), \
                    patch.object(hooks, "PCI_DEVICES_ROOT", pci_root), \
                    patch.object(hooks, "SYS_MODULE_ROOT", modules):
                with self.assertRaisesRegex(Exception, "reboot is required"):
                    hooks.recover_single_gpu("test", [device], runner)
            self.assertEqual(override.read_text(encoding="utf-8"), "\n")
            runner.run.assert_not_called()


class VmTests(unittest.TestCase):
    def test_devirtualized_secure_boot_pins_host_board_identity(self):
        runner = Mock()
        value = profile()
        board = {
            "manufacturer": "ASUSTeK COMPUTER INC.",
            "product": "TUF GAMING B850-PLUS WIFI",
            "version": "Rev 1.xx",
        }
        firmware = {
            "vendor": "American Megatrends Inc.",
            "version": "1686",
            "date": "06/25/2026",
        }
        with patch.object(vm, "require_root"), \
                patch.object(vm, "vm_lock", return_value=nullcontext()), \
                patch.object(vm, "load_profile", return_value=value), \
                patch.object(vm, "_refresh_profile_host_capabilities"), \
                patch.object(vm, "_ensure_inactive"), \
                patch.object(vm, "_dump_xml", return_value="<domain />"), \
                patch.object(vm, "_backup_xml"), \
                patch.object(vm, "_remember_existing_tpm"), \
                patch.object(vm, "_host_board_identity", return_value=board), \
                patch.object(vm, "_host_firmware_identity", return_value=firmware), \
                patch.object(vm, "_set_guest_secure_boot_varstore", return_value=None), \
                patch.object(vm, "build_domain_xml", return_value="<domain />") as build, \
                patch.object(vm, "_replace_definition"), \
                patch.object(vm, "save_profile"), \
                patch.object(vm, "atomic_write"):
            vm.enable_devirtualized(
                "test-vm", runner, guest_secure_boot=True,
            )
        configured = build.call_args.args[0]
        self.assertEqual(configured["identity_board"], board)
        self.assertEqual(configured["identity"]["manufacturer"], board["manufacturer"])
        self.assertEqual(configured["identity"]["product"], board["product"])
        self.assertEqual(configured["identity"]["baseboard_product"], board["product"])
        self.assertEqual(configured["identity_firmware"], firmware)

    def test_existing_emulator_tpm_is_preserved_for_future_rebuilds(self):
        value = profile()
        root = ET.fromstring(build_domain_xml(value, stage="final"))
        devices = root.find("devices")
        tpm = ET.SubElement(devices, "tpm", {"model": "tpm-crb"})
        ET.SubElement(
            tpm, "backend",
            {"type": "emulator", "version": "2.0", "persistent_state": "yes"},
        )
        vm._remember_existing_tpm(value, ET.tostring(root, encoding="unicode"))
        self.assertEqual(value["tpm"], {
            "mode": "emulator", "model": "tpm-crb", "version": "2.0",
        })
        rebuilt = ET.fromstring(build_domain_xml(value, stage="final"))
        self.assertIsNotNone(
            rebuilt.find("./devices/tpm[@model='tpm-crb']/backend[@type='emulator']")
        )

    def test_tpm_config_from_xml_reads_manual_emulator(self):
        xml = (
            "<domain><devices><tpm model='tpm-crb'><backend "
            "type='emulator' version='2.0' persistent_state='yes'/>"
            "</tpm></devices></domain>"
        )
        self.assertEqual(vm.tpm_config_from_xml(xml), {
            "mode": "emulator", "model": "tpm-crb", "version": "2.0",
        })

    def test_configure_tpm_uses_persistent_emulator(self):
        runner = Mock()
        value = profile()
        old_xml = build_domain_xml(value, stage="final")
        with patch.object(vm, "require_root"), \
                patch.object(vm, "vm_lock", return_value=nullcontext()), \
                patch.object(vm, "load_profile", return_value=value), \
                patch.object(vm, "_ensure_inactive"), \
                patch.object(vm, "_dump_xml", return_value=old_xml), \
                patch.object(vm, "_backup_xml"), \
                patch.object(vm, "_replace_definition") as replace, \
                patch.object(vm, "save_profile"), \
                patch.object(vm, "atomic_write"):
            vm.configure_tpm("test-vm", "emulator", runner)
        self.assertEqual(value["tpm"], {
            "mode": "emulator", "model": "tpm-crb", "version": "2.0",
        })
        self.assertIn("<tpm model=\"tpm-crb\">", replace.call_args.args[1])

    def test_configure_tpm_amd_profile_requires_patched_libtpms(self):
        runner = Mock()
        value = profile()
        old_xml = build_domain_xml(value, stage="final")
        with patch.object(vm, "require_root"), \
                patch.object(vm, "vm_lock", return_value=nullcontext()), \
                patch.object(vm, "load_profile", return_value=value), \
                patch.object(vm, "_ensure_inactive"), \
                patch.object(vm, "_dump_xml", return_value=old_xml), \
                patch.object(vm, "_backup_xml"), \
                patch.object(vm, "_require_amd_ftpm_libtpms") as require_profile, \
                patch.object(vm, "_replace_definition"), \
                patch.object(vm, "save_profile"), \
                patch.object(vm, "atomic_write"):
            vm.configure_tpm("test-vm", "amd-ftpm", runner)
        require_profile.assert_called_once_with(value, runner)
        self.assertEqual(value["tpm"], {
            "mode": "emulator", "model": "tpm-crb", "version": "2.0",
            "profile": "amd-ftpm",
        })

    def test_recreate_tpm_retires_state_after_creating_a_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_root = root / "libvirt-swtpm"
            backup_root = root / "backups"
            value = profile()
            value["tpm"] = {
                "mode": "emulator", "model": "tpm-crb", "version": "2.0",
                "profile": "amd-ftpm",
            }
            xml = build_domain_xml(value, stage="final")
            uuid = ET.fromstring(xml).findtext("uuid")
            active = state_root / uuid / "tpm2"
            active.mkdir(parents=True)
            (active / "tpm2-00.permall").write_bytes(b"old-tpm-state")
            runner = Mock()
            with patch.object(vm, "require_root"), \
                    patch.object(vm, "vm_lock", return_value=nullcontext()), \
                    patch.object(vm, "load_profile", return_value=value), \
                    patch.object(vm, "_ensure_inactive"), \
                    patch.object(vm, "_dump_xml", return_value=xml), \
                    patch.object(vm, "_backup_xml"), \
                    patch.object(vm, "_require_amd_ftpm_libtpms"), \
                    patch.object(vm, "LIBVIRT_SWTPM_DIR", state_root), \
                    patch.object(vm, "BACKUP_DIR", backup_root):
                backup = vm.recreate_tpm("test-vm", runner, confirmed=True)
            self.assertIsNotNone(backup)
            self.assertTrue((backup / "tpm2" / "tpm2-00.permall").is_file())
            self.assertTrue((backup / "recreation.json").is_file())
            self.assertFalse((state_root / uuid).exists())
            retired = list(state_root.glob(f"{uuid}.kvm-aavm-retired-*"))
            self.assertEqual(len(retired), 1)
            self.assertTrue((retired[0] / "tpm2" / "tpm2-00.permall").is_file())

    def test_recreate_tpm_requires_explicit_confirmation(self):
        with patch.object(vm, "require_root"):
            with self.assertRaisesRegex(AppError, "explicit confirmation"):
                vm.recreate_tpm("test-vm", Mock())

    def test_uuid_rotation_migrates_persistent_tpm_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            state_root = Path(temporary) / "libvirt-swtpm"
            value = profile()
            value["tpm"] = {
                "mode": "emulator", "model": "tpm-crb", "version": "2.0",
            }
            old_xml = build_domain_xml(value, stage="final")
            rotated = rerandomize(value)
            new_xml = update_identity(old_xml, rotated["identity"], 8)
            old_uuid = ET.fromstring(old_xml).findtext("uuid")
            new_uuid = ET.fromstring(new_xml).findtext("uuid")
            old_state = state_root / old_uuid / "tpm2"
            old_state.mkdir(parents=True)
            (old_state / "tpm2-00.permall").write_bytes(b"persistent")

            with patch.object(vm, "LIBVIRT_SWTPM_DIR", state_root):
                migration = vm._migrate_tpm_state_for_uuid(old_xml, new_xml)
                self.assertEqual(migration, (state_root / old_uuid, state_root / new_uuid))
                self.assertFalse((state_root / old_uuid).exists())
                self.assertTrue((state_root / new_uuid / "tpm2" / "tpm2-00.permall").is_file())
                vm._rollback_tpm_state_migration(migration)
                self.assertTrue((state_root / old_uuid / "tpm2" / "tpm2-00.permall").is_file())
                self.assertFalse((state_root / new_uuid).exists())

    def test_amd_ftpm_libtpms_rejects_unmanaged_package(self):
        runner = Mock()
        runner.run.return_value = Mock(returncode=0, stdout="0.9.3-0ubuntu4", stderr="")
        with self.assertRaisesRegex(AppError, "patched libtpms0"):
            vm._require_amd_ftpm_libtpms(profile(), runner)

    def test_configure_hugepages_reserves_total_for_all_managed_vms(self):
        runner = Mock()
        runner.dry_run = False
        value = profile()
        value["resources"]["hugepages_2m"] = False
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vm_root = root / "vms"
            (vm_root / "test-vm").mkdir(parents=True)
            (vm_root / "other").mkdir()
            (vm_root / "test-vm" / "profile.json").write_text(
                json.dumps(value), encoding="utf-8",
            )
            other = profile()
            other["name"] = "other"
            other["resources"].update({"memory_gib": 4, "hugepages_2m": True})
            (vm_root / "other" / "profile.json").write_text(
                json.dumps(other), encoding="utf-8",
            )
            sysctl = root / "99-kvm-aavm-hugepages.conf"
            target = (8 + 4) * 512
            with patch.object(vm, "require_root"), \
                    patch.object(vm, "vm_lock", return_value=nullcontext()), \
                    patch.object(vm, "load_profile", return_value=value), \
                    patch.object(vm, "_ensure_inactive"), \
                    patch.object(vm, "_dump_xml", return_value=build_domain_xml(value, stage="final")), \
                    patch.object(vm, "_backup_xml"), \
                    patch.object(vm, "_replace_definition"), \
                    patch.object(vm, "save_profile"), \
                    patch.object(vm, "VM_DIR", vm_root), \
                    patch.object(vm, "HUGEPAGES_SYSCTL", sysctl), \
                    patch.object(vm, "HUGEPAGES_2M_SYSFS", root / "nr_hugepages"), \
                    patch.object(vm, "_read_hugepage_count", side_effect=[0, target]), \
                    patch.object(vm, "vm_dir", return_value=vm_root / "test-vm"):
                vm.configure_hugepages("test-vm", True, runner)
            self.assertTrue(value["resources"]["hugepages_2m"])
            self.assertEqual(sysctl.read_text(encoding="utf-8").splitlines()[-1], f"vm.nr_hugepages={target}")
            self.assertIn(
                ["sysctl", "-w", f"vm.nr_hugepages={target}"],
                [call.args[0] for call in runner.run.call_args_list],
            )

    def test_configure_hugepages_restores_reservation_when_xml_definition_fails(self):
        runner = Mock()
        runner.dry_run = False
        value = profile()
        previous_text = "vm.nr_hugepages=100\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vm_root = root / "vms"
            (vm_root / "test-vm").mkdir(parents=True)
            sysctl = root / "99-kvm-aavm-hugepages.conf"
            sysctl.write_text(previous_text, encoding="utf-8")
            target = 8 * 512
            with patch.object(vm, "require_root"), \
                    patch.object(vm, "vm_lock", return_value=nullcontext()), \
                    patch.object(vm, "load_profile", return_value=value), \
                    patch.object(vm, "_ensure_inactive"), \
                    patch.object(vm, "_dump_xml", return_value=build_domain_xml(value, stage="final")), \
                    patch.object(vm, "_backup_xml"), \
                    patch.object(vm, "_replace_definition", side_effect=AppError("define failed")), \
                    patch.object(vm, "save_profile"), \
                    patch.object(vm, "VM_DIR", vm_root), \
                    patch.object(vm, "HUGEPAGES_SYSCTL", sysctl), \
                    patch.object(vm, "HUGEPAGES_2M_SYSFS", root / "nr_hugepages"), \
                    patch.object(vm, "_read_hugepage_count", side_effect=[100, target]):
                with self.assertRaisesRegex(AppError, "define failed"):
                    vm.configure_hugepages("test-vm", True, runner)
            self.assertFalse(value["resources"].get("hugepages_2m", False))
            self.assertEqual(sysctl.read_text(encoding="utf-8"), previous_text)
            self.assertIn(
                ["sysctl", "-w", "vm.nr_hugepages=100"],
                [call.args[0] for call in runner.run.call_args_list],
            )

    def test_rebuild_artifacts_preserves_identity_and_uses_next_generation(self):
        runner = Mock()
        value = profile()
        old_xml = build_domain_xml(value, stage="final")
        rebuilt = profile()
        rebuilt["artifact_generation"] = 2
        rebuilt["paths"].update({
            "qemu": "/vm/generation-2/bin/qemu-system-x86_64",
            "ovmf_code": "/vm/generation-2/ovmf/code.qcow2",
            "ovmf_vars": "/vm/generation-2/ovmf/vars.qcow2",
            "ssdt": ["/vm/generation-2/bin/ssdt1.aml", "/vm/generation-2/bin/ssdt2.aml"],
        })
        original_identity = value["identity"]
        with patch.object(vm, "require_root"), \
                patch.object(vm, "vm_lock", return_value=nullcontext()), \
                patch.object(vm, "load_profile", return_value=value), \
                patch.object(vm, "_ensure_inactive"), \
                patch.object(vm, "_dump_xml", return_value=old_xml), \
                patch.object(vm, "_backup_xml"), \
                patch.object(vm, "build_all", return_value=rebuilt) as build, \
                patch.object(vm, "update_artifact_paths", return_value=old_xml) as paths, \
                patch.object(vm, "_replace_definition"), \
                patch.object(vm, "save_profile"), \
                patch.object(vm, "clear_pending"):
            vm.rebuild_artifacts("test-vm", runner)
        build.assert_called_once_with("test-vm", value, runner, generation=2)
        paths.assert_called_once_with(old_xml, rebuilt["paths"])
        self.assertIs(value["identity"], original_identity)

    def test_cleanup_vm_artifacts_keeps_active_generation_and_removes_build_worktrees(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            active = root / "artifacts" / "generation-4"
            old = root / "artifacts" / "generation-3"
            build_old = root / "build" / "generation-1"
            build_active = root / "build" / "generation-4"
            for path in (active / "bin", active / "ovmf", old, build_old, build_active):
                path.mkdir(parents=True)
            qemu = active / "bin/qemu-system-x86_64"
            code = active / "ovmf/OVMF_CODE_4M.patched.qcow2"
            vars_file = active / "ovmf/OVMF_VARS_4M.patched.qcow2"
            ssdt1 = active / "bin/ssdt1.aml"
            ssdt2 = active / "bin/ssdt2.aml"
            for path in (qemu, code, vars_file, ssdt1, ssdt2):
                path.touch()
            value = profile()
            value["artifact_generation"] = 4
            value["paths"].update({
                "qemu": str(qemu), "ovmf_code": str(code), "ovmf_vars": str(vars_file),
                "ssdt": [str(ssdt1), str(ssdt2)],
            })
            runner = Mock()
            with patch.object(vm, "require_root"), \
                    patch.object(vm, "vm_dir", return_value=root), \
                    patch.object(vm, "vm_lock", return_value=nullcontext()), \
                    patch.object(vm, "load_profile", return_value=value), \
                    patch.object(vm, "_ensure_inactive"), \
                    patch.object(vm, "prompt_yes_no", return_value=True):
                vm.cleanup_vm_artifacts("test-vm", runner)
            self.assertTrue(active.is_dir())
            self.assertFalse(old.exists())
            self.assertFalse(build_old.exists())
            self.assertFalse(build_active.exists())

    def test_purge_vm_removes_state_backups_pending_and_disk(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "vms" / "test-vm"
            backup_root = Path(temporary) / "backups"
            image_root = Path(temporary) / "images"
            pending_root = Path(temporary) / "pending"
            root.mkdir(parents=True)
            backup_root.mkdir()
            image_root.mkdir()
            pending_root.mkdir()
            disk = image_root / "test-vm.qcow2"
            disk.touch()
            (root / "media").mkdir()
            (root / "profile.json").write_text(
                json.dumps({"paths": {"disk": str(disk)}}), encoding="utf-8",
            )
            (backup_root / "test-vm").mkdir()
            (backup_root / "test-vm-security-20260817").mkdir()
            (pending_root / "test-vm.json").write_text("{}", encoding="utf-8")
            runner = Mock()
            runner.run.return_value = Mock(returncode=1, stdout="", stderr="")
            with patch.object(vm, "require_root"), \
                    patch.object(vm, "vm_dir", return_value=root), \
                    patch.object(vm, "BACKUP_DIR", backup_root), \
                    patch.object(vm, "VM_IMAGE_DIR", image_root), \
                    patch.object(vm, "PENDING_DIR", pending_root), \
                    patch.object(state, "PENDING_DIR", pending_root), \
                    patch.object(vm, "prompt_yes_no", return_value=True), \
                    patch.object(hooks, "remove_dynamic_hooks"), \
                    patch.object(hooks, "remove_single_gpu_hooks"), \
                    patch.object(hooks, "remove_performance_hook"):
                vm.purge_vm("test-vm", runner)
            self.assertFalse(root.exists())
            self.assertFalse(disk.exists())
            self.assertFalse((backup_root / "test-vm").exists())
            self.assertFalse((backup_root / "test-vm-security-20260817").exists())
            self.assertFalse((pending_root / "test-vm.json").exists())

    def test_guest_security_update_preserves_xml_only_pci_hostdev(self):
        value = profile()
        value["guest_secure_boot"] = True
        value["guest_dma_protection"] = True
        value["guest_core_isolation"] = True
        root = ET.fromstring(build_domain_xml(value, stage="final"))
        devices = root.find("devices")
        hostdev = ET.SubElement(
            devices, "hostdev",
            {"mode": "subsystem", "type": "pci", "managed": "yes"},
        )
        source = ET.SubElement(hostdev, "source")
        ET.SubElement(source, "address", {
            "domain": "0x0000", "bus": "0x0a", "slot": "0x00", "function": "0x0",
        })
        ET.SubElement(hostdev, "alias", {"name": "manual-usb-controller"})
        old_xml = ET.tostring(root, encoding="unicode")

        vm._remember_existing_hostdevs(value, old_xml)
        updated = ET.fromstring(vm._update_guest_security_xml(old_xml, value))
        recovered = updated.find(
            "./devices/hostdev[@type='pci']/source/"
            "address[@bus='0x0a'][@slot='0x00'][@function='0x0']"
        )
        self.assertIsNotNone(recovered)
        self.assertIn("0a:00.0", value["passthrough"]["pci"])
        self.assertIn("0a:00.0", value["passthrough"]["extra_pci"])
        qemu_args = [
            item.get("value") for item in updated.findall(
                "./{http://libvirt.org/schemas/domain/qemu/1.0}commandline/"
                "{http://libvirt.org/schemas/domain/qemu/1.0}arg"
            )
        ]
        self.assertIn("intel-iommu.dma-control-platform-opt-in=on", qemu_args)
        self.assertIsNotNone(updated.find(
            "./devices/iommu[@model='intel']/driver"
            "[@intremap='off'][@caching_mode='on']"
        ))
        self.assertIsNotNone(updated.find(
            "./cpu/feature[@name='svm'][@policy='require']"
        ))
        stage = updated.find(
            "./metadata/{https://kvm-aavm.local/xmlns/domain/1.0}stage"
        )
        self.assertEqual(stage.get("guest-core-isolation"), "true")
        self.assertEqual(validate_required(ET.tostring(updated, encoding="unicode")), [])

    def test_secure_boot_defaults_filter_preserves_only_security_variables(self):
        value = {
            "version": 2,
            "variables": [
                {"name": "Boot0001", "data": "boot"},
                {"name": "BootOrder", "data": "order"},
                {"name": "PK", "data": "pk"},
                {"name": "KEK", "data": "kek"},
                {"name": "db", "data": "db"},
                {"name": "dbx", "data": "dbx"},
                {"name": "PKDefault", "data": "host-pk"},
                {"name": "KEKDefault", "data": "host-kek"},
                {"name": "dbDefault", "data": "host-db"},
                {"name": "dbxDefault", "data": "host-dbx"},
            ],
        }
        filtered = vm._filtered_secure_boot_variables(value)
        self.assertIsNotNone(filtered)
        self.assertEqual(
            {item["name"] for item in filtered["variables"]},
            {
                "PK", "KEK", "db", "dbx",
                "PKDefault", "KEKDefault", "dbDefault", "dbxDefault",
            },
        )

    def test_secure_boot_policy_validation_rejects_unexpected_key_data(self):
        variables = {
            "PK": {"data": "pk"},
            "KEK": {"data": "kek"},
            "db": {"data": "db"},
            "dbx": {"data": "dbx"},
            "PKDefault": {"data": "oem-pk"},
            "KEKDefault": {"data": "oem-kek"},
            "dbDefault": {"data": "oem-db"},
            "dbxDefault": {"data": "oem-dbx"},
            "VendorKeysNv": {"data": "01"},
            "CustomMode": {"data": "00"},
            "SecureBootEnable": {"data": "01"},
        }
        reference = {name: dict(value) for name, value in variables.items()}
        variables["db"]["data"] = "custom-db"
        errors = vm._secure_boot_policy_errors(variables, True, reference)
        self.assertIn("db does not match the normalized OEM/Microsoft key policy", errors)

    def test_secure_boot_policy_validation_accepts_normalized_oem_microsoft_policy(self):
        variables = {
            "PK": {"data": "pk"},
            "KEK": {"data": "kek"},
            "db": {"data": "db"},
            "dbx": {"data": "dbx"},
            "PKDefault": {"data": "oem-pk"},
            "KEKDefault": {"data": "oem-kek"},
            "dbDefault": {"data": "oem-db"},
            "dbxDefault": {"data": "oem-dbx"},
            "VendorKeysNv": {"data": "01"},
            "CustomMode": {"data": "00"},
            "SecureBootEnable": {"data": "01"},
        }
        self.assertEqual(vm._secure_boot_policy_errors(variables, True, variables), [])

    def test_host_secure_boot_policy_mirrors_active_and_preserves_factory_databases(self):
        signature_type = bytes.fromhex("a1" * 16)

        def database(*entries: bytes) -> str:
            signature_size = 16 + len(entries[0])
            body = b"".join(bytes([index]) * 16 + entry for index, entry in enumerate(entries, 1))
            return (
                signature_type
                + struct.pack("<III", 28 + len(body), 0, signature_size)
                + body
            ).hex()

        template = {
            name: {"name": name, "guid": "template", "attr": 39, "data": "template"}
            for name in (*vm.SECURE_BOOT_ACTIVE_NAMES, "VendorKeysNv", "CustomMode")
        }
        host = {
            "PK": {"name": "PK", "data": "active-pk"},
            "KEK": {"name": "KEK", "data": database(b"Microsoft Corporation active KEK")},
            "db": {"name": "db", "data": database(b"Microsoft Corporation active UEFI CA")},
            "dbx": {"name": "dbx", "data": "active-revocation"},
            "PKDefault": {"name": "PKDefault", "data": "a1"},
            "KEKDefault": {"name": "KEKDefault", "data": database(b"Microsoft Corporation KEK")},
            "dbDefault": {"name": "dbDefault", "data": database(b"Microsoft Corporation UEFI CA")},
            "dbxDefault": {"name": "dbxDefault", "data": database(b"factory-revocation")},
        }
        variables = vm._host_secure_boot_policy(template, host)
        values = {item["name"]: item for item in variables}
        for name in vm.SECURE_BOOT_ACTIVE_NAMES:
            self.assertEqual(values[name]["data"], host[name]["data"])
            self.assertEqual(values[name]["attr"], 39)
        for name in vm.SECURE_BOOT_FACTORY_NAMES:
            self.assertEqual(values[name]["data"], host[name]["data"])
        self.assertEqual(values["VendorKeysNv"]["data"], "01")
        self.assertEqual(values["CustomMode"]["data"], "00")

    def test_host_secure_boot_policy_rejects_missing_active_microsoft_keys(self):
        signature_type = bytes.fromhex("a1" * 16)

        def database(payload: bytes) -> str:
            return (
                signature_type
                + struct.pack("<III", 28 + 16 + len(payload), 0, 16 + len(payload))
                + bytes(16)
                + payload
            ).hex()

        template = {
            name: {"name": name, "guid": "template", "attr": 39, "data": "template"}
            for name in (*vm.SECURE_BOOT_ACTIVE_NAMES, "VendorKeysNv", "CustomMode")
        }
        host = {
            "PK": {"name": "PK", "data": "active-pk"},
            "KEK": {"name": "KEK", "data": database(b"owner KEK")},
            "db": {"name": "db", "data": database(b"Microsoft Corporation active UEFI CA")},
            "dbx": {"name": "dbx", "data": "active-revocation"},
            "PKDefault": {"name": "PKDefault", "data": "a1"},
            "KEKDefault": {"name": "KEKDefault", "data": database(b"OEM KEK")},
            "dbDefault": {"name": "dbDefault", "data": database(b"Microsoft Corporation UEFI CA")},
            "dbxDefault": {"name": "dbxDefault", "data": database(b"factory-revocation")},
        }
        with self.assertRaisesRegex(AppError, "active KEK does not contain a Microsoft certificate"):
            vm._host_secure_boot_policy(template, host)

    def test_host_secure_boot_snapshot_reads_active_and_default_variables(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "state" / "host-active-microsoft.json"
            names = (*vm.SECURE_BOOT_ACTIVE_NAMES, *vm.SECURE_BOOT_FACTORY_NAMES)
            for index, name in enumerate(names, 1):
                guid = vm.EFI_VARIABLE_GUIDS[name]
                (root / f"{name}-{guid}").write_bytes(
                    (7).to_bytes(4, "little") + bytes([index]),
                )
            with patch.object(vm, "EFI_VARIABLES_DIR", root), \
                    patch.object(vm, "HOST_SECURE_BOOT_SNAPSHOT", snapshot):
                variables = vm._host_secure_boot_variables()
            self.assertEqual(variables["PK"]["data"], "01")
            self.assertEqual(variables["dbxDefault"]["data"], "08")
            saved = json.loads(snapshot.read_text(encoding="utf-8"))
            self.assertEqual(saved["format"], 2)
            self.assertEqual(
                [item["name"] for item in saved["variables"]],
                list(names),
            )

    def test_export_host_secure_boot_writes_reusable_active_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "export" / "factory-keys.json"
            snapshot = root / "state" / "host-active-microsoft.json"
            names = (*vm.SECURE_BOOT_ACTIVE_NAMES, *vm.SECURE_BOOT_FACTORY_NAMES)
            for index, name in enumerate(names, 1):
                guid = vm.EFI_VARIABLE_GUIDS[name]
                (root / f"{name}-{guid}").write_bytes(
                    (7).to_bytes(4, "little") + bytes([index]),
                )
            with patch.object(vm, "EFI_VARIABLES_DIR", root), \
                    patch.object(vm, "HOST_SECURE_BOOT_SNAPSHOT", snapshot), \
                    patch.object(vm, "require_root"):
                result = vm.export_host_secure_boot(output)
            self.assertEqual(result, output.resolve())
            self.assertEqual(result.stat().st_mode & 0o777, 0o600)
            exported = json.loads(result.read_text(encoding="utf-8"))
            self.assertEqual(exported["policy"], "host-active-with-factory-defaults")
            self.assertEqual(
                [item["name"] for item in exported["variables"]],
                list(names),
            )
            self.assertIn("PK", {item["name"] for item in exported["variables"]})

    def test_system_ovmf_pair_is_converted_to_persistent_per_vm_qcow2(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            system_code = root / "OVMF_CODE_4M.secboot.fd"
            system_vars = root / "OVMF_VARS_4M.fd"
            system_code.write_bytes(b"ovmf")
            system_vars.write_bytes(b"vars")
            value = profile()
            runner = Mock(dry_run=True)
            with patch.object(vm, "INSTALL_OVMF_CODE", str(system_code)), \
                    patch.object(vm, "INSTALL_OVMF_VARS", str(system_vars)), \
                    patch.object(vm, "vm_dir", return_value=root / "state"):
                result = _ensure_install_ovmf_code("test-vm", value, runner)
            self.assertEqual(value["paths"]["install_ovmf_code"], str(result))
            self.assertEqual(result.name, "OVMF_CODE_4M.ubuntu-install.qcow2")
            install_vars = root / "state/firmware/OVMF_VARS_4M.ubuntu-install.qcow2"
            self.assertEqual(value["paths"]["install_ovmf_vars"], str(install_vars))
            self.assertEqual(runner.run.call_args_list[0].args[0], [
                "qemu-img", "convert", "-f", "raw", "-O", "qcow2",
                str(system_code), str(result),
            ])
            self.assertEqual(runner.run.call_args_list[1].args[0], [
                "qemu-img", "convert", "-f", "raw", "-O", "qcow2",
                str(system_vars), str(install_vars),
            ])

    def test_install_iso_is_hardlinked_into_traversable_managed_storage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "Windows.iso"
            source.write_bytes(b"test ISO")
            source.chmod(0o644)
            with patch.object(vm, "vm_dir", side_effect=lambda name: root / "state" / name):
                staged = _stage_install_media("test-vm", source)
            self.assertEqual(staged, root / "state" / "test-vm" / "media" / "windows-install.iso")
            self.assertEqual(staged.stat().st_ino, source.stat().st_ino)
            self.assertEqual(staged.parent.stat().st_mode & 0o777, 0o755)

    def test_passthrough_update_rebuilds_managed_domain_for_current_stage(self):
        runner = Mock()
        value = profile()
        value["stage"] = "install"
        value["passthrough"] = {
            "mode": "single-gpu", "pci": ["01:00.0", "01:00.1", "09:00.0"],
            "gpu_pci": ["01:00.0", "01:00.1"], "extra_pci": ["09:00.0"],
            "usb": [], "disable_virtual_network": False,
        }
        old_xml = build_domain_xml(value, install_stage=True)
        with patch.object(vm, "require_root"), \
                patch.object(vm, "vm_lock", return_value=nullcontext()), \
                patch.object(vm, "load_profile", return_value=value), \
                patch.object(vm, "_ensure_inactive"), \
                patch.object(vm, "_dump_xml", return_value=old_xml), \
                patch.object(vm, "_backup_xml"), \
                patch.object(vm, "build_domain_xml", return_value=old_xml) as build, \
                patch.object(vm, "_replace_definition"), \
                patch.object(vm, "save_profile"), \
                patch.object(vm, "atomic_write"):
            vm.configure_passthrough("test-vm", value["passthrough"], runner)
        rebuilt_profile = build.call_args.args[0]
        self.assertEqual(build.call_args.kwargs["stage"], "install")
        self.assertEqual(
            rebuilt_profile["passthrough"]["pci"],
            ["01:00.0", "01:00.1", "09:00.0"],
        )

    def test_disable_passthrough_restores_devirtualized_console_and_keeps_guest_vtd(self):
        runner = Mock()
        value = profile()
        value["stage"] = "final"
        value["guest_vtd"] = True
        value["guest_dma_protection"] = True
        value["minimal_devices"] = True
        value["passthrough"] = {
            "mode": "single-gpu", "pci": ["01:00.0", "01:00.1"],
            "gpu_pci": ["01:00.0", "01:00.1"], "gpu_guest_pci": ["01:00.0"],
            "extra_pci": [], "usb": [{"vendor_id": "1234", "product_id": "5678"}],
            "network_pci": "09:00.0", "disable_virtual_network": True,
            "rom_file": "/old/gpu.rom",
        }
        old_xml = build_domain_xml(value, stage="final")
        rebuilt_xml = "<domain />"
        with patch.object(vm, "require_root"), \
                patch.object(vm, "vm_lock", return_value=nullcontext()), \
                patch.object(vm, "load_profile", return_value=value), \
                patch.object(vm, "_ensure_inactive"), \
                patch.object(vm, "_dump_xml", return_value=old_xml), \
                patch.object(vm, "_backup_xml"), \
                patch.object(vm, "build_domain_xml", return_value=rebuilt_xml) as build, \
                patch.object(vm, "_replace_definition"), \
                patch.object(vm, "save_profile"), \
                patch.object(vm, "atomic_write"), \
                patch.object(hooks, "remove_single_gpu_hooks") as remove_hook:
            vm.disable_passthrough("test-vm", runner)
        self.assertEqual(build.call_args.kwargs["stage"], "devirtualized")
        self.assertEqual(value["stage"], "devirtualized")
        self.assertTrue(value["guest_vtd"])
        self.assertTrue(value["guest_dma_protection"])
        self.assertFalse(value["minimal_devices"])
        self.assertEqual(value["passthrough"]["pci"], [])
        self.assertEqual(value["passthrough"]["usb"], [])
        self.assertIsNone(value["passthrough"]["rom_file"])
        remove_hook.assert_called_once_with("test-vm")

    def test_existing_matching_qcow2_is_reused(self):
        with tempfile.TemporaryDirectory() as temporary:
            disk = Path(temporary) / "test.qcow2"
            disk.touch()
            runner = Mock()
            runner.dry_run = False
            runner.run.return_value = Mock(stdout='{"format":"qcow2","virtual-size":257698037760}')
            _ensure_disk(disk, 240, runner)
            runner.run.assert_called_once_with(
                ["qemu-img", "info", "--output=json", str(disk)], capture=True,
            )


    def test_resume_existing_domain_reapplies_install_xml(self):
        runner = Mock()
        value = profile()
        old_xml = build_domain_xml(value)
        with patch.object(vm, "require_root"), \
                patch.object(vm, "load_profile", return_value=value), \
                patch.object(vm, "_domain_exists", return_value=True), \
                patch.object(vm, "_ensure_inactive") as inactive, \
                patch.object(vm, "_stage_install_media", return_value=Path("/managed/windows-install.iso")) as stage_iso, \
                patch.object(vm, "_ensure_install_ovmf_code") as install_code, \
                patch.object(vm, "_dump_xml", return_value=old_xml), \
                patch.object(vm, "_backup_xml") as backup, \
                patch.object(vm, "save_profile") as save, \
                patch.object(vm, "_replace_definition") as replace:
            result = vm.resume_vm("test-vm", runner)
        self.assertIs(result, value)
        inactive.assert_called_once_with("test-vm", runner)
        stage_iso.assert_called_once_with("test-vm", Path("/iso/windows.iso"))
        install_code.assert_called_once_with("test-vm", value, runner)
        backup.assert_called_once_with("test-vm", old_xml)
        save.assert_called_once_with("test-vm", value)
        self.assertEqual(value["stage"], "install")
        self.assertEqual(value["paths"]["windows_iso"], "/managed/windows-install.iso")
        new_xml = ET.fromstring(replace.call_args.args[1])
        self.assertEqual(
            new_xml.find("./devices/disk[@device='cdrom']/source").get("file"),
            "/managed/windows-install.iso",
        )
        self.assertEqual(new_xml.find("./os/type").get("machine"), INSTALL_MACHINE_TYPE)
        self.assertEqual(new_xml.findtext("./devices/emulator"), INSTALL_QEMU)
        self.assertEqual(new_xml.findtext("./os/loader"), INSTALL_OVMF_CODE)


class KernelTests(unittest.TestCase):
    def test_memflow_queues_mok_when_secure_boot_rejects_module(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "memflow-source-only.dkms.tar.gz"
            archive.write_bytes(b"archive")
            certificate = root / "MOK.der"
            certificate.write_bytes(b"certificate")
            runner = Mock()
            runner.run.side_effect = [
                Mock(returncode=0, stdout="SecureBoot enabled", stderr=""),
                Mock(returncode=0, stdout="", stderr=""),
                Mock(returncode=0, stdout="", stderr=""),
                Mock(returncode=1, stdout="", stderr="Key was rejected by service"),
                Mock(returncode=0, stdout=f"{certificate} is not enrolled", stderr=""),
                Mock(returncode=0, stdout="", stderr=""),
                Mock(returncode=0, stdout="[key 1]", stderr=""),
            ]
            with patch.object(kernel, "require_root"), \
                    patch.object(kernel, "OFFLINE_DIR", root), \
                    patch.object(kernel, "MOK_CERTIFICATE", certificate):
                kernel.install_memflow(runner)

        commands = [call.args[0] for call in runner.run.call_args_list]
        self.assertIn(
            ["dkms", "install", "--force", f"--archive={archive}"], commands,
        )
        self.assertIn(["mokutil", "--list-new"], commands)
        self.assertIn(["update-secureboot-policy", "--enroll-key"], commands)


    def test_custom_kernel_signing_hook_is_tkg_scoped_and_verified(self):
        script = kernel._kernel_signing_hook()
        self.assertIn("*-tkg-*)", script)
        self.assertIn("openssl x509 -inform DER", script)
        self.assertIn("sbsign --key", script)
        self.assertIn("sbverify --cert", script)
        self.assertIn('sbattach --remove "$unsigned"', script)
        result = subprocess.run(["sh", "-n"], input=script, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_kernel_boot_key_does_not_use_dkms_module_only_oid(self):
        source = inspect.getsource(kernel._ensure_kernel_mok)
        self.assertIn("extendedKeyUsage=codeSigning", source)
        self.assertNotIn("1.3.6.1.4.1.2312.16.1.2", source)
        self.assertIn("rsa:3072", source)

    def test_kernel_profiles_keep_stable_default_and_pin_72_test(self):
        stable = kernel.kernel_profile()
        experimental = kernel.kernel_profile("test-7.2")
        self.assertEqual(stable.expected_version, (6, 19))
        self.assertEqual(stable.tkg_version, "6.19-latest")
        self.assertEqual(experimental.expected_version, (7, 2))
        self.assertEqual(experimental.tkg_version, "v7.2.2")
        self.assertTrue(experimental.test_release)

    def test_kernel_patches_hide_native_hypercall_interception(self):
        project = Path(__file__).parents[1]
        for name in ("amd619.mypatch", "intel619.mypatch", "amd72-test.mypatch", "intel72-test.mypatch"):
            patch = project / name
            self.assertTrue(patch.is_file(), name)
            kernel._validate_hypercall_patch(patch)

    def test_kernel_deb_install_allows_replacing_held_packages(self):
        source = inspect.getsource(kernel.build_kernel)
        self.assertIn('"--reinstall"', source)
        self.assertIn('"--allow-downgrades"', source)
        self.assertIn('"--allow-change-held-packages"', source)
        self.assertIn('"_processor_opt": "native"', source)
        self.assertIn('"_timer_freq": "1000"', source)
        self.assertIn('"_tickless": "2"', source)
        self.assertIn('"_acs_override": "false"', source)
        self.assertIn('if deb.name.startswith("linux-image-") and "-dbg_" not in deb.name', source)
        self.assertNotIn('for image in sorted(BOOT_DIR.glob("vmlinuz-*-tkg-*")):\n        _validate_tkg_boot_config', source)

    def test_amd72_kernel_patch_uses_svme_gated_vmcb01_cpuid_policy(self):
        project = Path(__file__).parents[1]
        patch_file = project / "amd72-test.mypatch"
        text = patch_file.read_text(encoding="utf-8")
        kernel._validate_amd_cpuid_virtualization_patch(patch_file)
        self.assertNotIn("kvm_hv_hypercall_enabled(vcpu)", text)
        self.assertNotIn("nested.save.cpl == 3", text)
        self.assertNotIn("vmcb_clr_intercept(&vmcb02->control, INTERCEPT_CPUID)", text)
        self.assertNotIn("nested_vmcb02", text)
        self.assertIn("if (svme)", text)
        self.assertIn("if (is_guest_mode(vcpu))", text)
        self.assertIn("svm->vmcb01.ptr->save.efer & EFER_SVME", text)
        self.assertIn("if (vcpu->arch.efer & EFER_SVME)", text)
        self.assertIn("case SVM_EXIT_CPUID:", text)
        self.assertIn("if (kvm_rax_read(vcpu) == 0)", text)
        self.assertIn("return NESTED_EXIT_HOST;", text)
        self.assertIn("handle_fastpath_nested_cpuid0", text)
        self.assertIn("kvm_find_cpuid_entry(vcpu, 0)", text)
        self.assertIn("kvm_pmu_is_fastpath_emulation_allowed(vcpu)", text)
        self.assertIn("kvm_is_cpuid_allowed(vcpu)", text)
        self.assertIn("EXIT_FASTPATH_REENTER_GUEST", text)
        self.assertIn("EXPORT_TRACEPOINT_SYMBOL_GPL(kvm_cpuid);", text)
        self.assertIn("svm_vcpu_exit_request", text)
        self.assertIn("xfer_to_guest_mode_prepare();", text)
        self.assertIn("aavm_nested_cpuid0_reenter:", text)
        self.assertIn("goto aavm_nested_cpuid0_reenter;", text)
        self.assertIn("svm->vmcb->save.rflags & X86_EFLAGS_TF", text)
        self.assertIn("kvm_rip_write(vcpu, control->next_rip);", text)
        self.assertIn("control->int_state &= ~SVM_INTERRUPT_SHADOW_MASK;", text)
        self.assertIn("svm_can_defer_nested_cpuid0_exit_tail", text)
        self.assertIn("control->exit_int_info & SVM_EXITINTINFO_VALID", text)
        self.assertIn("control->event_inj & SVM_EVTINJ_VALID", text)
        self.assertIn("nested_svm_virtualize_tpr(vcpu)", text)
        self.assertIn("control->tlb_ctl == TLB_CONTROL_DO_NOTHING", text)
        self.assertIn("kvm_clear_available_registers(vcpu, SVM_REGS_LAZY_LOAD_SET)", text)
        self.assertIn("aavm_nested_cpuid0_finish_full_tail:", text)
        self.assertIn("exit_code == SVM_EXIT_EXCP_BASE + DB_VECTOR", text)
        self.assertIn("vmcb12_is_intercept(&svm->nested.ctl, exit_code)", text)
        self.assertIn("kvm_deliver_exception_payload(vcpu, &db);", text)
        self.assertNotIn("nested_svm_cache_nonpresent_npf", text)
        self.assertNotIn("nested_svm_try_cached_npf_exit", text)
        self.assertNotIn("npf_cache[4]", text)
        self.assertIn("struct kvm_host_map vmcb12_map;", text)
        self.assertIn("svm->nested.vmcb12_map_generation != generation", text)

    def test_amd_cpuid_validation_rejects_missing_nested_db_direct_reflection(self):
        project = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            patch_file = Path(temporary) / "amd-test.mypatch"
            text = (project / "amd72-test.mypatch").read_text(encoding="utf-8")
            text = text.replace(
                "vmcb12_is_intercept(&svm->nested.ctl, exit_code)",
                "removed_nested_db_owner_check",
            )
            patch_file.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(AppError, "nested #DB"):
                kernel._validate_amd_cpuid_virtualization_patch(patch_file)

    def test_amd_validation_rejects_nested_npf_value_cache(self):
        project = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            patch_file = Path(temporary) / "amd-test.mypatch"
            text = (project / "amd72-test.mypatch").read_text(encoding="utf-8")
            text += "\n+bool nested_svm_try_cached_npf_exit(struct vcpu_svm *svm);\n"
            patch_file.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(AppError, "nested NPF value cache"):
                kernel._validate_amd_cpuid_virtualization_patch(patch_file)

    def test_amd_validation_rejects_unchecked_vmcb12_map_reuse(self):
        project = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            patch_file = Path(temporary) / "amd-test.mypatch"
            text = (project / "amd72-test.mypatch").read_text(encoding="utf-8")
            text = text.replace(
                "svm->nested.vmcb12_map_generation != generation",
                "removed_vmcb12_generation_guard",
            )
            patch_file.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(AppError, "VMCB12 map reuse"):
                kernel._validate_amd_cpuid_virtualization_patch(patch_file)

    def test_amd_cpuid_validation_rejects_missing_leaf0_irqoff_fastpath(self):
        project = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            patch_file = Path(temporary) / "amd-test.mypatch"
            text = (project / "amd72-test.mypatch").read_text(encoding="utf-8")
            text = text.replace("handle_fastpath_nested_cpuid0", "removed_nested_cpuid0")
            patch_file.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(AppError, "IRQ-off fastpath"):
                kernel._validate_amd_cpuid_virtualization_patch(patch_file)

    def test_amd_cpuid_validation_rejects_missing_deferred_tail_event_guard(self):
        project = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            patch_file = Path(temporary) / "amd-test.mypatch"
            text = (project / "amd72-test.mypatch").read_text(encoding="utf-8")
            text = text.replace(
                "control->exit_int_info & SVM_EXITINTINFO_VALID",
                "removed_exit_int_info_guard",
            )
            patch_file.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(AppError, "deferred exit-tail"):
                kernel._validate_amd_cpuid_virtualization_patch(patch_file)

    def test_vmexit_profiler_correlates_nested_l0_cpuid_handler(self):
        project = Path(__file__).parents[1]
        analyzer = project / "verification" / "analyze_vmexit_profile.py"
        verifier = project / "verification" / "verify_live_cpuid_policy.py"
        profiler = (
            project
            / "verification"
            / "nested-cpuid-static-fastpath-20260830"
            / "VMEXIT_PROFILE.sh"
        )
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "profile.txt"
            report.write_text(
                "cpuid_path_correlation=enabled\n"
                "@kvm_exit[114]: 32139\n"
                "@kvm_nested_vmexit[114]: 32139\n"
                "@kvm_cpuid[0, 0]: 15072\n"
                "@nested_cpuid_l0_emulation[0, 0]: 15072\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                ["python3", str(analyzer), str(report)],
                check=True,
                text=True,
                capture_output=True,
            )
        self.assertIn("cpuid_context=ALL_HARDWARE_EXITS_FROM_L2", result.stdout)
        self.assertIn("cpuid_l2_l0_emulations=15072", result.stdout)
        self.assertIn("cpuid_l2_forwarded_candidates=17067", result.stdout)
        self.assertIn("cpuid_path_result=CORRELATED", result.stdout)
        self.assertIn(
            'svm.count("svm_clr_intercept(svm, INTERCEPT_CPUID);") == 2',
            verifier.read_text(encoding="utf-8"),
        )
        self.assertIn(
            "nested_cpuid_leaf0_short_reentry=",
            verifier.read_text(encoding="utf-8"),
        )
        profiler_source = profiler.read_text(encoding="utf-8")
        self.assertIn("/args.exit_reason == 114/", profiler_source)
        self.assertIn("@pending_nested_cpuid[tid] = 1", profiler_source)
        self.assertIn("@nested_cpuid_l0_emulation", profiler_source)
        self.assertIn("resolve_vcpu_regs_offset", profiler_source)
        self.assertIn("kprobe:nested_svm_exit_special", profiler_source)
        self.assertIn("@nested_cpuid_observed", profiler_source)
        self.assertIn("kvm_nested_vmexit_inject", profiler_source)
        self.assertIn("@nested_exit_to_entry_ns", profiler_source)
        self.assertIn("@nested_npf_exit_to_entry_ns", profiler_source)
        self.assertIn("@nested_npf_injected_detail", profiler_source)
        self.assertIn("@kvm_page_fault_gpa", profiler_source)
        self.assertIn("@kvm_page_fault_detail", profiler_source)
        self.assertIn("npf_stage_timing=enabled", profiler_source)
        self.assertIn("kprobe:npf_interception", profiler_source)
        self.assertIn("kretprobe:npf_interception", profiler_source)
        self.assertIn("kprobe:nested_svm_inject_npf_exit", profiler_source)
        self.assertIn("@npf_exit_to_l1_confirmed_ns", profiler_source)
        self.assertIn("kprobe:nested_svm_vmexit", profiler_source)
        self.assertIn("@nested_vmexit_ns", profiler_source)
        self.assertIn("kprobe:__kvm_vcpu_map", profiler_source)
        self.assertIn("@vmcb12_map_ns", profiler_source)
        self.assertIn("@vmcb12_mapped_write_ns", profiler_source)
        self.assertNotIn("kprobe:nested_svm_try_cached_npf_exit", profiler_source)
        self.assertNotIn("@nested_npf_cache_hits", profiler_source)
        self.assertNotIn("@nested_npf_cache_lookup_ns", profiler_source)
        self.assertIn("@vmcb12_reused_write_ns", profiler_source)
        self.assertIn("timing_values_valid=no", profiler_source)
        self.assertIn('mode="${3:-cpuid}"', profiler_source)

    def test_vmexit_analyzer_does_not_mislabel_legacy_nested_trace_as_forwarding(self):
        project = Path(__file__).parents[1]
        analyzer = project / "verification" / "analyze_vmexit_profile.py"
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "legacy-profile.txt"
            report.write_text(
                "@kvm_exit[114]: 6938\n"
                "@kvm_nested_vmexit[114]: 6938\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                ["python3", str(analyzer), str(report)],
                check=True,
                text=True,
                capture_output=True,
            )
        self.assertIn("cpuid_path_result=UNRESOLVED_LEGACY_PROFILE", result.stdout)
        self.assertIn("not whether L0 handled or forwarded", result.stdout)
        self.assertNotIn("ALL_REFLECTED_TO_L1", result.stdout)

    def test_vmexit_analyzer_reports_db_and_npf_reflections(self):
        project = Path(__file__).parents[1]
        analyzer = project / "verification" / "analyze_vmexit_profile.py"
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "nested-profile.txt"
            report.write_text(
                "cpuid_path_correlation=enabled\n"
                "@kvm_exit[65]: 700\n"
                "@kvm_nested_vmexit[65]: 700\n"
                "@kvm_nested_vmexit_inject[65]: 700\n"
                "@kvm_exit[1024]: 500\n"
                "@kvm_nested_vmexit[1024]: 500\n"
                "@kvm_nested_vmexit_inject[1024]: 500\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                ["python3", str(analyzer), str(report)],
                check=True,
                text=True,
                capture_output=True,
            )
        self.assertIn("db_reflections_to_l1=700", result.stdout)
        self.assertIn("npf_reflections_to_l1=500", result.stdout)

    def test_vmexit_analyzer_marks_low_noise_npf_mode_as_not_collected(self):
        project = Path(__file__).parents[1]
        analyzer = project / "verification" / "analyze_vmexit_profile.py"
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "npf-profile.txt"
            report.write_text(
                "profile_mode=npf\n"
                "cpuid_path_correlation=not-collected\n"
                "@nested_npf_injected_gpa[12288]: 500\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                ["python3", str(analyzer), str(report)],
                check=True,
                text=True,
                capture_output=True,
            )
        self.assertIn("cpuid_context=NOT_COLLECTED_NPF_MODE", result.stdout)
        self.assertIn("cpuid_path_result=NOT_COLLECTED_NPF_MODE", result.stdout)
        self.assertIn("npf_hardware_exits=not_collected", result.stdout)
        self.assertIn("npf_reflections_to_l1=500", result.stdout)
        self.assertIn("intentionally omitted", result.stdout)

    def test_vmexit_analyzer_accepts_one_event_profile_boundary_delta(self):
        project = Path(__file__).parents[1]
        analyzer = project / "verification" / "analyze_vmexit_profile.py"
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "boundary-profile.txt"
            report.write_text(
                "cpuid_path_correlation=enabled\n"
                "@kvm_exit[114]: 4568\n"
                "@kvm_nested_vmexit[114]: 4569\n"
                "@nested_cpuid_observed[1, 0]: 913\n"
                "@nested_npf_injected_gpa[12288]: 500\n"
                "@nested_npf_injected_detail[12288, 4294967309]: 500\n"
                "@kvm_page_fault_detail[12288, 4294967309]: 500\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                ["python3", str(analyzer), str(report)],
                check=True,
                text=True,
                capture_output=True,
            )
        self.assertIn(
            "cpuid_context=ALL_HARDWARE_EXITS_FROM_L2_BOUNDARY_DELTA",
            result.stdout,
        )
        self.assertIn(
            "nested_observed_top=function=0x1,index=0x0,count=913",
            result.stdout,
        )
        self.assertIn("nested_npf_top=gpa=0x3000,count=500", result.stdout)
        self.assertIn(
            "nested_npf_detail_top=gpa=0x3000,error=0x10000000d,count=500",
            result.stdout,
        )
        self.assertIn(
            "page_fault_detail_top=gpa=0x3000,error=0x10000000d,count=500",
            result.stdout,
        )

    def test_ovmf_build_has_no_dynamic_native_cpuid_handoff(self):
        project = Path(__file__).parents[1]
        self.assertNotIn("ovmf-native-cpuid-exitbs.patch", build.LEGACY_FILES)
        self.assertNotIn(
            "ovmf-native-cpuid-exitbs.patch",
            (project / "ovmfpatch.sh").read_text(encoding="utf-8"),
        )
        self.assertNotIn("_validate_ovmf_native_cpuid_gate", inspect.getsource(build))

    def test_amd_cpuid_validation_rejects_dynamic_switch(self):
        with tempfile.TemporaryDirectory() as temporary:
            patch_file = Path(temporary) / "amd-test.mypatch"
            patch_file.write_text(
                "-\tsvm_set_intercept(svm, INTERCEPT_CPUID);\n"
                "+\tsvm_clr_intercept(svm, INTERCEPT_CPUID);\n"
                "+\tvmcb_clr_intercept(c, INTERCEPT_CPUID);\n"
                "+\tif (svm_is_intercept(svm, INTERCEPT_CPUID))\n"
                "+\t\tsvm_clr_intercept(svm, INTERCEPT_CPUID);\n"
                "+#define KVM_AAVM_NATIVE_CPUID_PORT 0x4b41\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(AppError, "CPUID intercept"):
                kernel._validate_amd_cpuid_virtualization_patch(patch_file)

    def test_amd_cpuid_validation_rejects_direct_native_cpuid(self):
        with tempfile.TemporaryDirectory() as temporary:
            patch_file = Path(temporary) / "amd-test.mypatch"
            patch_file.write_text(
                "-\tsvm_set_intercept(svm, INTERCEPT_CPUID);\n"
                "+\tsvm_clr_intercept(svm, INTERCEPT_CPUID);\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(AppError, "CPUID intercept"):
                kernel._validate_amd_cpuid_virtualization_patch(patch_file)

    def test_amd_cpuid_validation_rejects_nested_cpuid_clear(self):
        with tempfile.TemporaryDirectory() as temporary:
            patch_file = Path(temporary) / "amd-test.mypatch"
            patch_file.write_text(
                "+\tif (vcpu->arch.efer & EFER_SVME)\n"
                "+\t\tsvm_clr_intercept(svm, INTERCEPT_CPUID);\n"
                "+\telse\n"
                "+\t\tsvm_set_intercept(svm, INTERCEPT_CPUID);\n"
                "+\tvmcb_clr_intercept(&vmcb02->control, INTERCEPT_CPUID);\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(AppError, "VMCB02"):
                kernel._validate_amd_cpuid_virtualization_patch(patch_file)

    def test_amd_cpuid_validation_rejects_l2_efer_policy(self):
        project = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            patch_file = Path(temporary) / "amd-test.mypatch"
            text = (project / "amd72-test.mypatch").read_text(encoding="utf-8")
            text = text.replace(
                "+\n"
                "+\tif (is_guest_mode(vcpu))\n"
                "+\t\tsvme = svm->vmcb01.ptr->save.efer & EFER_SVME;\n",
                "",
            )
            patch_file.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(AppError, "VMCB01 保存的 L1 EFER"):
                kernel._validate_amd_cpuid_virtualization_patch(patch_file)

    def test_amd_cpuid_validation_rejects_cpl3_vmcb02_branch(self):
        project = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            patch_file = Path(temporary) / "amd-test.mypatch"
            text = (project / "amd72-test.mypatch").read_text(encoding="utf-8")
            text += (
                "\n+\tif (vmcb02->save.cpl == 3)\n"
                "+\t\tvmcb_clr_intercept(&vmcb02->control, INTERCEPT_CPUID);\n"
            )
            patch_file.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(AppError, "VMCB02"):
                kernel._validate_amd_cpuid_virtualization_patch(patch_file)

    def test_amd_cpuid_validation_rejects_cpl3_hypercall_gate(self):
        project = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            patch_file = Path(temporary) / "amd-test.mypatch"
            text = (project / "amd72-test.mypatch").read_text(encoding="utf-8")
            text = text.replace(
                "+\tif (svme)\n",
                "+\tif (kvm_hv_hypercall_enabled(vcpu) &&\n"
                "+\t    svme)\n",
            )
            patch_file.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(AppError, "hypercall state"):
                kernel._validate_amd_cpuid_virtualization_patch(patch_file)

    def test_amd_cpuid_validation_rejects_early_leaf0_direct_path(self):
        project = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            patch_file = Path(temporary) / "amd-test.mypatch"
            text = (project / "amd72-test.mypatch").read_text(encoding="utf-8")
            text += (
                "\n+\t\tif (svm->vmcb->control.exit_code == SVM_EXIT_CPUID &&\n"
                "+\t\t    kvm_rax_read(vcpu) == 0)\n"
                "+\t\t\treturn kvm_emulate_cpuid(vcpu);\n"
            )
            patch_file.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(AppError, "nested CPUID exit"):
                kernel._validate_amd_cpuid_virtualization_patch(patch_file)

    def test_kernel_patch_validation_rejects_hypercall_handler(self):
        with tempfile.TemporaryDirectory() as temporary:
            patch = Path(temporary) / "broken.mypatch"
            patch.write_text("SVM_EXIT_VMMCALL = vmmcall_interception\n", encoding="utf-8")
            with self.assertRaisesRegex(AppError, "kvm_handle_invalid_op"):
                kernel._validate_hypercall_patch(patch)

    def test_kernel_source_metadata_reads_stable_point_release_from_tarball_makefile(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            (source / "Makefile").write_text(
                "VERSION = 7\nPATCHLEVEL = 2\nSUBLEVEL = 2\nEXTRAVERSION =\n",
                encoding="utf-8",
            )
            self.assertEqual(kernel._kernel_source_metadata(source), ((7, 2), "v7.2.2"))

    def test_kernel_source_metadata_rejects_wrong_rc_for_test_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            (source / "Makefile").write_text(
                "VERSION = 7\nPATCHLEVEL = 2\nSUBLEVEL = 0\nEXTRAVERSION = -rc1\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(AppError, "固定使用 v7.2.2"):
                kernel._validate_kernel_source(kernel.kernel_profile("test-7.2"), source)

    def test_kernel_source_version_rejects_wrong_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            (source / "Makefile").write_text(
                "VERSION = 6\nPATCHLEVEL = 19\n", encoding="utf-8",
            )
            with self.assertRaisesRegex(AppError, "需要 Linux 7.2"):
                kernel._validate_kernel_source(kernel.kernel_profile("test-7.2"), source)

    def test_ubuntu_kernel_fragment_enables_apparmor_lsm(self):
        fragment = kernel._ubuntu_kernel_fragment()
        self.assertIn("CONFIG_DEFAULT_SECURITY_APPARMOR=y", fragment)
        self.assertIn('CONFIG_LSM="landlock,lockdown,yama,integrity,apparmor,bpf"', fragment)

    def test_nvidia_driver_maps_to_same_dkms_variant(self):
        runner = Mock()
        runner.run.return_value = Mock(
            returncode=0,
            stdout=(
                "nvidia-driver-595-open\t595.84-0ubuntu0.24.04.1\thi \n"
                "nvidia-driver-535-server-open\t535.1\tii \n"
            ),
            stderr="",
        )
        self.assertEqual(
            kernel._installed_nvidia_drivers(runner),
            [
                ("nvidia-dkms-535-server-open", "535.1"),
                ("nvidia-dkms-595-open", "595.84-0ubuntu0.24.04.1"),
            ],
        )

    def test_missing_matching_nvidia_dkms_blocks_custom_kernel(self):
        runner = Mock()
        with patch.object(
                kernel, "_installed_nvidia_drivers",
                return_value=[("nvidia-dkms-595-open", "595.84")]),                 patch.object(kernel, "_package_installed", return_value=False),                 patch.object(kernel, "_matching_offline_deb", return_value=None):
            with self.assertRaisesRegex(AppError, "nvidia-dkms-595-open"):
                kernel._ensure_nvidia_dkms_support(runner)

    def test_linux72_nvidia_compat_patch_replaces_removed_strncpy(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "nvidia-595.84" / "nvidia"
            source.mkdir(parents=True)
            target = source / "os-interface.c"
            target.write_text(
                '#include "os-interface.h"\n'
                '    strncpy(buf, current->comm, len - 1);\n',
                encoding="utf-8",
            )
            with patch.object(kernel, "NVIDIA_DKMS_SOURCE_ROOT", Path(temporary)):
                patched = kernel._patch_nvidia_dkms_for_linux_72()
                self.assertEqual(patched, [target])
                self.assertIn("strscpy(buf, current->comm, len);", target.read_text(encoding="utf-8"))
                self.assertTrue(target.with_name("os-interface.c.kvm-aavm.orig").is_file())
                self.assertEqual(kernel._patch_nvidia_dkms_for_linux_72(), [])

    def test_cleanup_kernel_build_keeps_debs_and_removes_source_worktrees(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            work = state / "kernel-build" / "test-7.2"
            (work / "linux-src-git").mkdir(parents=True)
            (work / "linux-kernel.git").mkdir()
            (work / "DEBS").mkdir()
            runner = Mock()
            with patch.object(kernel, "STATE_DIR", state), \
                    patch.object(kernel, "prompt_yes_no", return_value=True), \
                    patch.object(kernel, "require_root"):
                kernel.cleanup_kernel_build(runner)
            self.assertFalse((work / "linux-src-git").exists())
            self.assertFalse((work / "linux-kernel.git").exists())
            self.assertTrue((work / "DEBS").is_dir())
            runner.run.assert_called_once_with(["apt-get", "clean"])

    def test_prepare_external_modules_runs_dkms_for_each_tkg_kernel(self):
        with tempfile.TemporaryDirectory() as temporary:
            boot = Path(temporary)
            (boot / "vmlinuz-6.19.14-tkg-eevdf").touch()
            runner = Mock()
            with patch.object(kernel, "BOOT_DIR", boot),                     patch.object(kernel, "_ensure_nvidia_dkms_support", return_value=False):
                kernel._prepare_tkg_external_modules(runner, secure_boot=False)
        runner.run.assert_called_once_with(
            ["dkms", "autoinstall", "-k", "6.19.14-tkg-eevdf"],
        )

    def test_sign_installed_kernels_skips_ubuntu_kernel(self):
        with tempfile.TemporaryDirectory() as temporary:
            boot = Path(temporary)
            custom = boot / "vmlinuz-6.19.14-tkg-eevdf"
            ubuntu = boot / "vmlinuz-7.0.0-28-generic"
            custom.touch()
            ubuntu.touch()
            runner = Mock()
            hook = Path("/test/sign-hook")
            with patch.object(kernel, "BOOT_DIR", boot), \
                    patch.object(kernel, "KERNEL_SIGNING_HOOK", hook):
                kernel._sign_installed_tkg_kernels(runner)
        runner.run.assert_called_once_with(
            [str(hook), "6.19.14-tkg-eevdf", str(custom)],
        )


class CliTests(unittest.TestCase):
    def test_gpu_iommu_preflight_rejects_missing_group_before_handoff(self):
        display = PciDevice(
            "01:00.0", "0300", "10de", "2c02", "RTX", iommu_group=None,
            driver="nvidia",
        )
        with self.assertRaisesRegex(AppError, "no IOMMU group"):
            cli._validate_gpu_iommu_isolation([display], [display])

    def test_gpu_iommu_preflight_rejects_unselected_group_companion(self):
        display = PciDevice(
            "01:00.0", "0300", "10de", "2c02", "RTX", iommu_group=7,
            driver="nvidia",
        )
        companion = PciDevice(
            "00:01.1", "0604", "1022", "14db", "PCIe bridge", iommu_group=7,
            driver="pcieport",
        )
        with self.assertRaisesRegex(AppError, "00:01.1 PCIe bridge"):
            cli._validate_gpu_iommu_isolation(
                [display], [display, companion],
            )

    def test_gpu_iommu_preflight_accepts_complete_isolated_group(self):
        display = PciDevice(
            "01:00.0", "0300", "10de", "2c02", "RTX", iommu_group=7,
            driver="nvidia",
        )
        audio = PciDevice(
            "01:00.1", "0403", "10de", "22e9", "GPU Audio", iommu_group=7,
            driver="snd_hda_intel",
        )
        cli._validate_gpu_iommu_isolation(
            [display, audio], [display, audio],
        )

    def test_additional_pci_preflight_checks_iommu_group_before_display_handoff(self):
        candidate = PciDevice(
            "08:00.0", "0200", "10ec", "8168", "Ethernet", iommu_group=4,
            driver="r8169",
        )
        companion = PciDevice(
            "08:00.1", "0200", "10ec", "8169", "Ethernet function", iommu_group=4,
            driver="r8169",
        )
        with patch.object(cli, "pci_devices", side_effect=[[candidate], [candidate, companion]]), \
                patch.object(cli, "prompt_yes_no", return_value=True), \
                patch.object(cli, "prompt", return_value="1"):
            with self.assertRaisesRegex(AppError, "08:00.1 Ethernet function"):
                cli._select_additional_pci(set(), current=set(), ask=False)

    def test_recommended_resources_use_smt_and_reserve_host_cores(self):
        eight_core = {
            "memory_gib": 32,
            "cpu": {"logical_cpus": 16, "cores": 8, "threads_per_core": 2},
        }
        with patch.object(cli, "host_fingerprint", return_value=eight_core):
            self.assertEqual(cli._recommended_resources(), (16, 12))
        two_core = {
            "memory_gib": 8,
            "cpu": {"logical_cpus": 4, "cores": 2, "threads_per_core": 2},
        }
        with patch.object(cli, "host_fingerprint", return_value=two_core):
            self.assertEqual(cli._recommended_resources(), (4, 2))

    def test_windows_installer_start_accepts_optical_boot_prompt(self):
        runner = Mock(dry_run=False)
        with patch.object(cli.time, "sleep") as sleep:
            cli._start_windows_installer("test-vm", runner)
        self.assertEqual(sleep.call_args_list[0].args, (3,))
        self.assertEqual([call.args for call in sleep.call_args_list[1:]], [(1,)] * 7)
        self.assertEqual(
            runner.run.call_args_list[0].args[0],
            ["virsh", "start", "test-vm"],
        )
        send_calls = runner.run.call_args_list[1:]
        self.assertEqual(len(send_calls), 8)
        for call in send_calls:
            self.assertEqual(
                call.args[0],
                ["virsh", "send-key", "test-vm", "KEY_SPACE"],
            )
            self.assertFalse(call.kwargs["check"])

    def test_new_gpu_audio_passthrough_defaults_to_disabled(self):
        display = PciDevice(
            "01:00.0", "0300", "10de", "2c02", "RTX", driver="nvidia"
        )
        audio = PciDevice(
            "01:00.1", "0403", "10de", "22e9", "GPU Audio",
            driver="snd_hda_intel",
        )
        with patch.object(cli, "prompt_yes_no", return_value=False) as prompt_yes_no:
            selected = cli._select_gpu_guest_functions([display, audio])
        self.assertEqual(selected, ["01:00.0"])
        prompt_yes_no.assert_called_once_with(
            "同時直通 GPU HDMI/DP 音訊", False,
        )

    def test_pcie_usb_controller_defaults_virtual_network_to_disabled(self):
        controller = PciDevice(
            "0a:00.0", "0c03", "1022", "149c", "USB controller",
            driver="xhci_hcd",
        )
        self.assertFalse(
            cli._default_keep_virtual_network({}, [controller], False)
        )
        self.assertTrue(
            cli._default_keep_virtual_network(
                {
                    "virtual_network_choice_set": True,
                    "disable_virtual_network": False,
                },
                [controller],
                False,
            )
        )

    def test_one_click_passthrough_applies_xml_before_gpu_hook(self):
        runner = Mock()
        value = profile()
        value["stage"] = "devirtualized"
        value["passthrough"] = {
            "mode": "manual", "pci": [], "gpu_pci": [],
            "gpu_guest_pci": [], "extra_pci": [], "usb": [],
            "network_pci": None, "disable_virtual_network": False,
        }
        display = PciDevice(
            "01:00.0", "0300", "10de", "2c02", "RTX", driver="nvidia"
        )
        events = []
        captured = {}
        def save_passthrough(_name, settings, _runner):
            captured.update(settings)
            events.append("passthrough")
        with patch.object(cli, "require_root"),                 patch.object(cli, "install_performance_hook"),                 patch.object(cli, "load_profile", return_value=value),                 patch.object(cli, "_select_gpu", return_value=[display]),                 patch.object(cli, "_select_additional_pci", return_value=[]),                 patch.object(cli, "_select_usb_devices", return_value=[]),                 patch.object(cli, "_usb_configs", return_value=[]),                 patch.object(cli, "prompt_yes_no", side_effect=[True, False, False, False, False, False, True]),                 patch.object(cli, "configure_minimal_devices", side_effect=lambda *_: events.append("minimal")),                 patch.object(cli, "configure_passthrough", side_effect=save_passthrough),                 patch.object(cli, "finalize_vm", side_effect=lambda *_: events.append("final")),                 patch.object(cli, "install_single_gpu_hooks", side_effect=lambda *_, **__: events.append("hook")):
            cli.one_click_passthrough("test-vm", runner)
        self.assertEqual(events, ["minimal", "passthrough", "final", "hook"])
        self.assertEqual(captured["gpu_pci"], ["01:00.0"])
        self.assertEqual(captured["gpu_guest_pci"], ["01:00.0"])
        self.assertFalse(captured["gpu_rom_bar"])
        self.assertTrue(captured["disable_virtual_network"])
        self.assertTrue(captured["virtual_network_choice_set"])

    def test_one_click_passthrough_can_keep_vnc_for_generic_gpu_driver_setup(self):
        runner = Mock()
        value = profile()
        value["stage"] = "devirtualized"
        value["passthrough"] = {
            "mode": "manual", "pci": [], "gpu_pci": [],
            "gpu_guest_pci": [], "extra_pci": [], "usb": [],
            "network_pci": None, "disable_virtual_network": False,
        }
        display = PciDevice(
            "01:00.0", "0300", "10de", "2c02", "GPU", driver="nvidia"
        )
        events = []
        with patch.object(cli, "require_root"), \
                patch.object(cli, "install_performance_hook"), \
                patch.object(cli, "load_profile", return_value=value), \
                patch.object(cli, "_select_gpu", return_value=[display]), \
                patch.object(cli, "_select_additional_pci", return_value=[]), \
                patch.object(cli, "_select_usb_devices", return_value=[]), \
                patch.object(cli, "_usb_configs", return_value=[]), \
                patch.object(cli, "prompt_yes_no", side_effect=[True, False, False, False, True, True, True]), \
                patch.object(cli, "configure_minimal_devices", side_effect=lambda *_: events.append("minimal")), \
                patch.object(cli, "configure_passthrough", side_effect=lambda *_: events.append("passthrough")), \
                patch.object(cli, "enable_gpu_setup", side_effect=lambda *_: events.append("gpu-setup")), \
                patch.object(cli, "install_single_gpu_hooks", side_effect=lambda *_, **__: events.append("hook")):
            cli.one_click_passthrough("test-vm", runner)
        self.assertEqual(events, ["minimal", "passthrough", "gpu-setup", "hook"])

    def test_menu_quick_deploy_matches_bootstrap(self):
        runner = Mock()
        events = []

        with patch.object(cli, "print_preflight", side_effect=lambda: events.append("preflight")),                 patch.object(cli, "print_validation", side_effect=lambda: events.append("validate") or True),                 patch.object(cli, "install_packages", side_effect=lambda _: events.append("packages")),                 patch.object(cli, "install_application", side_effect=lambda _: events.append("app")),                 patch.object(cli, "install_pending_service", side_effect=lambda _: events.append("service")),                 patch.object(cli, "configure_host", side_effect=lambda _: events.append("host")),                 patch.object(cli, "print_status", side_effect=lambda: events.append("status")),                 patch.object(cli, "prompt_int", side_effect=[1, 0]):
            cli.menu(runner)

        self.assertEqual(
            events,
            ["preflight", "validate", "packages", "app", "service", "host", "status"],
        )

    def test_main_menu_has_only_three_vm_workflow_steps(self):
        labels = [
            "VM 1/3：建立新 Windows VM",
            "VM 2/3：去虛擬化（保留 VNC/VGA，不啟用直通）",
            "VM 3/3：一鍵直通（可跳過並自行配置特殊設備）",
        ]
        source = Path(cli.__file__).read_text(encoding="utf-8")
        for label in labels:
            self.assertIn(label, source)

    def test_kernel_and_memflow_are_in_main_menu(self):
        source = Path(cli.__file__).read_text(encoding="utf-8")
        self.assertIn("(\"自訂核心（建置／修復 Secure Boot 簽章）\", lambda: _custom_kernel_wizard(runner))", source)
        self.assertIn("(\"安裝 memflow\", lambda: install_memflow(runner))", source)

    def test_custom_kernel_wizard_can_repair_without_rebuild(self):
        runner = Mock()
        with patch.object(cli, "sign_custom_kernels") as sign, \
                patch.object(cli, "prompt_int", return_value=2):
            cli._custom_kernel_wizard(runner)
        sign.assert_called_once_with(runner)


    def test_update_protection_is_in_main_menu(self):
        runner = Mock()
        with patch.object(cli, "_update_protection_wizard") as protect, \
                patch.object(cli, "prompt_int", side_effect=[8, 0]):
            cli.menu(runner)
        protect.assert_called_once_with(runner)

    def test_minimal_device_feature_is_in_maintenance_menu(self):
        runner = Mock()
        with patch.object(cli, "_minimal_devices_wizard") as minimal,                 patch.object(cli, "prompt_int", side_effect=[9, 4, 0, 0]):
            cli.menu(runner)
        minimal.assert_called_once_with(runner)

    def test_recreate_tpm_is_available_from_cli_and_maintenance_menu(self):
        args = cli.build_parser().parse_args(
            ["recreate-tpm", "--vm", "win11", "--confirm"],
        )
        self.assertEqual(args.command, "recreate-tpm")
        self.assertEqual(args.vm, "win11")
        self.assertTrue(args.confirm)
        source = Path(cli.__file__).read_text(encoding="utf-8")
        self.assertIn('("vTPM 管理", lambda: _tpm_wizard(runner))', source)
        self.assertIn("[4] 重製目前 TPM 身分", source)

    def test_one_shot_gpu_mode_is_removed(self):
        help_text = cli.build_parser().format_help()
        self.assertNotIn("enter-vm-once", help_text)
        self.assertNotIn("start-oneshot-vm", help_text)


    def test_xml_validation_is_reachable_from_maintenance_menu(self):
        runner = Mock()
        with patch.object(cli, "validate_vm_xml") as validate,                 patch.object(cli, "prompt", return_value="test-vm"),                 patch.object(cli, "prompt_int", side_effect=[9, 9, 0, 0]):
            cli.menu(runner)
        validate.assert_called_once_with("test-vm", runner)

    def test_install_app_command_uses_shared_stack(self):
        with patch.object(cli, "install_app_stack") as install:
            result = cli.main(["install-app"])
        self.assertEqual(result, 0)
        install.assert_called_once()

    def test_adopt_refuses_to_overwrite_managed_profile(self):
        runner = Mock()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_path = root / "test-vm" / "profile.json"
            profile_path.parent.mkdir()
            profile_path.write_text("{}\n", encoding="utf-8")
            with patch.object(cli, "VM_DIR", root),                     patch.object(cli, "require_root"):
                with self.assertRaisesRegex(AppError, "拒絕用納管流程覆寫"):
                    cli.adopt_vm("test-vm", runner)
        runner.run.assert_not_called()

    def test_resume_creation_removes_gpu_hook_for_installer(self):
        runner = Mock()
        value = profile()
        with patch.object(cli, "load_profile", return_value=value), \
                patch.object(cli, "install_performance_hook"), \
                patch.object(cli, "_profile_gpu_devices", return_value=[]), \
                patch.object(cli, "remove_single_gpu_hooks") as remove, \
                patch.object(cli, "resume_vm") as resume:
            cli.resume_creation("test-vm", runner)
        remove.assert_called_once_with("test-vm")
        resume.assert_called_once_with("test-vm", runner, start=False)

    def test_leaving_final_gpu_stage_recovers_host_before_redefining_vm(self):
        runner = Mock()
        value = profile()
        value["stage"] = "final"
        device = PciDevice(
            "01:00.0", "0300", "10de", "2c02", "RTX", driver="nvidia"
        )
        events = []
        with patch.object(cli, "load_profile", return_value=value), \
                patch.object(cli, "install_performance_hook"), \
                patch.object(cli, "_profile_gpu_devices", return_value=[device]), \
                patch.object(cli, "remove_single_gpu_hooks", side_effect=lambda *_: events.append("remove-hook")), \
                patch.object(cli, "recover_single_gpu", side_effect=lambda *_: events.append("recover-display")), \
                patch.object(cli, "resume_vm", side_effect=lambda *_args, **_kwargs: events.append("xml")):
            cli.resume_creation("test-vm", runner)
        self.assertEqual(events, ["remove-hook", "recover-display", "xml"])

    def test_devirtualization_removes_gpu_hook_and_defines_safe_console_stage(self):
        runner = Mock()
        value = profile()
        events = []
        with patch.object(cli, "load_profile", return_value=value), \
                patch.object(cli, "install_performance_hook"), \
                patch.object(cli, "prompt_yes_no", return_value=False), \
                patch.object(cli, "remove_single_gpu_hooks", side_effect=lambda *_: events.append("remove-hook")), \
                patch.object(cli, "enable_devirtualized", side_effect=lambda *_, **__: events.append("xml")) as enable:
            cli.devirtualize_creation("test-vm", runner)
        self.assertEqual(events, ["remove-hook", "xml"])
        enable.assert_called_once_with(
            "test-vm", runner,
            guest_vtd=False,
            guest_vtd_intremap=False,
            guest_secure_boot=False,
            guest_dma_protection=False,
            guest_core_isolation=False,
            guest_hyperv_enlightenments=False,
        )

    def test_finalize_creation_installs_gpu_hook_after_xml(self):
        runner = Mock()
        value = profile()
        device = PciDevice("01:00.0", "0300", "10de", "1234", "GPU", driver="nvidia")
        events = []
        with patch.object(cli, "load_profile", return_value=value), \
                patch.object(cli, "install_performance_hook"), \
                patch.object(cli, "_profile_gpu_devices", return_value=[device]), \
                patch.object(cli, "finalize_vm", side_effect=lambda *_: events.append("xml")), \
                patch.object(cli, "install_single_gpu_hooks", side_effect=lambda *_, **__: events.append("hook")):
            cli.finalize_creation("test-vm", runner)
        self.assertEqual(events, ["xml", "hook"])

    def test_tpm_wizard_detects_manual_vtpm_without_saving_profile(self):
        runner = Mock()
        runner.run.return_value = Mock(
            returncode=0,
            stdout=(
                "<domain><devices><tpm model='tpm-crb'><backend "
                "type='emulator' version='2.0' persistent_state='yes'/>"
                "</tpm></devices></domain>"
            ),
        )
        defaults = []

        def choose(_text, default, _minimum, _maximum):
            defaults.append(default)
            return 2

        with patch.object(cli, "require_root"), \
                patch.object(cli, "prompt", return_value="test-vm"), \
                patch.object(cli, "load_profile", return_value=profile()), \
                patch.object(cli, "prompt_int", side_effect=choose), \
                patch.object(cli, "configure_tpm") as configure, \
                patch.object(cli, "save_profile") as save:
            cli._tpm_wizard(runner)
        self.assertEqual(defaults, [2])
        configure.assert_called_once_with("test-vm", "emulator", runner)
        save.assert_not_called()


class HostTests(unittest.TestCase):
    def test_install_application_refreshes_existing_single_gpu_hook(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "project"
            (project / "kvm_aavm").mkdir(parents=True)
            (project / "kvm_aavm" / "marker.py").write_text("# test\n", encoding="utf-8")
            (project / "deploy.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
            state = root / "state"
            profile_root = state / "vms" / "win11"
            profile_root.mkdir(parents=True)
            value = profile()
            value["name"] = "win11"
            value["host"]["pci"] = [{
                "address": "01:00.0",
                "class_code": "0300",
                "vendor_id": "10de",
                "device_id": "1234",
                "description": "Test GPU",
                "driver": "nvidia",
            }]
            value["passthrough"] = {
                "mode": "single-gpu",
                "gpu_pci": ["01:00.0"],
                "gpu_reset_method": "default",
            }
            profile_root.joinpath("profile.json").write_text(
                json.dumps(value), encoding="utf-8",
            )
            runner = Mock()
            with patch.object(host, "PROJECT_DIR", project), \
                    patch.object(host, "PREFIX", root / "prefix"), \
                    patch.object(host, "STATE_DIR", state), \
                    patch.object(host, "require_root"), \
                    patch.object(host, "remove_obsolete_oneshot_support"), \
                    patch.object(host, "configure_apparmor"), \
                    patch.object(host, "configure_virt_manager"), \
                    patch.object(host, "verify_spice_console_runtime"), \
                    patch.object(host, "configure_libvirt_hooks"), \
                    patch.object(host, "update_host_state"), \
                    patch.object(host, "ensure_state_dirs"), \
                    patch.object(host, "atomic_write"), \
                    patch.object(hooks, "install_performance_hook") as performance, \
                    patch.object(hooks, "install_single_gpu_hooks") as gpu_hook:
                host.install_application(runner)
            performance.assert_called_once_with("win11")
            gpu_hook.assert_called_once()
            self.assertEqual(gpu_hook.call_args.args[0], "win11")
            self.assertEqual(gpu_hook.call_args.args[1][0].address, "01:00.0")

    def test_amd_host_config_explicitly_enables_avic(self):
        self.assertEqual(
            _managed_kvm_module_config("amd"),
            "options kvm_amd nested=1 avic=1\noptions kvm ignore_msrs=0\n",
        )

    def test_nested_module_option_is_enabled_idempotently(self):
        original = "options kvm_amd avic=1 nested=0\noptions kvm ignore_msrs=0\n"
        changed = _set_nested_module_option(original, "kvm_amd", True)
        self.assertIn("options kvm_amd avic=1 nested=1", changed)
        self.assertIn("options kvm ignore_msrs=0", changed)
        self.assertEqual(_set_nested_module_option(changed, "kvm_amd", True), changed)

    def test_vfio_options_keep_vga_enabled_and_disable_idle_d3_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "kvm-aavm-vfio.conf"
            with patch.object(host, "VFIO_MODPROBE_CONFIG", config):
                host.configure_vfio_module_options()
                host.configure_vfio_module_options()
            self.assertEqual(
                config.read_text(encoding="utf-8"),
                "# Managed by KVM-AntiAntiVM; applied through initramfs.\n"
                "options vfio-pci disable_idle_d3=1\n",
            )
            self.assertNotIn("disable_vga", config.read_text(encoding="utf-8"))
            self.assertNotIn("enable_sriov", config.read_text(encoding="utf-8"))
            self.assertNotIn("disable_denylist", config.read_text(encoding="utf-8"))

    def test_update_protection_preserves_preexisting_holds(self):
        runner = Mock()
        runner.run.side_effect = [
            Mock(stdout="qemu-system-x86\n"),
            Mock(stdout=(
                "linux-generic\tii \n"
                "qemu-system-x86\thi \n"
                "virt-manager\tii \n"
                "libtpms0\tii \n"
                "nvidia-driver-595-open\tii \n"
                "bash\tii \n"
            )),
            Mock(),
        ]
        with patch.object(host, "require_root"), \
                patch.object(host, "load_host_state", return_value={}), \
                patch.object(host, "update_host_state") as update:
            host.configure_update_protection(runner, True)

        runner.run.assert_any_call([
            "apt-mark", "hold", "libtpms0", "linux-generic",
            "nvidia-driver-595-open", "virt-manager",
        ])
        values = update.call_args.kwargs
        self.assertTrue(values["update_protection_enabled"])
        self.assertEqual(
            values["update_protection_packages"],
            ["libtpms0", "linux-generic", "nvidia-driver-595-open", "qemu-system-x86", "virt-manager"],
        )
        self.assertNotIn(
            "qemu-system-x86", values["update_protection_managed_holds"],
        )

    def test_disabling_update_protection_unholds_only_managed_packages(self):
        runner = Mock()
        runner.run.side_effect = [
            Mock(stdout="linux-generic\nqemu-system-x86\nvirt-manager\n"),
            Mock(),
        ]
        state = {
            "update_protection_enabled": True,
            "update_protection_managed_holds": ["linux-generic", "virt-manager"],
        }
        with patch.object(host, "require_root"), \
                patch.object(host, "load_host_state", return_value=state), \
                patch.object(host, "update_host_state") as update:
            host.configure_update_protection(runner, False)

        runner.run.assert_any_call([
            "apt-mark", "unhold", "linux-generic", "virt-manager",
        ])
        self.assertFalse(update.call_args.kwargs["update_protection_enabled"])

    def test_missing_spice_gi_runtime_is_reported_before_console_use(self):
        runner = Mock()
        runner.run.return_value = Mock(returncode=1)
        with self.assertRaisesRegex(Exception, "SPICE console runtime is missing"):
            host.verify_spice_console_runtime(runner)
        command = runner.run.call_args.args[0]
        self.assertIn("SpiceClientGLib", command[-1])
        self.assertIn("SpiceClientGtk", command[-1])

    def test_grub_idempotent_and_vendor_switch(self):
        original = (
            'GRUB_CMDLINE_LINUX_DEFAULT="quiet splash intel_iommu=on '
            'lsm=landlock,yama"\n'
        )
        additions = [
            "amd_iommu=on", "iommu=pt",
            "lsm=landlock,lockdown,yama,integrity,apparmor,bpf",
        ]
        changed = _replace_grub_args(original, additions)
        self.assertNotIn("intel_iommu=on", changed)
        self.assertNotIn("lsm=landlock,yama", changed)
        self.assertIn("lsm=landlock,lockdown,yama,integrity,apparmor,bpf", changed)
        self.assertEqual(changed.count("amd_iommu=on"), 1)
        self.assertEqual(_replace_grub_args(changed, additions), changed)

    def test_apparmor_custom_qemu_rules_are_scoped_and_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            libvirtd_profile = root / "usr.sbin.libvirtd"
            libvirtd_profile.write_text("profile libvirtd {}\n", encoding="utf-8")
            libvirtd_local = root / "local" / "usr.sbin.libvirtd"
            libvirtd_local.parent.mkdir()
            libvirtd_local.write_text("# keep existing local rules\n", encoding="utf-8")
            qemu_dropin = root / "abstractions" / "libvirt-qemu.d" / "kvm-aavm"
            runner = Mock()

            with patch.object(host, "APPARMOR_LIBVIRTD_PROFILE", libvirtd_profile), \
                    patch.object(host, "APPARMOR_LIBVIRTD_LOCAL", libvirtd_local), \
                    patch.object(host, "APPARMOR_QEMU_DROPIN", qemu_dropin), \
                    patch.object(host, "APPARMOR_SECURITY_DIR", root), \
                    patch.object(host, "STATE_DIR", Path("/var/lib/kvm-aavm")), \
                    patch.object(host, "require_root"), \
                    patch.object(host, "command_exists", return_value=True):
                host.configure_apparmor(runner)
                host.configure_apparmor(runner)

            local_text = libvirtd_local.read_text(encoding="utf-8")
            qemu_rule = "/var/lib/kvm-aavm/vms/*/artifacts/generation-*/bin/qemu-system-x86_64"
            ssdt_rule = "/var/lib/kvm-aavm/vms/*/artifacts/generation-*/bin/*.aml"
            qemu_share_rule = "/var/lib/kvm-aavm/vms/*/artifacts/generation-*/share/qemu/{,**}"
            qemu_firmware_rule = "/var/lib/kvm-aavm/vms/*/artifacts/generation-*/share/qemu-firmware/{,**}"
            vm_rom_rule = "/var/lib/kvm-aavm/vms/*/firmware/*.rom"
            self.assertIn("# keep existing local rules", local_text)
            self.assertEqual(local_text.count("# BEGIN KVM-AAVM"), 1)
            self.assertIn(f"{qemu_rule} PUx,", local_text)
            qemu_dropin_text = qemu_dropin.read_text(encoding="utf-8")
            self.assertIn(f"{qemu_rule} rmix,", qemu_dropin_text)
            self.assertIn(f"{ssdt_rule} r,", qemu_dropin_text)
            self.assertIn(f"{qemu_share_rule} r,", qemu_dropin_text)
            self.assertIn(f"{qemu_firmware_rule} r,", qemu_dropin_text)
            self.assertIn(f"{vm_rom_rule} r,", qemu_dropin_text)
            self.assertNotIn("artifacts/**", qemu_dropin_text)
            parsed_paths = [call.args[0][-1] for call in runner.run.call_args_list]
            self.assertEqual(parsed_paths.count(str(libvirtd_profile)), 2)
            self.assertEqual(len(parsed_paths), 2)


    def test_virt_manager_custom_machine_patch_is_backed_up_and_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            guest = root / "guest.py"
            backup = root / "backup" / "guest.py"
            original = """        def _compare_machine(domcaps):
            capsinfo = self.lookup_capsinfo()
            if self.os.machine == domcaps.machine:
                return True
            if capsinfo.is_machine_alias(self.os.machine, domcaps.machine):
                return True
            return False
"""
            guest.write_text(original, encoding="utf-8")
            runner = Mock()
            with patch.object(host, "VIRTINST_GUEST", guest), \
                    patch.object(host, "VIRTINST_GUEST_BACKUP", backup), \
                    patch.object(host, "require_root"):
                host.configure_virt_manager(runner)
                host.configure_virt_manager(runner)
            changed = guest.read_text(encoding="utf-8")
            self.assertIn("accept an exact custom-emulator machine", changed)
            self.assertLess(
                changed.index("if self.os.machine == domcaps.machine"),
                changed.index("capsinfo = self.lookup_capsinfo()"),
            )
            self.assertEqual(backup.read_text(encoding="utf-8"), original)
            runner.run.assert_called_once_with(
                [host.sys.executable, "-m", "py_compile", str(guest)]
            )


    def test_libvirt_dispatcher_is_executable_and_restarts_daemon(self):
        with tempfile.TemporaryDirectory() as temporary:
            dispatcher = Path(temporary) / "qemu.d" / "50-kvm-aavm"
            runner = Mock()
            with patch.object(host, "LIBVIRT_HOOK_DISPATCHER", dispatcher), \
                    patch.object(host, "require_root"):
                host.configure_libvirt_hooks(runner)
            text = dispatcher.read_text(encoding="utf-8")
            self.assertIn("/etc/libvirt/hooks/kvm-aavm/$vm", text)
            self.assertTrue(dispatcher.stat().st_mode & 0o111)
            subprocess.run(["bash", "-n", str(dispatcher)], check=True)
            runner.run.assert_called_once_with(
                ["systemctl", "try-restart", "libvirtd.service"]
            )


if __name__ == "__main__":
    unittest.main()
