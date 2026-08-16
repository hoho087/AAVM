from __future__ import annotations

import inspect
import subprocess
import tempfile
from contextlib import nullcontext
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import Mock, patch

from kvm_aavm import cli, hooks, host, kernel, offline, vm
from kvm_aavm.build import _adapt_qemu_script, _validate_generated_vars
from kvm_aavm.hardware import PciDevice, parse_usb_line, vm_cpu_layout
from kvm_aavm.host import _replace_grub_args, _set_nested_module_option
from kvm_aavm.identity import generate, mac_address, rerandomize
from kvm_aavm.util import AppError
from kvm_aavm.vm import _ensure_disk, _ensure_install_ovmf_code, _stage_install_media
from kvm_aavm.xmlgen import (
    INSTALL_MACHINE_TYPE, INSTALL_OVMF_CODE, INSTALL_OVMF_VARS, INSTALL_QEMU,
    build_domain_xml, update_artifact_paths, update_identity,
    update_passthrough, validate_required,
)


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


class HardwareTests(unittest.TestCase):
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


class XmlTests(unittest.TestCase):
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
        self.assertIsNone(root.find("./devices/controller[@type='usb']"))
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
            (bundle / "roots.txt").write_text("example\nopenssh-server\n", encoding="utf-8")

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
                    patch.object(offline.os, "chown"), \
                    patch.object(offline, "update_host_state"):
                offline.install_packages(runner)

            install = runner.run.call_args_list[1].args[0]
            self.assertNotIn("--no-download", install)
            self.assertTrue(any(value.startswith("Dir::Cache::archives=") for value in install))
            self.assertEqual(install[-2:], ["example", "openssh-server"])
            runner.run.assert_any_call(
                ["systemctl", "enable", "--now", "ssh.service"]
            )


class BuildTests(unittest.TestCase):
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
            self.assertIn("nvidia_drm nvidia_modeset nvidia_uvm nvidia", script_text)
            self.assertIn("driver_override", script_text)
            self.assertIn("echo vfio-pci", script_text)
            self.assertIn("loginctl terminate-seat seat0", script_text)
            self.assertIn("for attempt in {1..40}", script_text)
            self.assertIn('[[ -d "/sys/module/$module" ]] || continue', script_text)
            prepare_offset = script_text.index("prepare:begin)")
            self.assertLess(
                script_text.index('> "$dev/driver/unbind"', prepare_offset),
                script_text.index('for attempt in {1..40}', prepare_offset),
            )
            self.assertIn("GPU device unbind failed", script_text)
            self.assertIn('echo bus > "$dev/reset_method"', script_text)
            self.assertIn('echo 1 > "$dev/reset"', script_text)
            self.assertIn("Requested PCIe bus reset is unavailable", script_text)
            self.assertIn("aborting VM start and restoring the host", script_text)
            self.assertIn("systemctl daemon-reload", script_text)
            self.assertIn("reactivate_graphical_seat", script_text)
            self.assertIn("deactivate_graphical_outputs", script_text)
            self.assertLess(
                script_text.index(
                    "deactivate_graphical_outputs\n    systemctl stop display-manager.service",
                    prepare_offset,
                ),
                script_text.index('> "$dev/driver/unbind"', prepare_offset),
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
            ],
        }
        filtered = vm._filtered_secure_boot_variables(value)
        self.assertIsNotNone(filtered)
        self.assertEqual(
            {item["name"] for item in filtered["variables"]},
            {"PK", "KEK", "db", "dbx"},
        )

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

    def test_one_shot_gpu_mode_is_removed(self):
        help_text = cli.build_parser().format_help()
        self.assertNotIn("enter-vm-once", help_text)
        self.assertNotIn("start-oneshot-vm", help_text)


    def test_xml_validation_is_reachable_from_maintenance_menu(self):
        runner = Mock()
        with patch.object(cli, "validate_vm_xml") as validate,                 patch.object(cli, "prompt", return_value="test-vm"),                 patch.object(cli, "prompt_int", side_effect=[9, 8, 0, 0]):
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


class HostTests(unittest.TestCase):
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
            "apt-mark", "hold", "linux-generic",
            "nvidia-driver-595-open", "virt-manager",
        ])
        values = update.call_args.kwargs
        self.assertTrue(values["update_protection_enabled"])
        self.assertEqual(
            values["update_protection_packages"],
            ["linux-generic", "nvidia-driver-595-open", "qemu-system-x86", "virt-manager"],
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
