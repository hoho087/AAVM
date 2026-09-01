```shell
# Ubuntu 24.04 離線快速部署

> 原始手動流程保留在下方作為參考。新的 Ubuntu 互動式部署器請先閱讀
> [`DEPLOYMENT.zh-TW.md`](DEPLOYMENT.zh-TW.md)。

```bash
# 驗證專案內已封裝的離線資源
./deploy.sh validate-offline

# 在乾淨 Ubuntu 24.04 amd64 完成離線安裝、程式安裝及主機配置
sudo ./deploy.sh bootstrap

# 重開機後啟動精簡中文選單
sudo ./deploy.sh

# VM 主流程只有三步：
# 1. 建立新 VM
# 2. 去虛擬化（保留 VNC/VGA，不啟用直通）
# 3. 一鍵直通（特殊設備可跳過此步並自行配置）

# 對完整關機的部署器 VM 執行相同的第 2、3 步
sudo ./deploy.sh devirtualize-vm --vm VM名稱
sudo ./deploy.sh one-click-passthrough --vm VM名稱
```

For AMD systems, `維護與進階工具 -> vTPM 管理` can enable the source-pinned
AMD-profiled software TPM 2.0 profile. The same menu also manages persistent
guest Secure Boot: it restores the host motherboard factory databases, verifies
their shipped Microsoft keys, and replaces guest `PK/KEK/db/dbx` so custom
firmware keys and OVMF-owned keys are removed.
The OVMF build also aligns BIOS vendor/version/date and its HSTI platform
descriptor with that physical motherboard; rebuild existing VM artifacts after
updating to apply CODE-image changes.
See [`DEPLOYMENT.zh-TW.md`](DEPLOYMENT.zh-TW.md) for the key-policy and BitLocker implications.

The AMD profile uses persistent `swtpm/libtpms` TPM 2.0 behind `tpm-crb`, while
patched OVMF includes the TCG2 PEI/DXE measured-boot modules that extend PCRs and
publish the EFI event log. XML identity refreshes migrate the UUID-keyed swtpm
state, so they do not silently change the TPM identity; `recreate-tpm --confirm`
retires the previous state and creates a fresh TPM identity on the next boot
without starting the VM.
It cannot
contain AMD's hardware-backed endorsement key, platform seed, or factory certificate
chain. It aligns the observable manufacturer/capability profile, PCR banks, and
certificate metadata, but it is not a physical fTPM or a hardware attestation source.

For the Linux 7.2 AMD test kernel, the CPUID policy keeps firmware and ordinary
Windows boot under KVM interception, then clears only VMCB01's CPUID intercept
after the guest enables `EFER.SVME`. Nested VMCB02 preserves the L0/L1 merged
intercept contract. For the measured nested CPUID leaf 0 only, Linux 7.2 caches
the guest-visible CPUID result at `KVM_SET_CPUID2` time and handles the common
case in SVM's IRQ-off immediate-reentry path. After the standard mode/request/
thread-work boundary, repeated leaf-0 exits can remain inside `svm_vcpu_run()`
and skip invariant entry preparation. A stricter v4 guard can also defer the
nested-control and empty event-completion tail, but only after all hardware
register state and DEBUGCTL have been restored and `STGI` has run. Pending
events/requests, PMU state, TLB/ERAP work, non-virtualized TPR, and every other
exit use the complete upstream tail. The guarded leaf-0 path also commits NRIPS directly when TF and KVM
single-step are inactive.  For current upstream VMAware, a separate guarded
path reflects an L1-owned nested `#DB` in the same pass after synchronizing DR6;
host debugging, hardware breakpoints, NMI single-step and event reinjection stay
on the stock queued path. CPUID faulting, mediated PMU,
SEV-ES, missing NRIPS, and every other leaf retain the normal slow/fallback
path. For the legacy nested-NPF Memory check, v5 keeps a four-slot cache only
for non-present faults already proven L1-owned by the stock KVM walker. A hit
rereads and exactly compares the complete NPT PTE chain plus memslot generation;
permission, reserved-bit, GMET-fetch, encrypted/RMP, changed-PTE, and read-error
cases all return to the original MMU path. VMCB12's writable map is retained
only from one VMRUN to its nested VMEXIT, and is remapped if the GPA or memslot
generation changed. No VMCB02 NPF ownership bit is changed and no hardware NPF
is reflected without prior software proof. Host setup persists
`kvm_amd nested=1 avic=1`. Rebuild, install, and boot the patched kernel before
these kernel-side changes become active.

After booting the test kernel, run the read-only provenance check before starting
`win11`:

```bash
sudo python3 verification/verify_live_cpuid_policy.py
```

This checks the running Linux 7.2.2 kernel, module vermagic, the loaded module's GNU
build ID against the module produced by the 7.2 build tree, source markers, the
bounded L2 leaf-0 route, cached IRQ-off fastpath, event-safe deferred-tail
guards, value-validated nested-NPF cache, generation-checked VMCB12 map reuse,
and the absence of rejected VMCB02/broad-leaf changes.
`srcversion` alone is not sufficient proof that the patched module is loaded.

AMD SVM exposes one global CPUID intercept bit, not a per-leaf bitmap. First run
the VMAware TIMER test with no profiler active and record its ratios. Then use a
separate diagnostic run to distinguish an L0-owned intercept from a CPUID exit
that L1 Hyper-V explicitly requested in VMCB12:

```bash
sudo verification/nested-cpuid-static-fastpath-20260830/VMEXIT_PROFILE.sh \
  start verification/timer-window.txt
# Repeat the TIMER workload only to attribute CPUID ownership. Do not use the
# ratios from this instrumented run as performance results.
sudo verification/nested-cpuid-static-fastpath-20260830/VMEXIT_PROFILE.sh stop
```

The profiler defaults to a filtered CPUID-only mode, but tracepoint attachment
still changes VMEXIT latency. The stop command appends `cpuid_path_analysis`.
`kvm_nested_vmexit` is emitted before KVM decides whether an exit stays in L0
or is forwarded to L1, so its count alone is not an ownership result. The
profiler now correlates `kvm_cpuid` before the next `kvm_entry`; only
`cpuid_l2_l0_emulations` proves that an L2 CPUID reached L0's cached handler,
including the new immediate-reentry fastpath.  The profiler also verifies the
loaded module's build ID against its DWARF image and reports generic-path CPUID
leaves as `nested_observed_top`.  Use those leaf counts only when the report
says `cpuid_leaf_probe=enabled`.
Forcing VMCB02 clear remains unsafe because AMD provides one global CPUID
intercept bit and Hyper-V relies on the other leaves.

The older VMAware `Memory > VMM` check is not ordinary RAM latency: it creates
a WHP vCPU, deliberately accesses unmapped GPA `0x3000`, and times the complete
nested NPF return against 2256 `NtQuerySystemTime` calls (threshold 4.0). Upstream
removed that WHP test in commit `01b0174` and now compares hardware `#DB` against
`NtRaiseException` (threshold 2.5). To attribute both paths, boot and settle
`win11`, then use a separate full diagnostic window:

```bash
sudo verification/nested-cpuid-static-fastpath-20260830/VMEXIT_PROFILE.sh \
  start verification/nested-timer-window.txt full
# Run only the TIMER workload, then stop immediately.
sudo verification/nested-cpuid-static-fastpath-20260830/VMEXIT_PROFILE.sh stop
```

The report includes actual `kvm_nested_vmexit_inject` counts for NPF (`1024`)
and `#DB` (`65`), fault GPAs, and exit-to-next-entry histograms. Full mode also
breaks an L1-owned NPF into `npf_handler_ns`,
`npf_exit_to_l1_confirmed_ns`, `nested_vmexit_ns`, `vmcb12_map_ns`, and
`vmcb12_mapped_write_ns`. v6 also reports `vmcb12_reused_write_ns`, which
confirms that nested VMEXIT reused the VMRUN mapping. The experimental v5 NPF
value cache was removed after 499 hits left the GPA `0x3000` round trip
unchanged while all 5,494 misses paid extra lookup cost. As with CPUID,
instrumented ratios are not performance results.

---

+----------+    +----------+    +------------+
| Linux PC | -> | QEMU/KVM | -> | Windows VM |
+----------+    +----------+    +------------+
```


### 1. Use single-gpu-passthrough

- https://github.com/joeknock90/single-gpu-passthrough
- read this repo


### 2. New VM set up in QEMU/KVM

- Virtual Machine Manager >> File >> New Virtual Machine

- Local install media (ISO image or CDROM) >> `Windows10.iso` >> Choose Memory and CPU settings >> _uncheck_ [ ] Enable storage for this virtual machine >> _check_ [x] Customize configuration before install >> [Finish]
  - Overview >> Chipset: Q35, **Firmware**: OVMF_CODE_4M.secboot >> [Apply]
  - [Add Hardware] >> Storage >> Device type: Disk device >> Bus type: SATA >> Create a disk image for the virtual machine: 240 GiB >> Advanced options >> Serial: `generate_your_serial` >> Cache mode: none >> Discard mode: ignore >> [Finish]
  - [Begin Installation] >> Virtual Machine >> Shut Down >> Force Off

- Virtual Machine Manager >> [Open] >> View >> Details >> Video QXL >> Model: VGA >> [Apply]

- Virtual Machine Manager >> [Open] >> View >> Details >> NIC :xx:xx:xx >> XML


- Generate your MAC (UAA) to replace `<mac address="52:54:00:xx:xx:xx"/>` and [Apply]:
  <details>
    <summary>Spoiler</summary>

  ```shell
  <mac address="xx:xx:xx:xx:xx:xx"/>
  ```
  </details>

### 2.1. Configure VM

- Virtual Machine Manager >> [Open] >> View >> Details >> Overview >> XML


- Replace `<domain type="kvm">` and [Apply]:
  <details>
    <summary>Spoiler <b>(do NOT use this example, instead modify it with fake SMBIOS data; sudo dmidecode)</b></summary>

  ```shell
  <domain type="kvm" xmlns:qemu="http://libvirt.org/schemas/domain/qemu/1.0">
    <qemu:commandline>
      <qemu:arg value="-smbios"/>
      <qemu:arg value="type=1,manufacturer=Gigabyte Technology Co.,, Ltd.,product=HP Laptop 14s-fq2xxx,version=23.41,serial=D3E4F56789"/>
      <qemu:arg value="-smbios"/>
      <qemu:arg value="type=2,manufacturer=Gigabyte Technology Co.,, Ltd.,product=89FE,version=34.12,serial=B1C2D3E4F56789"/>
      <qemu:arg value="-smbios"/>
      <qemu:arg value="type=3,manufacturer=Gigabyte Technology Co.,, Ltd.,version=23.41,serial=D3E4F56789"/>
      <qemu:arg value="-smbios"/>
      <qemu:arg value="type=4,sock_pfx=U3E1,manufacturer=Advanced Micro Devices,, Inc.,version=AMD Ryzen 5 5625U 6-Core Processor,max-speed=4300,current-speed=2300"/>
      <qemu:arg value="-smbios"/>
      <qemu:arg value="type=17,manufacturer=Samsung,part=M471A5244CB0-CWE,speed=3200,serial=D3E4F5"/>
      <qemu:arg value="-smbios"/>
      <qemu:arg value="type=8,internal_reference=J1A1,external_reference=Keyboard,connector_type=0x0F,port_type=0x0D"/>
      <qemu:arg value="-smbios"/>
      <qemu:arg value="type=8,internal_reference=J1A1,external_reference=Mouse,connector_type=0x0F,port_type=0x0E"/>
      <qemu:arg value="-smbios"/>
      <qemu:arg value="type=9,slot_designation=J6C1,slot_type=0xAA,slot_data_bus_width=0x0D,current_usage=0x04,slot_length=0x04,slot_id=0x01,slot_characteristics1=0x04,slot_characteristics2=0x03"/>
    </qemu:commandline>
  ```
  </details>


- Replace `</metadata>` and [Apply]:
  <details>
    <summary>Spoiler</summary>

  ```shell
    <vmware xmlns="http://www.vmware.com/schema/vmware.config">
      <config>
        <entry name="hypervisor.cpuid.v0" value="FALSE"/>
      </config>
    </vmware>
  </metadata>
  ```
  </details>


- Replace from `<memory unit="KiB">4194304</memory>` to `<vcpu placement="static">2</vcpu>` and [Apply]:
  <details>
    <summary>Spoiler <b>(use a commercial memory size like 8, 16, or 24 GiB; vcpu example for 8 threads host CPU)</b></summary>

  ```shell
  <memory unit="GiB">24</memory>
  <currentMemory unit="GiB">24</currentMemory>
  <vcpu placement="static">8</vcpu>
  ```
  </details>


- Replace from `<features>` to `</clock>` and [Apply]:
  <details>
    <summary>Spoiler (example for 4 cores 8 threads host CPU)</summary>

  ```shell
  <features>
    <acpi/>
    <apic/>
    <hyperv mode="custom">
      <relaxed state="off"/>
      <vapic state="off"/>
      <spinlocks state="off"/>
      <vpindex state="off"/>
      <runtime state="off"/>
      <synic state="off"/>
      <stimer state="off"/>
      <reset state="off"/>
      <vendor_id state="off"/>
      <frequencies state="off"/>
      <reenlightenment state="off"/>
      <tlbflush state="off"/>
      <ipi state="off"/>
      <evmcs state="off"/>
      <avic state="off"/>
    </hyperv>
    <kvm>
      <hidden state="on"/>
    </kvm>
    <ioapic driver="kvm"/>
    <msrs unknown="fault"/>
    <pmu state="on"/>
    <smm state="on"/>
    <vmport state="off"/>
    <ps2 state="on"/>
  </features>
  <cpu mode="host-passthrough" check="none" migratable="off">
    <topology sockets="1" cores="4" threads="2"/>
    <cache mode="passthrough"/>
    <feature policy="disable" name="hypervisor"/>
    <feature policy="require" name="svm"/>
    <feature policy="require" name="vmx"/>
    <feature policy="disable" name="x2apic"/>
    <feature policy="require" name="topoext"/>
    <feature policy="require" name="spec-ctrl"/>
    <feature policy="require" name="stibp"/>
    <feature policy="require" name="ssbd"/>
  </cpu>
  <clock offset="localtime">
    <timer name="tsc" present="yes" tickpolicy="discard" mode="native"/>
    <timer name="hpet" present="yes"/>
    <timer name="rtc" present="yes"/>
    <timer name="pit" present="yes"/>
    <timer name="kvmclock" present="no"/>
    <timer name="hypervclock" present="no"/>
  </clock>
  ```
  </details>

  - For host @2468002000Hz, using `<timer name="tsc" frequency="1234001000"/>` will scale guest TSC down @2:1 ratio.


- Replace from `<memballoon model="virtio">` to `</memballoon>` and [Apply]:
  <details>
    <summary>Spoiler</summary>

  ```shell
  <memballoon model="none"/>
  ```
  </details>


- Replace `<audio id="1" type="spice"/>` and [Apply]:
  <details>
    <summary>Spoiler <b>(for pipewire sound, not required)</b></summary>

  ```shell
  <audio id="1" type="pipewire" runtimeDir="/run/user/1000">
    <input name="qemuinput"/>
    <output name="qemuoutput"/>
  </audio>
  ```
  </details>

- Virtual Machine Manager >> [Open] >> View >> Details >> Tablet >> [Remove]

- Virtual Machine Manager >> [Open] >> View >> Details >> Serial 1 >> [Remove]

- Virtual Machine Manager >> [Open] >> View >> Details >> Channel (spice) >> [Remove]

- Virtual Machine Manager >> [Open] >> View >> Details >> Controller VirtIO Serial 0 >> [Remove]

### 2.2. Remove excess PCI

- Virtual Machine Manager >> [Open] >> View >> Details >> Overview >> XML

- Remove:
```shell
    <controller type="pci" index="5" model="pcie-root-port">
      <model name="pcie-root-port"/>
      <target chassis="5" port="0x14"/>
      <address type="pci" domain="0x0000" bus="0x00" slot="0x02" function="0x4"/>
    </controller>
    <controller type="pci" index="6" model="pcie-root-port">
      <model name="pcie-root-port"/>
      <target chassis="6" port="0x15"/>
      <address type="pci" domain="0x0000" bus="0x00" slot="0x02" function="0x5"/>
    </controller>
    <controller type="pci" index="7" model="pcie-root-port">
      <model name="pcie-root-port"/>
      <target chassis="7" port="0x16"/>
      <address type="pci" domain="0x0000" bus="0x00" slot="0x02" function="0x6"/>
    </controller>
    <controller type="pci" index="8" model="pcie-root-port">
      <model name="pcie-root-port"/>
      <target chassis="8" port="0x17"/>
      <address type="pci" domain="0x0000" bus="0x00" slot="0x02" function="0x7"/>
    </controller>
    <controller type="pci" index="9" model="pcie-root-port">
      <model name="pcie-root-port"/>
      <target chassis="9" port="0x18"/>
      <address type="pci" domain="0x0000" bus="0x00" slot="0x03" function="0x0" multifunction="on"/>
    </controller>
    <controller type="pci" index="10" model="pcie-root-port">
      <model name="pcie-root-port"/>
      <target chassis="10" port="0x19"/>
      <address type="pci" domain="0x0000" bus="0x00" slot="0x03" function="0x1"/>
    </controller>
    <controller type="pci" index="11" model="pcie-root-port">
      <model name="pcie-root-port"/>
      <target chassis="11" port="0x1a"/>
      <address type="pci" domain="0x0000" bus="0x00" slot="0x03" function="0x2"/>
    </controller>
    <controller type="pci" index="12" model="pcie-root-port">
      <model name="pcie-root-port"/>
      <target chassis="12" port="0x1b"/>
      <address type="pci" domain="0x0000" bus="0x00" slot="0x03" function="0x3"/>
    </controller>
    <controller type="pci" index="13" model="pcie-root-port">
      <model name="pcie-root-port"/>
      <target chassis="13" port="0x1c"/>
      <address type="pci" domain="0x0000" bus="0x00" slot="0x03" function="0x4"/>
    </controller>
    <controller type="pci" index="14" model="pcie-root-port">
      <model name="pcie-root-port"/>
      <target chassis="14" port="0x1d"/>
      <address type="pci" domain="0x0000" bus="0x00" slot="0x03" function="0x5"/>
    </controller>
```

### 3. Environment set up in Linux

- Enter BIOS and enable Virtualization Technology:
  - Enable VT-d for Intel (VMX).
  - Enable AMD-Vi for AMD (SVM).
  - Enable "IOMMU".
  - Disable "Above 4G Decoding".

- Nested Virtualization for Intel:
```shell
sudo su
echo "options kvm_intel nested=0" > /etc/modprobe.d/kvm.conf
echo "options kvm ignore_msrs=0" >> /etc/modprobe.d/kvm.conf
```

- Nested Virtualization for AMD:
```shell
sudo su
echo "options kvm_amd nested=0" > /etc/modprobe.d/kvm.conf
echo "options kvm ignore_msrs=0" >> /etc/modprobe.d/kvm.conf
```

> **Ubuntu deployer note:** the automated deployer prepares the host KVM module
> with `nested=1`, but still hides SVM/VMX from every VM by default. The CPU
> extension is exposed only when that VM explicitly enables the optional
> Core Isolation/VBS mode. See `DEPLOYMENT.zh-TW.md` for the tested workflow
> and its VMAware timing-anomaly trade-off.

- Preload `vfio-pci` module so it can bind to PCI IDs:
```shell
sudo su
echo "softdep radeon pre: vfio-pci" >> /etc/modprobe.d/kvm.conf
echo "softdep amdgpu pre: vfio-pci" >> /etc/modprobe.d/kvm.conf
echo "softdep nouveau pre: vfio-pci" >> /etc/modprobe.d/kvm.conf
echo "softdep nvidia pre: vfio-pci" >> /etc/modprobe.d/kvm.conf
```

- Update initramfs:
```shell
<Fedora> sudo dracut --force
<Debian> sudo update-initramfs -c -k $(uname -r)
```

### 3.1. VFIO GPU passthrough (on Linux PC) (just read https://github.com/joeknock90/single-gpu-passthrough)

- Find GPU location with: `lspci -v | grep -i VGA`
```shell
00:02.0 VGA compatible controller: Intel Corporation HD Graphics 530 (rev 06) (prog-if 00 [VGA controller])
02:00.0 VGA compatible controller: NVIDIA Corporation TU106 [GeForce RTX 2070] (rev a1) (prog-if 00 [VGA controller])
```

- GeForce RTX 2070 has 4 PCI IDs: `lspci -v | grep -i NVIDIA`
```shell
02:00.0 VGA compatible controller: NVIDIA Corporation TU106 [GeForce RTX 2070] (rev a1) (prog-if 00 [VGA controller])
        Subsystem: NVIDIA Corporation TU106 [GeForce RTX 2070]
02:00.1 Audio device: NVIDIA Corporation TU106 High Definition Audio Controller (rev a1)
        Subsystem: NVIDIA Corporation Device 1f02
02:00.2 USB controller: NVIDIA Corporation TU106 USB 3.1 Host Controller (rev a1) (prog-if 30 [XHCI])
        Subsystem: NVIDIA Corporation Device 1f02
02:00.3 Serial bus controller: NVIDIA Corporation TU106 USB Type-C UCSI Controller (rev a1)
        Subsystem: NVIDIA Corporation Device 1f02
```

- Find PCI IDs with: `lspci -n -s 02:00`
```shell
02:00.0 0300: 10de:1f02 (rev a1)
02:00.1 0403: 10de:10f9 (rev a1)
02:00.2 0c03: 10de:1ada (rev a1)
02:00.3 0c80: 10de:1adb (rev a1)
```

- Edit `/etc/default/grub`, use either **intel_iommu=on** or **amd_iommu=on**:
```shell
GRUB_CMDLINE_LINUX="nofb vfio-pci.ids=10de:1f02,10de:10f9,10de:1ada,10de:1adb split_lock_detect=off intel_iommu=on iommu=pt"
```

- For single GPU `vfio-pci.ids` is actually not required as the host is in terminal mode.
  - You can switch TTY with `CTRL+ALT+F2` / `CTRL+ALT+F3` / `...` while the VM is not running.

- Update GRUB and restart Linux PC:
```shell
<Fedora> sudo grub2-mkconfig -o /boot/grub2/grub.cfg
<Debian> sudo grub-mkconfig -o /boot/grub/grub.cfg
```

- Inspect kernel driver in use with: `lspci -k -s 02:00`
```lua
02:00.0 VGA compatible controller: NVIDIA Corporation TU106 [GeForce RTX 2070] (rev a1)
        Subsystem: NVIDIA Corporation TU106 [GeForce RTX 2070]
        Kernel driver in use: vfio-pci
        Kernel modules: nouveau
02:00.1 Audio device: NVIDIA Corporation TU106 High Definition Audio Controller (rev a1)
        Subsystem: NVIDIA Corporation Device 1f02
        Kernel driver in use: vfio-pci
        Kernel modules: snd_hda_intel
02:00.2 USB controller: NVIDIA Corporation TU106 USB 3.1 Host Controller (rev a1)
        Subsystem: NVIDIA Corporation Device 1f02
        Kernel driver in use: xhci_hcd
02:00.3 Serial bus controller: NVIDIA Corporation TU106 USB Type-C UCSI Controller (rev a1)
        Subsystem: NVIDIA Corporation Device 1f02
        Kernel driver in use: vfio-pci
        Kernel modules: i2c_nvidia_gpu
```

- Not loaded as a module, `xhci_hcd` will be managed by libvirt.

### 3.2. Add passthrough GPU devices to Windows VM

- Start VM and install Windows.
  - For single GPU switch to VNC after Windows install.

- Virtual Machine Manager >> [Open] >> View >> Details >> [Add Hardware] >> PCI Host Device:
  - 02:00.0 NVIDIA Corporation TU106 [GeForce RTX 2070] >> **[Finish]**
  - 02:00.1 NVIDIA Corporation TU106 High Definition Audio Controller >> **[Finish]**
  - 02:00.2 NVIDIA Corporation TU106 USB 3.1 Host Controller >> **[Finish]**
  - 02:00.3 NVIDIA Corporation TU106 USB Type-C UCSI Controller >> **[Finish]**

- Install GPU drivers on Windows VM.

- Set `shader cache size` to **10 GiB** with `Nvidia Control Panel`.

### 4. Configure usb passthrough (on Linux PC)

- In the virtual machine manager, pass through the USB port (manually , do not make it script.cus amd motherboard will have problem).


### 5. Spoof QEMU (mandatory)

- This script is based on: [Scrut1ny/Hypervisor-Phantom](https://github.com/Scrut1ny/Hypervisor-Phantom).


  <details>
    <summary>Build on <b>Fedora 44</b>:</summary>

  ```shell
  sudo dnf install acpica-tools bzip2-devel gcc git glib2-devel libfdt-devel libusb1-devel libuuid-devel ninja-build pipewire-devel pixman-devel SDL2_image-devel spice-server-devel usbredir-devel zlib-ng-compat-devel
  ```
  </details>


  <details>
    <summary>Build on <b>Debian 13</b>:</summary>

  ```shell
  sudo apt install acpica-tools
  sudo apt build-dep qemu
  ```
  </details>

- Edit `qemupatch.sh`, use your own `lspci -nn` data:
```shell
lspci -nn

00:1f.0 ISA bridge [0601]: Intel Corporation Tiger Lake-LP LPC Controller [8086:a082] (rev 20)
00:1f.4 SMBus [0c05]: Intel Corporation Tiger Lake-LP SMBus Controller [8086:a0a3] (rev 20)
00:1f.3 Multimedia audio controller [0401]: Intel Corporation Tiger Lake-LP Smart Sound Technology Audio Controller [8086:a0c8] (rev 20)
02:00.0 Non-Volatile memory controller [0108]: Intel Corporation SSD 660P Series [8086:f1a8] (rev 03)
00:1c.0 PCI bridge [0604]: Intel Corporation Tiger Lake-LP PCI Express Root Port #8 [8086:a0bf] (rev 20)
00:14.0 USB controller [0c03]: Intel Corporation Tiger Lake-LP USB 3.2 Gen 2x1 xHCI Host Controller [8086:a0ed] (rev 20)
00:00.0 Host bridge [0600]: Intel Corporation Tiger Lake-UP3/H35 4 cores Host Bridge/DRAM Registers [8086:9a14] (rev 01)
00:14.2 RAM memory [0500]: Intel Corporation Tiger Lake-LP Shared SRAM [8086:a0ef] (rev 20)


lpc_8086="a082"         # Tiger Lake-LP LPC Controller
smbus_8086="a0a3"       # Tiger Lake-LP SMBus Controller
hdaudio_8086="a0c8"     # Tiger Lake-LP Smart Sound Technology Audio Controller
hdaname_8086="Tiger Lake-LP Smart Sound Technology Audio Controller"
sata_8086="f1a8"        # SSD 660P Series
#rootport_8086="a0bf"    # Tiger Lake-LP PCI Express Root Port #8
rootport_8086="a0b8"    # 8-7=1, a0bf-7=a0b8, Tiger Lake-LP PCI Express Root Port #1
xhci_8086="a0ed"        # Tiger Lake-LP USB 3.2 Gen 2x1 xHCI Host Controller
hostbridge_8086="9a14"  # 11th Gen Core Processor Host Bridge/DRAM Registers
pcibridge_8086="a0ef"   # Tiger Lake-LP Shared SRAM
```

- Run `qemupatch.sh` to clone, patch, and build QEMU with generated data.

- Virtual Machine Manager >> [Open] >> View >> Details >> Overview >> XML


- Replace from `<pm>` to `</emulator>` and [Apply]:
  <details>
    <summary>Spoiler</summary>

  ```shell
  <pm>
    <suspend-to-mem enabled="yes"/>
    <suspend-to-disk enabled="no"/>
  </pm>
  <devices>
    <emulator>/usr/local/bin/qemu-system-x86_64</emulator>
  ```
  </details>


- Replace `</qemu:commandline>` and [Apply]:
  <details>
    <summary>Spoiler</summary>

  ```shell
    <qemu:arg value="-acpitable"/>
    <qemu:arg value="file=/usr/local/bin/ssdt1.aml"/>
    <qemu:arg value="-acpitable"/>
    <qemu:arg value="file=/usr/local/bin/ssdt2.aml"/>
  </qemu:commandline>
  ```
  </details>

- Make sure that `pc-q35-11.0` is specified in your XML:
```shell
<type arch="x86_64" machine="pc-q35-11.0">hvm</type>
```

### 5.1. Spoof OVMF (mandatory)

- This script is based on: [Scrut1ny/Hypervisor-Phantom](https://github.com/Scrut1ny/Hypervisor-Phantom).


  <details>
    <summary>Build on <b>Fedora Linux</b>:</summary>

  ```shell
  sudo dnf install g++ nasm python3-virt-firmware
  ```
  </details>


  <details>
    <summary>Build on <b>Debian Linux</b>:</summary>

  ```shell
  sudo apt install g++ nasm python3-virt-firmware
  ```
  </details>

- Run `ovmfpatch.sh` to clone, patch, and build OVMF with generated data.

- Virtual Machine Manager >> [Open] >> View >> Details >> Overview >> XML


- Replace from `<os firmware="efi">` to `</os>` and [Apply]:
  <details>
    <summary>Spoiler</summary>

  ```shell
  <os>
    <type arch="x86_64" machine="pc-q35-11.0">hvm</type>
    <loader readonly="yes" secure="yes" type="pflash" format="qcow2">/usr/share/edk2/ovmf/OVMF_CODE_4M.patched.qcow2</loader>
    <nvram format="qcow2">/usr/share/edk2/ovmf/OVMF_VARS_4M.patched.qcow2</nvram>
    <bootmenu enable="yes"/>
  </os>
  ```
  </details>

### 5.2. Replace network (mandatory)

- Virtual Machine Manager >> [Open] >> View >> Details >> NIC :xx:xx:xx >> [Remove]

- Virtual Machine Manager >> [Open] >> View >> Details >> [Add Hardware] >> USB/PCI Host Device:
  - USB/PCI Network Interface Card >> **[Finish]**

- Start VM.

- Device Manager >> View >> Show hidden devices >> Intel(R) 82574L Gigabit Network Connection >> Uninstall device

### 5.3. Build custom Linux kernel (mandatory)

For the supported Ubuntu offline workflow, use `sudo ./deploy.sh` and choose
the custom-kernel menu. The stable path builds Linux 6.19; the separate
`build-kernel-test` command targets a pinned Linux 7.2.2 source only when the
offline bundle contains it and a separately ported CPU patch. The Fedora RPM
commands below are legacy reference steps and are not used by the deployer.


  <details>
    <summary>Build on <b>Fedora Linux</b>:</summary>

  ```shell
  sudo dnf install util-linux-script
  ```
  </details>

- Run `kernelpatch.sh` to clone, patch, and build custom Linux kernel.

- Install `kernel-6.19.14_tkg_eevdf+-1.x86_64`:
```shell
cd "linux-tkg/RPMs"
sudo dnf install kernel-6.19.14_tkg_eevdf+-1.x86_64.rpm
```

- Edit `/etc/default/grub`, add **mitigations=auto**:
```shell
GRUB_CMDLINE_LINUX="mitigations=auto ..."
```

- Update GRUB and restart Linux PC:
```shell
<Fedora> sudo grub2-mkconfig -o /boot/grub2/grub.cfg
<Debian> sudo grub-mkconfig -o /boot/grub/grub.cfg
```

### 5.4. memflow-kvm

- Boot `kernel-6.19.14_tkg_eevdf+-1.x86_64`.

- Install `dkms`:
```shell
cd "linux-tkg/RPMs"
sudo dnf install kernel-devel-6.19.14_tkg_eevdf+-1.x86_64.rpm
sudo dnf download dkms
sudo rpm -i --nodeps dkms-3.4.1-1.fc44.noarch.rpm
sudo wget https://github.com/memflow/memflow-kvm/releases/download/bin-kernel-6.19/memflow-source-only.dkms.tar.gz
sudo dkms install --archive=memflow-source-only.dkms.tar.gz
```

- Edit `/etc/default/grub`, add **ibt=off**:
```shell
GRUB_CMDLINE_LINUX="ibt=off ..."
```

- Update GRUB and restart Linux PC:
```shell
<Fedora> sudo grub2-mkconfig -o /boot/grub2/grub.cfg
<Debian> sudo grub-mkconfig -o /boot/grub/grub.cfg
```

- Run:
```shell
sudo modprobe memflow
cd path/to/extracted/repository
sudo -E ./nika
```
