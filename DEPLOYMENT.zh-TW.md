# Ubuntu 24.04 快速部署器

這個部署器將原 README 的 Fedora/RPM 步驟改為 Ubuntu 24.04 amd64 的
APT、DEB、`update-initramfs`、`update-grub` 與 systemd/libvirt 流程。舊腳本仍保留作為
QEMU/OVMF patch 的來源，但實際建置永遠在每台 VM 的乾淨副本中執行。
部署器會將 QEMU/OVMF 共用的 CPU hotplug I/O base 限定為 4-byte 對齊，並在
OVMF 建置前再次驗證；這可避免隨機到未對齊位址時卡在 `CpuHotplugSmm`、
圖形控制台只顯示 `Guest has not initialized the display (yet)`。
建立或續接 VM 時若選擇立即啟動 Windows 安裝，部署器會在啟動後自動送出一次空白鍵，
避免使用者在開啟 virt-manager 期間錯過 Windows ISO 的 `Press any key to boot from CD or DVD`
倒數，然後在空白虛擬磁碟上看到 `No bootable option or device was found`。
安裝階段會依原 README 順序使用 Ubuntu 系統 QEMU、`pc-q35-noble` 與系統 OVMF CODE，
但沿用該 VM 專屬 NVRAM，避免 Windows PE 在全部低階層 QEMU patch 啟用時卡住。
Windows 安裝並完整關機後，VM 第 2 步才切換為專屬 QEMU、`pc-q35-11.0`、patched
OVMF 與 SSDT；此時固定保留 VNC/VGA 且不啟用任何硬體直通。VM 第 3 步才選擇並一次
套用 GPU、PCI、USB、ROM BAR、精簡設備與動態單 GPU hook。首次 GPU 直通預設先進入
通用驅動維護階段：實體 GPU 已掛入 guest，但保留 VNC/VGA 與虛擬網路；安裝完 guest
顯示驅動並關機後，再執行第 3 步切換為純實體顯卡輸出。

## 1. 製作一次離線包

在一台可上網、乾淨的 Ubuntu 24.04 amd64 主機執行：

```bash
cd KVM-AntiAntiVM
sudo apt-get update
./tools/prepare_offline.sh
./deploy.sh validate-offline
```


可公開轉交的部署包不應內含 Windows ISO、破解軟體或某張顯卡專用的驅動。
建立 VM 時請輸入自己合法取得的 Windows ISO 絕對路徑；部署器只會在 `KVM/`
內實際偵測到 Windows ISO 時提供預設值。GPU 驅動則由 guest 的 Windows Update
自動安裝，或由使用者在通用 GPU 驅動維護階段自行安裝。
完成後複製**整個專案目錄**到離線主機。`offline/` 會包含 DEB、QEMU、EDK2、
linux-tkg、Linux 6.19、`libtpms` 0.9.3 source、AMD fTPM profile patch、memflow archive
和 SHA-256 manifest。部署器不會偷偷連網補檔；`install-offline` 在本機從這份固定 source
建置並安裝 AMD profile 的 `libtpms0`，不使用網路或未受控 binary。

## 2. 從乾淨 Ubuntu 部署

```bash
sudo ./deploy.sh install-offline
sudo ./deploy.sh install-app
sudo ./deploy.sh configure-host
sudo reboot
```

也可以直接執行 `sudo ./deploy.sh`，選主選單第 1 項「Ubuntu 主機一鍵部署／更新」。這一項
會依序完成預檢、離線資源驗證、套件安裝、部署器／virt-manager／AppArmor／hook／服務
更新，以及 Ubuntu KVM/IOMMU 配置，結果與 `bootstrap` 相同。所有較少使用的診斷、
續接、納管與 XML 驗證統一收在「維護與進階工具」；自訂核心與 memflow 則保留在主選單。

### 更新保護

主選單第 8 項「更新保護」使用 `apt-mark hold` 鎖定目前已安裝的 Ubuntu 核心、
headers/modules、QEMU/libvirt、OVMF、virt-manager/virtinst、swtpm/libtpms 與 GPU 驅動套件，
避免一般 `apt upgrade` 或 unattended upgrades 改變已驗證的直通堆疊。其他 Ubuntu
安全更新不受影響。重跑啟用會補鎖後來新增的相關套件；停用只解除部署器自己建立的
hold，不會移除使用者原本的 hold。若要刻意升級核心或虛擬化套件，先由此停用，完成
升級與重新開機驗證後再啟用；virt-manager 升級後應重跑主選單第 1 項以恢復相容修補。

重新開機後檢查：

```bash
./deploy.sh preflight
sudo ./deploy.sh
```

`install-app` 會在 Ubuntu 啟用 AppArmor 時，自動安裝並重新載入限定範圍的 libvirt
規則，讓 libvirt 可探測及執行每台 VM 的專屬 QEMU。規則只允許執行
`/var/lib/kvm-aavm/vms/*/artifacts/generation-*/bin/qemu-system-x86_64`，以及唯讀存取
同一代 `bin/*.aml`（`-acpitable` 使用的 SSDT）與 QEMU 自身的
`share/qemu{,-firmware}` runtime ROM，不會放寬 build tree、整個 artifacts 目錄或停用
AppArmor；重跑會更新同一個 managed block，並保留既有 local 規則。
它也會備份並修補 Ubuntu 24.04 virtinst 的 custom-emulator machine 比對順序，讓
virt-manager 可正常開啟使用 `pc-q35-11.0` 的自訂 QEMU 11 VM 詳細頁；APT 日後覆寫該檔時，
重跑 `install-app` 即會重新檢查及套用。修補後必須關閉再重開 virt-manager。

離線套件包含 `openssh-server`。部署第 2 步、`install-offline` 與 `bootstrap`
會在套件安裝後執行 `systemctl enable --now ssh.service`，確保 SSH 立刻啟動且
開機自啟；部署器不修改 `sshd_config`、認證方式或防火牆規則。
離線 roots 也明確包含 `gir1.2-spiceclientglib-2.0` 與
`gir1.2-spiceclientgtk-3.0`（Ubuntu 僅把它們列為 virt-manager Recommends），確保
virt-manager 能開啟 SPICE 圖形控制台；第 3 步會在安裝應用程式時再次驗證 namespace。

VM 主流程只有三項：
1. 「建立新 Windows VM」：先詢問磁碟 GiB，再詢問名稱、RAM、vCPU 與 ISO；不在此步
   選擇任何直通設備，Windows 以 SPICE/VGA 安裝。部署器從 sysfs 偵測實體核心與 SMT
   sibling；支援 SMT 時預設 `threads=2`，並保留完整實體核心給 Ubuntu。例如
   8C/16T 主機預設為 VM 6C/12T，主機保留 2C/4T。
2. 「去虛擬化（保留 VNC/VGA，不啟用直通）」：切換 patched QEMU/OVMF/SSDT 與完整
   anti-VM XML，詢問可選的 guest VT-d，並保留安全控制台與虛擬網路。
3. 「一鍵直通」：列出完整硬體名稱、ID、IOMMU group、驅動、網路介面、MAC 與狀態，
   再一次套用 GPU、PCI/USB、ROM BAR、精簡設備及 hook。首次預設保留 VNC/VGA 供
   通用 guest 顯示驅動安裝；安裝完並關機後再執行一次，即進入最終直通。
   特殊設備可跳過此步自行配置。

每台部署器 VM 會安裝主機效能 hook：啟動時先儲存各 CPU policy 的
`scaling_governor` 與 `energy_performance_preference`，再切到 `performance`；最後一台
效能模式 VM 完全停止後復原原值。多台 VM 同時運行時會用 lock 與 active marker
避免提前復原。既有 VM 可在「維護與進階工具 → CPU SMT 拓撲／綁核／主機電源效能模式」
重新計算；執行中 VM 不會被中斷，新拓撲從下次完整開機生效。

QEMU/OVMF 原始碼建置可能耗時很久，並需要足夠磁碟空間。

部署器會把所選 Windows ISO staging 到
`/var/lib/kvm-aavm/vms/VM名稱/media/windows-install.iso`，避免 Ubuntu 上
`libvirt-qemu` 無法穿越使用者的 `0750` 家目錄。來源與 VM state 位於同一檔案系統且
ISO 可公開讀取時使用 hard link（不重複占用 ISO 容量）；否則才以原子方式複製。
原始 ISO 不會被移動或刪除。舊 profile 在主選單選「續接未完成的 VM 建立」時會自動遷移。

VM 第 2 步不會解綁主機 GPU，也不會把任何 hostdev 交給 QEMU，因此可先透過 VNC/VGA
確認 patched 身份能正常啟動。第 3 步選擇單 GPU 後才安裝動態 hook、啟用實體 GPU 並
移除 VNC/VGA。需要自行處理特殊直通者可停在第 2 步。

如果 QEMU/OVMF 與虛擬磁碟已完成，但最後的 libvirt XML 定義失敗，更新部署器後可續接：

```bash
sudo ./deploy.sh install-app
sudo ./deploy.sh resume-vm --vm VM名稱
```

續接會核對全部產物及既有 qcow2 的格式與虛擬容量，不會重新編譯，也不會覆寫磁碟。
互動選單亦提供「續接未完成的 VM 建立（不重新編譯）」。

Windows 安裝完成並完整關機後，依序執行 VM 第 2、3 步。CLI 捷徑是：

```bash
sudo ./deploy.sh devirtualize-vm --vm VM名稱
sudo ./deploy.sh one-click-passthrough --vm VM名稱
```

舊的 `enable-gpu`／`finalize-vm` 指令只保留自動化相容性，不再出現在互動主流程。

## 3. 單 GPU 直通

VM 第 3 步選擇內建單 GPU 模式時，精靈會列出所有顯示卡及同一 PCI slot 的
audio/USB functions，每項均需確認。首次套用預設進入通用 GPU 驅動維護階段，
保留 VNC/VGA、虛擬網卡和標準輸入設備，同時將選定的實體 GPU 掛入 guest。
可透過 Windows Update 自動安裝適用驅動，或透過 VNC 手動安裝使用者自備的廠商驅動。
驅動完成後正常關閉 Windows，再執行第 3 步並不選維護模式，才移除 VNC/VGA
並以實體 GPU 為主要畫面。VM 啟動時 hook 會停止 display manager、detach 顯卡，
VM 關機或 force-off 時 reattach 顯卡並恢復 Ubuntu 畫面。建議事先準備 SSH。
新版 hook 若無法完整卸載顯示驅動，會中止 VM 啟動並立即恢復主機畫面；它不會在
libvirt hook 內回呼 `virsh`。精靈還會在關閉畫面前驗證 GPU 的 IOMMU group：
缺少 group，或 group 內還有未選的 PCI function，都會先拒絕直通，避免 QEMU
在主機畫面關閉後才因 group 不完整而退出。

從關閉顯示輸出開始，hook 使用交易式 rollback；display manager、seat 終止、
驅動卸載、PCI unbind、VFIO bind 與選用 bus reset 都有有界等待。任一步逾時或
失敗會觸發 EXIT trap，清除 `driver_override`、重新 probe 原驅動並啟動畫面，
避免 hook 無限卡住而留下長時間黑屏。

單 GPU 的顯示 function 預設生成 `<rom bar="off"/>`，等同取消 virt-manager 裡的
「ROM BAR」勾選；libvirt 會將它轉成 QEMU `rombar=0`。部分高階 NVIDIA 顯卡若保留
預設 ROM BAR，QEMU/guest 韌體可能無法正確讀取或映射顯卡 ROM，結果是螢幕有訊號但
全黑。VM 第 3 步「一鍵直通」可切換此欄位，
預設為關閉；選擇開啟時生成 `<rom bar="on"/>`。設定只套用到實體 GPU 顯示 function，
不會修改網卡、USB controller 或其他 PCI passthrough 裝置，且 XML 隨機化與重新生成後
仍會保留。

單 GPU 固定採動態切換：從 Ubuntu 桌面啟動 VM 時才卸載 NVIDIA 並改綁 `vfio-pci`；
VM 關機或 force-off 後，hook 將顯卡重新交還 Ubuntu 並啟動 display manager。部署器
不再提供提前綁 VFIO／重開機自動啟動 VM 的模式；重跑 `install-app` 會清除舊版留下的
GRUB、initramfs 與 systemd 一次性啟動設定。

若 VM 啟動失敗且主機顯卡仍停留在 `vfio-pci` 或未綁定狀態，可從 SSH/TTY 執行：

```bash
sudo ./deploy.sh recover-display --vm VM名稱
```

此命令拒絕在該 VM 的 QEMU 程序仍運作時搶回 GPU；安全時會清除 `driver_override`、
重新 probe 記錄的原始驅動、恢復 VT/EFI framebuffer 並重啟 display manager。
若 NVIDIA 模組仍保留已解綁裝置的 stale kernel state，程式只清除 override 並要求
重開機，不會冒險熱重綁；重開後再執行 `install-app` 與 `resume-vm` 更新 hook。

不要把整組 USB controller 自動直通；原 README 已指出部分 AMD 主機會因此失效。

## 4. PCI/USB 實體裝置直通

VM 第 3 步「一鍵直通」可分別多選：

- PCI/PCIe 端點：有線/無線網卡、聲卡、USB 控制器及其他裝置。
- USB 周邊：USB 網卡、聲卡、麥克風、鍵盤、滑鼠、接收器等；不能直通的 Linux
  root hub 會自動隱藏。

「保留 libvirt e1000e 虛擬網卡」是獨立選項，不論 PCI 類別偵測結果都會詢問並記住選擇。
使用實體網卡、USB 網卡，或直通包含 USB 網卡的 PCIe USB 控制器時，建議關閉；
舊 profile 首次偵測到實體網路或 PCIe USB 控制器時也預設關閉。後續可在主選單
「維護／修復」→「虛擬設備／libvirt 虛擬網卡開關」隨時變更。

選擇主機正在使用的網卡、儲存控制器或 USB 控制器會讓 Ubuntu 暫時失去該硬體，
套用前務必確認管理連線不依賴它。

部署器建立的 VM 必須完整關機，再從主選單選 VM 第 3 步「一鍵直通」，或執行：

```bash
sudo ./deploy.sh configure-passthrough --vm VM名稱
```

若直通後 VM 無畫面或需要回到虛擬顯示器排查，先讓 VM 完全關機，再從
「維護與進階工具 → 移除 VM 直通並恢復 VNC/VGA 排查模式」執行。此操作會移除
部署器管理的 PCI/USB/GPU/網路直通、恢復 VNC/VGA、PS/2 輸入與 libvirt 虛擬網路，
並保留 VM 磁碟、XML 身分、Guest VT-d、DMA 保護與 Secure Boot 設定。命令列等價操作：

```bash
sudo ./deploy.sh disable-passthrough --vm VM名稱
```

更新前會備份 inactive XML，只替換本部署器管理的 `ua-kvm-aavm-*` hostdev；其他手動
加入的 hostdev 會保留。USB 一般使用 VID/PID 綁定；偵測到多個相同 VID/PID 時才加上
Bus/Device 以避免選錯，但重新插拔後若位置改變，需重新執行此選項。

## 5. 身分隨機化

先納管不是由本程式建立的 VM：

```bash
sudo ./deploy.sh adopt-vm --vm VM名稱
```

- `randomize-xml`：VM 關機時更新 UUID、MAC、磁碟 serial/WWN 與 SMBIOS commandline。
- `set-dynamic --enable`：每次 VM 關機後排程上述 XML 隨機化；主機意外斷電時由開機
  service 補做 pending generation。
- `randomize-all`：更新 XML，並從固定離線原始碼重新建置該 VM 專屬 QEMU/OVMF。

若 VM 使用 persistent `swtpm`，上述 XML 身分刷新會在 UUID 變更時同步搬移
`/var/lib/libvirt/swtpm/<UUID>` state，因此不會靜默製造新的 TPM identity；只有
`recreate-tpm --vm VM名稱 --confirm` 會明確更換 TPM state。

「維護與進階工具 → 重建目前 VM 的 QEMU／OVMF 工件」及
`rebuild-artifacts --vm VM名稱` 只重建 patched QEMU/OVMF/SSDT，保留目前 XML 身份、
Windows Boot Manager、NVRAM、PCI/USB/GPU 直通設定。部署器更新 QEMU/OVMF patch 後，
已完成的 VM 應優先使用此項目套用新工件。

目前版本也會在 QEMU 建置時停用 KVM 的跨 vendor `VMCALL/VMMCALL` 改寫 quirk，
避免 VMAware 的「KVM interception」誤判。更新部署器後，既有 VM 必須完整關機並重建工件：

```bash
sudo ./deploy.sh rebuild-artifacts --vm VM名稱
```

若主機目前啟動的是部署器的 Linux 7.2.2 測試核心，還要在「自訂核心」精靈選擇
Linux 7.2.2 重新建置並重新開機；核心補丁會把 AMD `SVM_EXIT_VMMCALL`／Intel
`EXIT_REASON_VMCALL` 導向 guest `#UD`。只重建 QEMU 工件不會改變已安裝核心的 exit handler。

每次操作會先把 inactive XML 存到 `/var/lib/kvm-aavm/backups/VM名稱/`。大量硬體
身分變更可能觸發 Windows 啟用、驅動或 BitLocker 復原要求。

## 6. VT-d 與 guest IOMMU

Windows 安裝完成並由 VM 第 2 步切換到 patched 去虛擬化階段後，VM 固定包含
split IOAPIC 與 KVM hidden；只有明確啟用進階 guest VT-d 選項時才加入虛擬 IOMMU：

```xml
<features>
  <ioapic driver="qemu"/>
  <kvm><hidden state="on"/></kvm>
</features>
<devices>
  <iommu model="intel"><driver intremap="off" caching_mode="on"/></iommu>
</devices>
```

`model="intel"` 是 Q35 guest 的虛擬 IOMMU 型號，AMD host 也使用它。主機端則依 CPU
自動使用 `intel_iommu=on` 或 `amd_iommu=on`。BIOS 的 VT-d/AMD-Vi/IOMMU 必須由使用者
自行開啟。AMD 主機 KVM 模組會明確設定 `nested=1 avic=1`；Intel 設定 `nested=1`。
每台 VM 預設仍會以
`<feature policy="disable" name="svm|vmx"/>` 隱藏 CPU 虛擬化功能；只有明確啟用
「核心隔離／VBS」的 VM 才改為 `policy="require"`。主機 IOMMU/VFIO、guest 虛擬
IOMMU 與 guest SVM/VMX 是獨立開關：關閉 guest VT-d 不會影響 PCI/USB/GPU
passthrough，開啟 VT-d 也不會自動暴露 SVM/VMX。
`intremap="off"` 只關閉 interrupt remapping，DMA translation 與 guest IOMMU/DMAR 仍然
存在。這是部署器的 Windows 相容模式。第二個明確標示為實驗性的選項可改成
`intremap="on"`，但 QEMU 10.1/11 的既有問題與本機 `test5` A/B 測試都顯示它可能讓
Windows 卡在 `Start Boot Option`；除非 guest 確實需要完整 x2APIC interrupt remapping，
否則不應開啟。Windows 工作管理員的「虛擬化」欄位顯示 CPU 的 nested VMX/SVM，與
guest IOMMU 不同；去虛擬化設定會繼續隱藏該 CPU 功能。
`caching_mode="on"` 是 QEMU 在 guest Intel IOMMU 後方使用 VFIO PCI 裝置的必要條件；
缺少時 QEMU 會在顯卡解綁後立即退出，單 GPU hook 隨即把畫面送回 Ubuntu。
部署器還會使 DMAR 中的虛擬 IOAPIC 使用與 QEMU 內部一致的 root-bus
requester ID，不再宣告無效的 Bus `0xFF`；PCIe Root Port 也會避開 Intel
IGD 保留的 `00:02.x` 位置。這兩項都是實際拓撲修正，不會關閉 guest
IOMMU，並避免 VMAware 2.8.1 新增的 DMAR firmware 特徵。

Windows 的「核心 DMA 保護」還要求 DMAR flags bit 2
`DMA_CTRL_PLATFORM_OPT_IN`。Patched QEMU 為 `intel-iommu` 增加
`dma-control-platform-opt-in` 布林屬性；部署器只在該 VM 明確啟用核心 DMA 保護時加入
`-global intel-iommu.dma-control-platform-opt-in=on`。這個旗標與 interrupt remapping
互相獨立，因此仍可保持已驗證可開機的 `intremap="off"`。VM 第 2 步與
「維護與進階工具 → Guest Secure Boot／核心 DMA 保護／核心隔離」都能設定此功能。
地址寬度不再固定，使用 QEMU 11 的預設 48-bit。實機 A/B 顯示強制 `aw_bits="39"`
會卡在 `Start Boot Option`；移除位寬但保持 `intremap="on"` 仍會卡住，改成
`intremap="off"` 後同一台 `test5` 成功進入桌面。

單 GPU 直通會保留 VM 第 2 步選擇的 guest IOMMU 模式；相容模式使用
`intremap="off"` 與 `caching_mode="on"`，讓 VFIO 裝置可在仿真 VT-d 後方建立 DMA
mapping。GPU 維持原生 PCIe root port，顯示功能加入 `x-vga=true`。GPU slot 的全部功能
仍會由 hook 從 Ubuntu 解綁。新 VM 預設不把同 slot 的 HDMI/DP 音訊 function 傳入
guest，避免部分顯卡出現無訊號；建立精靈與直通管理選單仍可明確開啟，既有 VM 會保留
上次選擇。ROM BAR 是另一個獨立設定，預設同樣關閉。
單 GPU VM 也使用 `on_reboot=destroy`，Windows 的「重新啟動」會先完整停止 VM，需再啟動
一次，避免顯卡 warm reset 失敗。

Guest Secure Boot 使用每台 VM 持久保存的
`firmware/OVMF_VARS_4M.ubuntu-install.qcow2`。啟用時部署器會先備份 VARS，再從主機
UEFI `efivarfs` 讀取目前 active `PK`、`KEK`、`db`、`dbx`，並同時保存
`PKDefault`、`KEKDefault`、`dbDefault`、`dbxDefault` 作為該主機板的 factory-reset state；
快照儲存於 `/var/lib/kvm-aavm/secure-boot/host-active-microsoft.json`，權限為 root-only。

Guest 的 active `PK`、`KEK`、`db`、`dbx` 會逐一鏡像主機目前實際使用的 database，包含已套用
的 Microsoft trust 與 dbx revocation 更新；`*Default` 家族保留主機板 factory values。部署器會先
驗證 active `KEK` 與 `db` 已含 Microsoft 憑證，否則 fail closed。這會完整覆寫先前自行加入的
**Custom keys**，設定 `CustomMode=false`、`VendorKeysNv=true` 及 `SecureBootEnable=true`，但不會
混入 Ubuntu OVMF 自有金鑰。

啟用 Secure Boot 時，部署器會同時記錄供應 active key set 的主機 BIOS vendor/version/date
與主機板名稱，並把同一組資料寫入 guest 韌體的 SMBIOS Type 0 與 HSTI platform descriptor。
後續 QEMU/OVMF artifact 重建會重用這份固定資料，不會再生成互相矛盾的隨機 BIOS 版本或日期；
既有 VM 需在關機時執行「重建目前 VM 的 QEMU／OVMF 工件」才會套用新的 CODE image。

它不會匯入或變更 `BootOrder`、`Boot####`、Windows Boot Manager 或 shim 的 MOK variables。
主機並非 UEFI 開機、或缺少任何 factory variable 時，操作會 fail closed 並且不修改 VM VARS。
這裡是 guest 韌體狀態，與 Ubuntu 主機用於 DKMS/linux-tkg 的 MOK 是兩套不同機制。

若要先檢查或保存部署器將使用的 active/factory key databases，可執行：

```bash
sudo ./deploy.sh export-host-secure-boot --output /root/kvm-aavm-host-secure-boot.json
```

輸出包含 active `PK/KEK/db/dbx` 與其 `*Default` factory-reset databases、UEFI attributes，
不包含 Windows 開機項目或 MOK variables。檔案權限為 `0600`；啟用 guest Secure Boot 時，
部署器會重新讀取主機 variables 並建立新的可稽核快照。

### TPM 裝置

「維護與進階工具 → vTPM 管理」可在 VM 完全關機時選擇 AMD-profiled software TPM 2.0 profile、
一般持久 `swtpm` TPM 2.0，或移除 TPM。AMD profile 只在 AMD host profile 上提供，必須已由
`install-offline` 安裝本專案 source-pinned、版本標記為 `+kvm-aavm1` 的 patched `libtpms0`；
否則部署器會拒絕套用，絕不回退成一般 library。它固定使用 `tpm-crb` 與 TPM 2.0，並回報
AMD/fTPM fixed capability profile。部署流程會讀取主機 `/sys/class/tpm/tpm0/pcr-*` 的實際啟用
PCR bank，讓 `swtpm_setup` 使用同一組；主機沒有可讀取的 TPM 時才使用 `sha1,sha256` fallback。
EK/platform certificate metadata 會設為 `AMD / fTPM / 2.0`；這些設定只會套用到新製造或重新
製造的 TPM state，既有 state 不會由部署器靜默覆寫。

此 profile 不會使用、鎖定或改變主機的 fTPM/Intel PTT；其 state 仍由 libvirt 為該 VM 持久保存。

patched OVMF 以 `TPM2_ENABLE` 建置，發布 artifact 前會驗證 `Tcg2Pei`、`Tcg2Dxe`、
`Tcg2PlatformPei/Dxe` 都存在於實際 DSC/FDF build graph。這些模組會量測 firmware volume、
UEFI image 與後續 boot events，並建立供 Windows 讀取的 TCG2 event log；PCR 值必須由這份
event log 重播得到，部署器不會寫死或複製主機 PCR。既有 swtpm identity 不會因更新 OVMF
靜默重製；是否需要重製應以 guest 的 event-log/PCR replay 結果決定。

這仍然是軟體 TPM，沒有 AMD 真實 fTPM 的硬體 EK 私鑰、平台 seed、廠商 EK 憑證鏈或硬體防回放
計數器；因此不能當成實體 TPM 的遠端證明來源。實體 TPM 的 PCR 是 Ubuntu 主機的量測開機鏈，無法代表 Windows 客體的 UEFI、boot loader 與
驅動程式。為避免安全狀態與量測記錄互相矛盾，部署器不提供實體 TPM 直通。既有實體 TPM
直通 VM 應在完全關機後切換為 vTPM 或移除 TPM；更換 TPM 身分可能要求 BitLocker 復原金鑰。

若要明確重製某台 VM 的 TPM 身分，必須先完整關機，使用：

```bash
sudo ./deploy.sh recreate-tpm --vm VM名稱 --confirm
```

部署器會先把 TPM state 複製到 `/var/lib/kvm-aavm/backups/VM名稱/tpm-state-*`，再將原 state
改名保留為 `*.kvm-aavm-retired-*`，下次啟動才由 libvirt 製造新 state。此命令不會修改
Secure Boot VARS、Windows 磁碟或 XML，但 TPM EK、PCR 與所有 TPM-bound secrets 都會改變；
BitLocker、Windows Hello、Device Encryption 可能要求復原或重新註冊。沒有 `--confirm` 時命令
會拒絕執行。維護選單的「vTPM 管理」也提供相同的二次確認入口。

### Windows 核心隔離／記憶體完整性（VBS/HVCI）

VM 第 2 步與維護選單都提供每台 VM 的 VBS 開關，預設關閉。啟用時部署器會：

- 要求同時啟用 Guest UEFI Secure Boot；互相矛盾的選擇會被拒絕，不會寫入半完成 XML。
- 確認主機 `kvm_amd`/`kvm_intel` 已以 `nested=1` 載入；舊部署若仍是 `nested=0`，
  會寫入持久設定、更新 initramfs 並要求重開 Ubuntu，不會自動啟動 VM。
- 對 AMD guest 加入 `<feature policy="require" name="svm"/>`，Intel 則使用 `vmx`；
  `hypervisor` CPUID bit 與 KVM hidden 繼續維持原設定。
- 可選擇 nested Hyper-V 效能加速，啟用 `direct stimer`、`hv-tlbflush`、`ipi` 等標準
  enlightenment。AMD AVIC 只依主機 `kvm_amd avic` 能力獨立啟用；GMET 與 extended/direct
  TLB flush 仍要求完整 `nested`、`npt`、`avic`、`gmet` 能力。缺少 GMET 不會再把可用的
  AVIC 一起關掉。
- 保留 Secure Boot、guest VT-d、核心 DMA 保護、PCI/USB/GPU 直通及虛擬網卡選擇。

進入 Windows 後再到「Windows 安全性 → 裝置安全性 → 核心隔離詳細資料」開啟
「記憶體完整性」。單 GPU VM 使用 `on_reboot=destroy`，Windows 選擇重新啟動後會先
完整停止，需手動再啟動一次。VBS 會讓 Windows Hypervisor 運行在 KVM 內，實測可使
VMAware 2.8.1 增加一項 `timing anomaly`，雖然仍為 `VM confirmation: false` 且結論是
bare metal，但需要完全 0 偵測時應保持關閉。

Linux 7.2 已包含 KVM AMD GMET 與 nested-SVM 支援。部署器在每次套用安全設定時重新
讀取目前載入的 KVM 模組參數，因此只會在實際可用的核心啟用上述 AMD 擴充；舊核心或
Intel 主機仍可使用標準 nested Hyper-V enlightenment。這些選項降低巢狀 Hyper-V/HVCI
的正確性與效能成本，並不會偽造計時結果或保證移除 `timing anomaly` 偵測。

Linux 7.2 AMD 測試核心在每個 non-SEV vCPU reset 後，先以 30 秒 jiffies grace 維持
VMCB01 的 KVM CPUID 模型，讓韌體與 Windows 早期開機使用架構化的 guest-visible 結果；grace
結束後會黏著清除 VMCB01 的 `INTERCEPT_CPUID`。Windows/Hyper-V 成功寫入 `EFER.SVME`
也會提早 arm；即使 Hyper-V 暫時清除 SVME，也不會在 recalc/init_vmcb 時重新打開 intercept。
vCPU reset 會清除 arm 並重新計時。隱藏 SVM 不能作為原生 CPUID 的條件，否則客體會在早期
開機讀到主機的拓撲和未宣告功能。Nested VMCB02 保留上游的 L0/L1 intercept 合併，不能直接
清除 CPUID：VMCB01 已透傳且 VMCB12 未要求 CPUID exit 時，合併的 VMCB02 會自然透傳；只要
L1 要求 ownership，結果仍保留 CPUID exit。這避免繞過 L1 並重現 Windows Hyper-V 停滯。先前
`resources.cpuid_policy=svme-gated-native` 的舊 profile 在下一次套用去虛擬化設定時會
遷移為 `intercepted`；XML 產生期間也會以 intercepted 相容處理。修改需重新建置、安裝並
開機進入 Linux 7.2.2 patched AMD 核心後才會生效；是否消除 VMAware 計時異常必須以重新
量測結果為準，正式 TIMER 量測必須在 reset/開機至少 30 秒後、且 profiler 已停止時執行。

為了降低仍無法避免的 nested leaf 0 VMEXIT 軟體成本，7.2 實驗補丁會在
`KVM_SET_CPUID2` 後預先快取 guest-visible leaf 0，並在 SVM IRQ-off VMEXIT 路徑直接寫回
EAX/EBX/ECX/EDX、推進 RIP 後立即重入 L2。此路徑不會清除 VMCB02，只限 leaf 0；
CPUID faulting、mediated PMU、SEV-ES、沒有 NRIPS 或其他 leaf 都回到原本的 nested/
CPUID handler。
重複 leaf 0 命中時，會在和 x86 core 相同的 vCPU mode、KVM request 與 thread-work
檢查後留在 `svm_vcpu_run()` 內，略過沒有變化的 ASID、CR2/CR8、VP-ID、DR6 與
nested-RIP entry preparation。v4 在完整回存 RAX/RSP/RIP、CR2/CR0/CR3、
dirty-register 狀態、DEBUGCTL 並執行 STGI 後，才允許延後空的 event completion
與 nested-control tail。只有在無 pending event/request、無 mediated PMU 指令計數、
TLB/ERAP 已乾淨、nested vTPR 啟用且 PMU global MSR 仍由 KVM intercept 時才會命中；
其他情況全部回完整上游 exit tail。
v3 另在 TF/KVM single-step 關閉且 PMU guard 通過時直接提交 NRIPS 與清除 interrupt
shadow，省去通用 instruction-retire/skip 尾端。對上游新版 VMAware 的 `#DB` 計時，只有
VMCB12 明確擁有 `#DB`，且 L0 沒有 debugger、hardware breakpoint、NMI single-step、
event reinjection 或 pending exception 責任時，才在同一輪同步 DR6/DR7 並反射給 L1；其他
狀態完全沿用原本 queued exception 路徑。

v5 曾針對舊版 `Memory > VMM` 加入四槽 nested NPF PTE-value cache。完整 profiler
確認 GPA `0x3000` 命中 499 次，但完整返回延遲桶完全不變；其餘 5,494 個 NPF 反而
都多付出 128–512 ns 為主的查找成本。因此 v6 已撤除此快取並恢復原始 KVM MMU
fault 分類路徑。VMCB12 writable map reuse 則保留：它把主要 `nested_svm_vmexit`
延遲桶由 2–4 us 降至 1–2 us。map 仍只從一次 VMRUN 保留到對應 nested VMEXIT；
GPA 或 memslot generation 改變時會先 unmap 再重建。這不會直接反射尚未分類的
hardware NPF，也不改 VMCB02 的 NPF ownership。

進入 7.2 核心後，先執行唯讀 provenance 檢查，確認載入的模組和 source 不是舊版本：

```bash
sudo python3 verification/verify_live_cpuid_policy.py
```

此檢查會驗證執行中的 `7.2.2-tkg-eevdf`、source tree release、`kvm_amd` vermagic、
loaded module 與 7.2 build tree module 的 GNU build ID、30 秒 reset grace/SVME VMCB01 CPUID handoff、只限 leaf 0 的 L2→L0 fallback、
AMD guest leaf 7 EDX 的 Intel mitigation mask、IRQ-off fastpath 與 event-safe deferred-tail guards、VMCB02 未被直接清除，以及 `win11`
的狀態；也會要求 `nested_npf_value_cache=absent` 與
`vmcb12_map_reuse=present`。`srcversion` 不能單獨證明補丁已載入，因為只修改模組
內部程式碼時它可能保持不變。

AMD SVM 的 CPUID intercept 是全域 bit，沒有 CPUID leaf bitmap。先在沒有
profiler 運作時執行 VMAware TIMER 並記錄 ratio，再另外執行一次下列診斷：

```bash
sudo verification/nested-cpuid-static-fastpath-20260830/VMEXIT_PROFILE.sh \
  start verification/timer-window.txt
# 只重複 TIMER workload 來判斷 CPUID ownership；這次的 ratio 不得當效能結果
sudo verification/nested-cpuid-static-fastpath-20260830/VMEXIT_PROFILE.sh stop
```

預設會使用過濾後的 CPUID-only 模式，但 tracepoint 本身仍會改變 VMEXIT 延遲，
所以不能將 profiler 開啟時的 TIMER ratio 用來做 A/B 比較。停止後報告會附上
`cpuid_path_analysis`。`kvm_nested_vmexit` 發生在 KVM 決定由 L0 處理或轉交 L1
之前，因此它的數量本身不能證明 L1 ownership。新版 profiler 會把 nested CPUID
事件與下一次 `kvm_entry` 前的 `kvm_cpuid` 配對；只有
`cpuid_l2_l0_emulations` 能證明 L2 CPUID 到達 L0 cached handler（包含 IRQ-off
immediate-reentry fastpath）。新版也會先比對 loaded module build ID 與 DWARF
image，再用唯讀 kprobe 將 generic path 的 CPUID leaf 列為
`nested_observed_top`；只有 `cpuid_leaf_probe=enabled` 時才能採信這些 leaf counts。
直接清除 VMCB02
仍會破壞 Hyper-V 對其他 leaf 的 ownership，不是安全方案。

舊版 VMAware 顯示的 `Memory > VMM` 並不是一般 RAM latency。它透過 WHP 建立 nested
vCPU，刻意讀未映射 GPA `0x3000`，計時完整 nested NPF 返回，並以 2256 次
`NtQuerySystemTime` 作分母，門檻為 4.0。上游在 2026-08-22 的 `01b0174` 移除此 WHP
測試，最新版改用硬體 `#DB` 與 `NtRaiseException` 比較，門檻為 2.5。要歸因兩代路徑，
先讓 `win11` 開機並穩定，再開一個獨立的 full 診斷視窗：

```bash
sudo verification/nested-cpuid-static-fastpath-20260830/VMEXIT_PROFILE.sh \
  start verification/nested-timer-window.txt full
# 只執行 TIMER，完成後立刻停止
sudo verification/nested-cpuid-static-fastpath-20260830/VMEXIT_PROFILE.sh stop
```

報告會列出 NPF (`1024`) 與 `#DB` (`65`) 的實際
`kvm_nested_vmexit_inject` 數量、fault GPA，以及 VMEXIT 到下一次 VM entry 的延遲
histogram。full 模式另外將 L1-owned NPF 拆成 `npf_handler_ns`、
`npf_exit_to_l1_confirmed_ns`、`nested_vmexit_ns`、`vmcb12_map_ns`、
`vmcb12_mapped_write_ns` 與 `vmcb12_reused_write_ns`，用來確認原始 MMU 分類路徑與
VMRUN map reuse 是否實際命中。v6 不再探測已移除的 NPF value-cache symbol。
啟用 profiler 時的 ratio 仍不得當成效能 A/B 結果。

命令列等價選項：

```bash
sudo ./deploy.sh configure-guest-security --vm VM名稱 --core-isolation
sudo ./deploy.sh configure-guest-security --vm VM名稱 --no-core-isolation
sudo ./deploy.sh configure-guest-security --vm VM名稱 --core-isolation --hyperv-enlightenments
```

Windows PE 安裝階段暫不加入 guest IOMMU 與 split IOAPIC，使用 Ubuntu QEMU 的標準
中斷路徑以避免安裝程式停在旋轉畫面；VM 第 2 步會啟用 patched QEMU/OVMF、SSDT 與
split IOAPIC，並詢問是否額外啟用 guest VT-d（預設否）。主機 IOMMU 與非 GPU 的
PCI/USB passthrough 不受此選項影響。

安裝階段會從 Ubuntu 的配對範本建立每台 VM 專用的 qcow2 OVMF CODE/VARS。這份 VARS
會跨階段保留 BootOrder、Windows Boot Manager 與使用者韌體設定；VM 第 2 步只將 CODE
切到隨機化 patched OVMF。完整隨機化會重建 patched CODE，但不覆蓋正在使用的 VARS。
部署器啟動安裝器後會在 OVMF 的短暫 DVD 開機時窗內重試送出空白鍵，以適應不同速度
的 CPU、儲存裝置與主機，不必先開啟圖形控制台搶按按鍵。

### 2 MiB Hugepages

「維護與進階工具 → CPU SMT 拓撲／綁核／2 MiB Hugepages／主機電源效能模式」可針對每台
部署器建立的 VM 開關 2 MiB hugepages，預設關閉。啟用時 VM 必須完全關機；部署器依其
RAM 大小預留 `記憶體 GiB × 512` 個頁面，並將所有已啟用 VM 的需求相加，寫入唯一受管理的
`/etc/sysctl.d/99-kvm-aavm-hugepages.conf`。XML 會使用 `<memoryBacking><hugepages>`
及 `<nosharepages/>`，不會啟用 1 GiB hugepages 或不必要的 memlock 限制。

若核心無法立即配置所需頁面，部署器不會修改 VM XML，會恢復先前的 reservation 與 sysctl
檔案；先關閉吃記憶體的程式或降低 VM RAM 後再試。關閉最後一台使用 hugepages 的 VM 設定時，
部署器會將預留歸零並移除自己的 sysctl 檔案。

命令列等價選項：

```bash
sudo ./deploy.sh configure-performance --vm VM名稱 --vcpus 12 --hugepages
sudo ./deploy.sh configure-performance --vm VM名稱 --vcpus 12 --no-hugepages
```

## 7. 精簡 QEMU 虛擬設備

VM 第 3 步可選擇精簡模式；既有部署器 VM 也可在「維護與進階工具」切換此設定。
啟用後會透過 QEMU 11 q35 的 `i8042=off` 停用 PS/2 controller，並移除虛擬 PS/2 鍵鼠、
libvirt 虛擬網卡、虛擬 HDA／SPICE audio，
以及沒有 USB hostdev 時不需要的虛擬 xHCI controller。磁碟、CD-ROM、SATA/PCI root、
OVMF 與 anti-VM 必要設定不會刪除；guest IOMMU 依 VM 第 2 步的選擇保留。Windows 安裝
階段保留 SPICE/VGA；實體單 GPU 啟用後只使用實體顯示輸出。

若沒有直通實體 USB 鍵盤／滑鼠，啟用後 guest 可能無法操作，精靈會要求再次確認。
新增 USB passthrough 時會自動保留必要的 xHCI controller；關閉精簡模式則重新產生完整
受管 XML。此功能不直接重建未由部署器建立的 adopted VM，以免覆蓋未知手動設備。

## 8. 可選核心與 memflow

選單中的核心階段使用 linux-tkg 產生 Ubuntu DEB，不安裝 Fedora RPM，也不套用只修改
`kernel.spec` 的 Fedora strip patch。原 Ubuntu kernel 保留為 GRUB 回復入口。memflow 是
另一個明確選擇的 DKMS 階段。

Secure Boot 也會拒絕沒有 PE/EFI 簽章的 linux-tkg 核心。核心入口現在可選擇「建置新的核心」
或「只修復／驗證現有核心簽章」；後者不重新編譯。部署器會安裝限定 `*-tkg-*` 的
`/etc/kernel/postinst.d/kvm-aavm-sign-custom-kernel`。Ubuntu 自動產生的 DKMS MOK 帶有
`1.3.6.1.4.1.2312.16.1.2` module-only 用途；它能載入 memflow/NVIDIA 模組，但新版
shim 會故意拒絕它簽署的可開機映像，否則會出現 `bad shim signature`。

因此部署器會在 `/var/lib/kvm-aavm/secure-boot/` 產生一把獨立、只含 code-signing
用途的核心開機 MOK，先移除映像中舊的 PE 簽章表，再用 `sbsign` 簽署並以
`sbverify` 驗證後原子替換核心映像。Ubuntu 官方 `*-generic` 核心不會被修改；
同一核心已由該專用 MOK 簽署時會直接跳過。第一次需要在下次開機的
MOK Manager 登錄這張第二憑證。
未來 linux-tkg 套件安裝或重裝時也會自動重簽，原 Ubuntu 核心仍保留為 GRUB 回復入口。

自訂核心不能沿用 Ubuntu 官方核心的預編譯顯示模組。部署器現在會對每個新 TKG 核心執行
`dkms autoinstall -k <版本>`，重建該主機已安裝的 memflow、NVIDIA 或其他 DKMS 模組。
若偵測到 NVIDIA driver 只有官方核心的預編譯模組，會依已安裝的分支與版本（例如
`595-open`、`535-server-open`）尋找完全匹配的 `nvidia-dkms-*` companion DEB；
不匹配時會在重開機前停止並清楚報錯，不會把某張顯卡或某個驅動版本硬編碼給其他機器。
Secure Boot 開啟時，部署器也會以已登錄的 DKMS MOK 簽署 TKG 核心下的外部模組。

linux-tkg 的上游預設雖編譯 AppArmor，但沒有把它列入 `CONFIG_LSM`，會造成
`apparmor_parser` 找不到介面。部署器的 Ubuntu config fragment 會把 AppArmor 設為預設
LSM；GRUB 同時加入 `lsm=landlock,lockdown,yama,integrity,apparmor,bpf`，可兼容先前已
建好的 TKG 核心。若目前核心未啟用 AppArmor，安裝器會先寫好規則並略過即時 reload，
不再讓整個 install-app 流程失敗；重新開機後規則恢復強制執行。

Secure Boot 啟用時，DKMS 會用 `/var/lib/shim-signed/mok/MOK.der` 對 memflow 模組簽署；
Ubuntu 核心只有在這張 Machine Owner Key 已登錄後才允許載入。部署器會建立簽署金鑰、
安裝模組並檢查 MOK 狀態。若尚未登錄，選單會要求設定一組 8–16 字元的一次性 MOK 密碼，
安排下一次開機登錄，而不再把 `Key was rejected by service` 當成 DKMS 編譯失敗。
重新開機時依序操作：

1. 在藍色 MOK Manager 選 `Enroll MOK`。
2. 選 `Continue` → `Yes`。
3. 輸入安裝時設定的一次性 MOK 密碼。
4. 選擇重新開機，回到 Ubuntu 後再執行「安裝 memflow」確認能直接載入。

### 8.1 Linux 7.2.2 實驗核心

自訂核心精靈的第 3 項是獨立的 `Linux 7.2.2` 實驗 profile，目的是在不覆蓋
6.19 穩定核心的前提下測試 HVCI/VBS 的 KVM 效能。它只接受本地、固定版本的
`v7.2.2` source，並要求 CPU 對應的 `amd72-test.mypatch` 或 `intel72-test.mypatch`；
6.19 補丁不會被自動重用，避免在 KVM 結構變動後產生可開機但行為錯誤的核心。

若部署包尚未包含 Linux 7.2.2，準備新的離線包時，
`tools/prepare_offline.sh` 會從 kernel.org 固定下載並保留
`offline/sources/linux-7.2.2.tar.xz`（SHA-256 固定驗證），驗證後解壓到
`offline/sources/linux-7.2`；
目前部署器 profile 固定為 7.2.2；其他 point release 必須先有相容的 CPU 補丁並同步更新 profile，
不會只靠環境變數繞過版本檢查。
部署端不會下載或回退到其他版本，缺少 source／port 補丁時會在編譯前停止。
實驗核心安裝完成後仍保留 Ubuntu generic 與 6.19 TKG 核心，請先在 GRUB 選單測試，
確認 HVCI/VBS、VFIO、NVIDIA/DKMS 和 Secure Boot 後再決定是否使用。

## 9. QEMU-full-emulation 交叉審查

下載專案的五份 QEMU C 原始碼補丁沒有修改 VT-d；其 VT-d 開關實際位於 `VM/模板.xml`。
交叉審查時曾採用其 `aw_bits="39"`，但實機 A/B 證實會阻塞 Windows 開機，現已撤回並
保留 QEMU 預設值。SMBIOS type 20 handle 則從 `0x1400` 移到 `0x2E00`，避免與 type 19
在多 DIMM／大記憶體配置下的 handle 範圍碰撞。

該專案較新的 SMBIOS type 4/7/16/17/20/26/27/28/29/39 XML 欄位控制值得後續移植；
它比在 QEMU binary 內寫死欄位更適合動態身份。但它與本專案既有大型 sed patch 修改同一批
`smbios.c` 區段，不能直接疊加，必須改造成針對乾淨 QEMU 11.0.3 的單一可驗證 patch 後再納入。

未採用其主機腳本中的 `allow_unsafe_interrupts=1`、`disable_vga=1`、永久 `vfio-pci.ids` 與
全域顯卡黑名單：前兩項會降低隔離或破壞本機已驗證的 `x-vga` 單 GPU 輸出，
後兩項與動態切換及跨硬體部署衝突。`nested=1` 只作為主機能力預先準備，
仍由每台 VM 的 VBS 選項決定是否暴露 SVM/VMX。其 QEMU
安裝到 `/usr/bin`、廣泛放寬 AppArmor 和通用 hook 也不取代目前的 per-VM artifacts、
限定 AppArmor 規則與帶失敗回復的逐裝置 hook。

## 常用診斷

```bash
./deploy.sh preflight
./deploy.sh validate-offline
sudo ./deploy.sh validate-xml --vm VM名稱
virsh domstate VM名稱
sudo tail -n 200 /var/log/libvirt/qemu/VM名稱-gpu-hook.log
journalctl -u kvm-aavm-pending.service
```

本專案依原 README 固定使用自訂 QEMU 的 `pc-q35-11.0`。未執行最新版 `install-app` 時，Ubuntu 24.04 內建的 virt-manager/virtinst 可能以系統 QEMU 8.2 查詢 capabilities，因而在詳細資訊頁誤報「主機不支援 pc-q35-11.0」；不要因此把 XML 降版。最新版 `install-app` 會修補此比對順序。也可用 `sudo virsh start VM名稱` 啟動，並以 `自訂QEMU路徑 -machine help` 核對支援情形；需要圖形遠端檢視時可使用離線包內的 `virt-viewer`。

舊版部署器若在 `virsh define` 顯示自訂 QEMU `Operation not permitted`／`拒絕不符權限的操作`，
先執行 `sudo ./deploy.sh install-app` 載入新 AppArmor 規則，再以
`sudo ./deploy.sh resume-vm --vm VM名稱` 安全續接，不必重新編譯或重建磁碟。
若啟動時顯示 `-acpitable ... ssdt1.aml: Permission denied`，從主選單重跑
「Ubuntu 主機一鍵部署／更新」，或在維護工具選「只安裝／更新部署器與服務」，即可加入
SSDT 唯讀規則；libvirt 會在下一次啟動 VM 時重建完整的 per-domain
profile，不需重建 VM。若 ISO 位於不可穿越的家目錄，接著選「續接未完成的 VM 建立」遷移路徑。
