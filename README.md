# KVM-AntiAntiVM

Ubuntu 24.04 amd64 的離線 KVM/QEMU Windows 部署器。專案會在每台 VM 的獨立產物目錄建置
自訂 QEMU、OVMF、SSDT 與可選 Linux 核心，並以 libvirt 管理 Windows VM。目標是提供可重現、
可回復的去虛擬化、身分管理、TPM、Secure Boot、VBS/HVCI 與硬體直通流程。

本專案不是匿名化或安全產品，也不保證任何第三方反虛擬機檢測結果。大量變更硬體身分可能觸發
Windows 啟用、驅動重新安裝、BitLocker 或 Windows Hello 復原；請只在自己擁有且獲授權的主機、
作業系統與映像上使用。

## 使用前提

- 主機：Ubuntu 24.04 amd64，已在 BIOS 開啟 AMD-V/AMD-Vi（或 Intel VT-x/VT-d）。
- 必須能使用 root 權限；離線安裝主機不會由部署器偷偷連網。
- 建立 VM 時提供合法取得的 Windows ISO 絕對路徑。ISO 不會被移動或刪除。
- 單 GPU 直通會暫停主機顯示輸出，建議先準備 SSH 或 TTY；不要直通主機目前依賴的儲存、
  網路或 USB 控制器。
- 目前實驗核心固定為 Linux `7.2.2`，不是 `7.2-rc7`。它不會取代 Ubuntu 官方核心或
  6.19 穩定核心，缺少相符 CPU 補丁時會拒絕建置。

詳細的風險、XML 欄位、故障排查和設計理由請閱讀
[`DEPLOYMENT.zh-TW.md`](DEPLOYMENT.zh-TW.md)。

## 建立離線包

在可上網且乾淨的 Ubuntu 24.04 amd64 主機執行一次：

```bash
cd KVM-AntiAntiVM
sudo apt-get update
./tools/prepare_offline.sh
./deploy.sh validate-offline
```

完成後將整個專案目錄複製到離線主機。`offline/` 會保存 DEB 依賴、固定版本的 QEMU/EDK2、
libtpms 0.9.3 原始碼、memflow DKMS 壓縮檔、Linux 7.2.2 原始碼與 SHA-256 manifest。
準備腳本會清理同一套件的舊版本，避免 `curl`/`libcurl4t64` 或 `libssl-dev`/`libssl3t64`
只帶到其中一個版本而無法離線安裝。

Linux 7.2.2 來源固定為：

```text
https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.2.2.tar.xz
SHA-256: 7d0e7ce14f98c43efe880cffbf354a59be45928fdf7170d7333c374ae91c0d83
```

部署端只接受此版本及對應的 `amd72-test.mypatch`/`intel72-test.mypatch`，不會以環境變數
繞過版本檢查，也不會在缺檔時下載替代來源。

## 主機安裝

在離線 Ubuntu 主機執行：

```bash
sudo ./deploy.sh bootstrap
```

`bootstrap` 會依序完成預檢、離線資源驗證、套件安裝、部署器與 virt-manager/AppArmor/hook
更新，以及 KVM/IOMMU 設定。也可以分開執行：

```bash
sudo ./deploy.sh install-offline
sudo ./deploy.sh install-app
sudo ./deploy.sh configure-host
sudo reboot
```

重開機後可用 `sudo ./deploy.sh` 開啟互動式選單。主選單的「更新保護」會以 `apt-mark hold`
鎖定已驗證的核心、QEMU/libvirt、OVMF、virt-manager、swtpm/libtpms 與 GPU 套件；刻意升級
前先停用，完成升級和重開機驗證後再啟用。

## Windows VM 三階段

1. **建立新 Windows VM**：輸入磁碟大小、名稱、RAM、vCPU 與 ISO。安裝階段使用 Ubuntu
   系統 QEMU、`pc-q35-noble`、系統 OVMF、SPICE/VGA 與虛擬網路，不加入直通設備。
2. **去虛擬化**：Windows 完整關機後，切換至每台 VM 專屬的 patched QEMU/OVMF/SSDT、
   `pc-q35-11.0`、隨機化 XML 身分與 KVM hidden；仍保留 VNC/VGA，並可選擇 guest VT-d。
3. **一鍵直通**：列出 GPU、PCI、USB 及 IOMMU group 後一次套用選取項目。單 GPU 第一次
   預設保留 VNC/VGA 和虛擬網路供 Windows 安裝驅動；驅動完成並關機後再執行一次，才切到
   純實體顯示輸出。

命令列等價操作（`win11` 可替換成其他 VM 名稱）：

```bash
sudo ./deploy.sh devirtualize-vm --vm win11
sudo ./deploy.sh one-click-passthrough --vm win11
sudo ./deploy.sh configure-passthrough --vm win11
```

若 XML 定義或啟動中斷，可先安裝最新 AppArmor 規則再安全續接，不會重建磁碟：

```bash
sudo ./deploy.sh install-app
sudo ./deploy.sh resume-vm --vm win11
```

### 單 GPU 黑屏回復

hook 以有界等待執行停止 display manager、卸載廠商模組、PCI unbind、VFIO bind 與可選 bus
reset；任何一步失敗都會 rollback、重新 probe 原驅動並恢復主機畫面。若 VM 已停止但 GPU
仍停在 `vfio-pci` 或未綁定狀態：

```bash
sudo ./deploy.sh recover-display --vm win11
```

不要在 QEMU 仍執行時搶回 GPU。診斷紀錄位於：

```text
/var/log/libvirt/qemu/win11-gpu-hook.log
```

顯示 function 預設關閉 ROM BAR（`rombar=0`），可在直通精靈中明確開啟。USB 周邊採 VID/PID，
重複裝置才追加 Bus/Device；整組 USB controller 不會自動直通。

## 身分、TPM 與安全功能

納管既有 VM 後，可在 VM 完整關機時刷新 XML 身分：

```bash
sudo ./deploy.sh adopt-vm --vm win11
sudo ./deploy.sh randomize-xml --vm win11
sudo ./deploy.sh set-dynamic --vm win11 --enable
```

XML 身分刷新會更新 UUID、MAC、磁碟 serial/WWN 與 SMBIOS 資料；若使用持久 `swtpm`，會同步
搬移以 UUID 命名的 TPM state，因此不會偷偷改變 TPM 身分。只有明確重建才會更換 TPM：

```bash
sudo ./deploy.sh recreate-tpm --vm win11 --confirm
```

該命令會先備份並退休舊 state，下一次啟動由 libvirt 製造新 state；TPM EK、PCR 和所有
TPM-bound secrets 都會改變，可能觸發 BitLocker/Hello 復原。`recreate-tpm` 也可從互動選單
的「維護與進階工具 -> vTPM 管理」執行，沒有 `--confirm` 時一律拒絕。

Secure Boot 會保存每台 VM 的 OVMF VARS，並將主機目前的 `PK/KEK/db/dbx` 與 factory
databases 鏡像到 guest；不會匯入 BootOrder 或主機 MOK。guest VT-d、核心 DMA 保護、VBS/HVCI
均是獨立選項；啟用 VBS 必須同時啟用 guest Secure Boot。

## Linux 7.2.2 與 nested CPUID

自訂核心選單的 Linux 7.2.2 profile 僅供 AMD/Intel 對應補丁的實驗測試，安裝後仍保留原生
Ubuntu/6.19 核心作為 GRUB 回復入口。變更核心後，先確認載入的模組和 source 確實相同：

```bash
sudo python3 verification/verify_live_cpuid_policy.py
```

CPUID 快速路徑的安全邊界如下：

- AMD SVM 只有全域 `INTERCEPT_CPUID`，沒有 per-leaf bitmap；不能粗暴清除 nested VMCB02
  intercept，否則會繞過 Hyper-V 對其他 leaf 的 ownership，可能讓 Windows 卡死。
- 韌體、一般 Windows 開機及隱藏 guest SVM/VMX 的 VM 一律使用 KVM CPUID 模型；隱藏 SVM
  不代表可安全回傳主機 CPUID，否則會洩漏主機拓撲與客體未宣告的功能。只有 nested L1 寫入
  `EFER.SVME` 後，VMCB01 才可依既有 L0/L1 ownership 規則解除 intercept。
- 先前的 `svme-gated-native` profile 會在下一次套用去虛擬化設定時遷移為
  `resources.cpuid_policy=intercepted`；XML 產生期間也會以 intercepted 相容處理舊 profile。
- AMD-compatible guest 的 `CPUID.7.0.EDX` 清除 Intel 專用的 `SPEC_CTRL`、`STIBP` 與
  `SSBD` bits；AMD 原生 mitigation enumeration 保留在 `0x80000008.EBX`。
- 只對受控的 leaf 0 快取結果，並在 IRQ-off、無 pending event/request、PMU/TLB/ERAP 狀態
  安全且有 NRIPS 時直接重入 L2；其他 leaf、CPUID faulting、SEV-ES 或不符合 guard 的情況
  全部回到完整上游 handler。
- nested VMCB02 仍保留 L0/L1 intercept 合併；不以 VMRUN 當下 CPL 或靜態位元清除來取代它。
- 新版 `#DB` 與舊版 nested NPF/`Memory > VMM` 路徑亦有獨立 guard；實驗 NPF value cache
  已移除，僅保留 generation 檢查的 VMCB12 writable map reuse。

這些修改的目標是讓常見 CPUID 接近原生路徑，而不是偽造計時結果；是否改善 VMAware 必須
在沒有 profiler 時另行量測。profiler 只用於歸因：

```bash
# 先在 profiler 關閉時執行 VMAware TIMER，記錄正式結果
sudo verification/nested-cpuid-static-fastpath-20260830/VMEXIT_PROFILE.sh \
  start verification/timer-window.txt
# 只重複 TIMER workload；此輪 ratio 不可作效能 A/B 結果
sudo verification/nested-cpuid-static-fastpath-20260830/VMEXIT_PROFILE.sh stop

# 同時分析舊版 Memory/NPF 與新版 #DB（需要完整診斷時才使用）
sudo verification/nested-cpuid-static-fastpath-20260830/VMEXIT_PROFILE.sh \
  start verification/nested-timer-window.txt full
sudo verification/nested-cpuid-static-fastpath-20260830/VMEXIT_PROFILE.sh stop
```

## 常用維護命令

```bash
./deploy.sh preflight
./deploy.sh status
./deploy.sh validate-offline
sudo ./deploy.sh validate-xml --vm win11
sudo ./deploy.sh rebuild-artifacts --vm win11
sudo ./deploy.sh disable-passthrough --vm win11
sudo ./deploy.sh configure-performance --vm win11 --vcpus 12 --hugepages
sudo ./deploy.sh configure-guest-security --vm win11 --core-isolation
virsh domstate win11
```

重要位置：

- `/var/lib/kvm-aavm/vms/`：每台 VM 的設定、磁碟媒體與 QEMU/OVMF 產物。
- `/var/lib/kvm-aavm/backups/`：inactive XML、TPM state 與回復備份。
- `/var/log/libvirt/qemu/`：QEMU 與 GPU hook 日誌。
- `offline/`：離線套件、原始碼、manifest 與索引。

若要進行完整部署、故障排查或了解限制，請參閱
[`DEPLOYMENT.zh-TW.md`](DEPLOYMENT.zh-TW.md)。
