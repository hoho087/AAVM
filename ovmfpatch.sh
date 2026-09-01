#!/usr/bin/env bash
set -e

if [ "$EUID" != 0 ]; then
    faillock --reset
    sudo -E "$0" "$@"
    exit $?
fi

if [[ ! -f vars.sh ]]; then
  echo -e "$(pwd)/\e[1mvars.sh\e[0m does not exist, aborting..."
  exit 0
else
  echo -e "$(pwd)/\e[1mvars.sh\e[0m found."
  source vars.sh
fi

SCRIPT_DIR="$(pwd)"
EDK2_DEST="/usr/share/edk2/ovmf"
CODE_FILE="OVMF_CODE_4M.patched.qcow2"
VARS_FILE="OVMF_VARS_4M.empty.qcow2"
VARS_FILE_2="OVMF_VARS_4M.patched.qcow2"
CODE_DEST="${EDK2_DEST}/${CODE_FILE}"
VARS_DEST="${EDK2_DEST}/${VARS_FILE}"
VARS_DEST_2="${EDK2_DEST}/${VARS_FILE_2}"

numbers=(
  "01" "02" "03" "04" "05" "06" "07" "08" "09" "10" "11" "12"
)

get_random_element() {
  local array=("$@")
  echo "${array[RANDOM % ${#array[@]}]}"
}

get_random_string() { head /dev/urandom | tr -dc 'A-Z'    | head -c "$1"; }
get_random_serial() { head /dev/urandom | tr -dc 'A-Z0-9' | head -c "$1"; }
get_random_dec()    { head /dev/urandom | tr -dc '0-9'    | head -c "$1"; }
get_random_hex()    { head /dev/urandom | tr -dc '0-9A-F' | head -c "$1"; }

get_new_string() {
  local random_string=""
  local vowel_count=0
  while [ $vowel_count -ne $2 ]
  do
    random_string="$(get_random_string 100)"
    new_string=$(echo $random_string | sed -E 's/(.)\1+/\1/g' | head -c $1)
    vowel_count=$(echo $new_string | grep -io '[aeiou]' | wc -l)
  done
  prefix=$(echo $new_string | head -c 1)
  suffix=$(echo $new_string | tail -c ${#new_string} | tr '[A-Z]' '[a-z]')
}

if [[ ! -d ovmfbackup ]]; then
  echo -e "$(pwd)/\e[1movmfbackup\e[0m does not exist, clone started..."
  git clone --recursive --single-branch --branch edk2-stable202602 https://github.com/tianocore/edk2.git ovmfbackup
else
  echo -e "$(pwd)/\e[1movmfbackup\e[0m found."
fi

file_MdeModulePkg="$(pwd)/ovmf/MdeModulePkg/MdeModulePkg.dec"
file_Dsdt="$(pwd)/ovmf/OvmfPkg/Bhyve/AcpiTables/Dsdt.asl"
file_Facp="$(pwd)/ovmf/OvmfPkg/Bhyve/AcpiTables/Facp.aslc"
file_Hpet="$(pwd)/ovmf/OvmfPkg/Bhyve/AcpiTables/Hpet.aslc"
file_Madt="$(pwd)/ovmf/OvmfPkg/Bhyve/AcpiTables/Madt.aslc"
file_Mcfg="$(pwd)/ovmf/OvmfPkg/Bhyve/AcpiTables/Mcfg.aslc"
file_Platform="$(pwd)/ovmf/OvmfPkg/Bhyve/AcpiTables/Platform.h"
file_Spcr="$(pwd)/ovmf/OvmfPkg/Bhyve/AcpiTables/Spcr.aslc"
file_VbeShim="$(pwd)/ovmf/OvmfPkg/Bhyve/BhyveRfbDxe/VbeShim.c"
file_BhyveX64="$(pwd)/ovmf/OvmfPkg/Bhyve/BhyveX64.dsc"
file_BhyveSmbiosPlatformDxe="$(pwd)/ovmf/OvmfPkg/Bhyve/SmbiosPlatformDxe/SmbiosPlatformDxe.c"
file_SmbiosPlatformDxe="$(pwd)/ovmf/OvmfPkg/SmbiosPlatformDxe/SmbiosPlatformDxe.c"
file_QemuQ35Hsti="$(pwd)/ovmf/OvmfPkg/VirtHstiDxe/QemuQ35.c"
file_QemuPCHsti="$(pwd)/ovmf/OvmfPkg/VirtHstiDxe/QemuPC.c"
file_PlatformUni="$(pwd)/ovmf/OvmfPkg/PlatformDxe/Platform.uni"
file_SioComponentName="$(pwd)/ovmf/OvmfPkg/SioBusDxe/ComponentName.c"
file_X86QemuLoadImageLib="$(pwd)/ovmf/OvmfPkg/Library/X86QemuLoadImageLib/X86QemuLoadImageLib.c"
file_QemuFwCfgCacheInit="$(pwd)/ovmf/OvmfPkg/Library/QemuFwCfgLib/QemuFwCfgCacheInit.c"
file_FwBlockService="$(pwd)/ovmf/OvmfPkg/QemuFlashFvbServicesRuntimeDxe/FwBlockService.c"
file_QemuFlash="$(pwd)/ovmf/OvmfPkg/QemuFlashFvbServicesRuntimeDxe/QemuFlash.c"
file_ComponentName="$(pwd)/ovmf/OvmfPkg/QemuVideoDxe/ComponentName.c"
file_Driver="$(pwd)/ovmf/OvmfPkg/QemuVideoDxe/Driver.c"
file_ShellPkg="$(pwd)/ovmf/ShellPkg/ShellPkg.dec"
file_QemuBootOrderLib="$(pwd)/ovmf/OvmfPkg/Library/QemuBootOrderLib/QemuBootOrderLib.c"
file_AuthServiceInternal="$(pwd)/ovmf/SecurityPkg/Library/AuthVariableLib/AuthServiceInternal.h"
file_Q35MchIch9="$(pwd)/ovmf/OvmfPkg/Include/IndustryStandard/Q35MchIch9.h"
file_BhyveDefines="$(pwd)/ovmf/OvmfPkg/Bhyve/BhyveDefines.fdf.inc"
file_OvmfPkgDefines="$(pwd)/ovmf/OvmfPkg/Include/Fdf/OvmfPkgDefines.fdf.inc"

if [[ -f "$file_MdeModulePkg" ]]; then rm "$file_MdeModulePkg"; fi
if [[ -f "$file_Dsdt" ]]; then rm "$file_Dsdt"; fi
if [[ -f "$file_Facp" ]]; then rm "$file_Facp"; fi
if [[ -f "$file_Hpet" ]]; then rm "$file_Hpet"; fi
if [[ -f "$file_Madt" ]]; then rm "$file_Madt"; fi
if [[ -f "$file_Mcfg" ]]; then rm "$file_Mcfg"; fi
if [[ -f "$file_Platform" ]]; then rm "$file_Platform"; fi
if [[ -f "$file_Spcr" ]]; then rm "$file_Spcr"; fi
if [[ -f "$file_VbeShim" ]]; then rm "$file_VbeShim"; fi
if [[ -f "$file_BhyveX64" ]]; then rm "$file_BhyveX64"; fi
if [[ -f "$file_BhyveSmbiosPlatformDxe" ]]; then rm "$file_BhyveSmbiosPlatformDxe"; fi
if [[ -f "$file_SmbiosPlatformDxe" ]]; then rm "$file_SmbiosPlatformDxe"; fi
if [[ -f "$file_QemuQ35Hsti" ]]; then rm "$file_QemuQ35Hsti"; fi
if [[ -f "$file_QemuPCHsti" ]]; then rm "$file_QemuPCHsti"; fi
if [[ -f "$file_PlatformUni" ]]; then rm "$file_PlatformUni"; fi
if [[ -f "$file_SioComponentName" ]]; then rm "$file_SioComponentName"; fi
if [[ -f "$file_X86QemuLoadImageLib" ]]; then rm "$file_X86QemuLoadImageLib"; fi
if [[ -f "$file_QemuFwCfgCacheInit" ]]; then rm "$file_QemuFwCfgCacheInit"; fi
if [[ -f "$file_FwBlockService" ]]; then rm "$file_FwBlockService"; fi
if [[ -f "$file_QemuFlash" ]]; then rm "$file_QemuFlash"; fi
if [[ -f "$file_ComponentName" ]]; then rm "$file_ComponentName"; fi
if [[ -f "$file_Driver" ]]; then rm "$file_Driver"; fi
if [[ -f "$file_ShellPkg" ]]; then rm "$file_ShellPkg"; fi
if [[ -f "$file_QemuBootOrderLib" ]]; then rm "$file_QemuBootOrderLib"; fi
if [[ -f "$file_AuthServiceInternal" ]]; then rm "$file_AuthServiceInternal"; fi
if [[ -f "$file_Q35MchIch9" ]]; then rm "$file_Q35MchIch9"; fi
if [[ -f "$file_BhyveDefines" ]]; then rm "$file_BhyveDefines"; fi
if [[ -f "$file_OvmfPkgDefines" ]]; then rm "$file_OvmfPkgDefines"; fi
mkdir -p ovmf
cp -a ovmfbackup/. ovmf
cp -fr splash.bmp ovmf/MdeModulePkg/Logo/Logo.bmp
cp -fr /sys/firmware/acpi/bgrt/image ovmf/MdeModulePkg/Logo/Logo.bmp

# Keep board-level firmware identity coherent with the physical board whose
# factory Secure Boot databases are imported into the guest VARS.
read_dmi() {
  local field="$1" fallback="$2" value
  value=""
  if [[ -r "/sys/class/dmi/id/${field}" ]]; then
    value="$(tr -d '\000\r\n' < "/sys/class/dmi/id/${field}")"
  fi
  case "$value" in
    ""|*'"'*|*'\\'*|*'|'*) value="$fallback" ;;
  esac
  printf '%s' "$value"
}

escape_sed_replacement() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//&/\\&}"
  value="${value//|/\\|}"
  printf '%s' "$value"
}

validate_identity_value() {
  local label="$1" value="$2"
  case "$value" in
    ""|*$'\n'*|*$'\r'*|*'"'*|*'\\'*)
      echo "Unsafe ${label} value; refusing to generate OVMF source" >&2
      exit 1
      ;;
  esac
}

firmware_vendor="${KVM_AAVM_FIRMWARE_VENDOR:-$(read_dmi bios_vendor 'American Megatrends Inc.')}"
firmware_version="${KVM_AAVM_FIRMWARE_VERSION:-$(read_dmi bios_version '440')}"
firmware_date="${KVM_AAVM_FIRMWARE_DATE:-$(read_dmi bios_date '10/11/2017')}"
board_vendor="${KVM_AAVM_BOARD_VENDOR:-$(read_dmi board_vendor 'ASUSTeK COMPUTER INC.')}"
board_product="${KVM_AAVM_BOARD_PRODUCT:-$(read_dmi board_name 'TUF GAMING B850-PLUS WIFI')}"
hsti_platform="${board_vendor} ${board_product}"
validate_identity_value "firmware vendor" "$firmware_vendor"
validate_identity_value "firmware version" "$firmware_version"
validate_identity_value "firmware date" "$firmware_date"
validate_identity_value "board vendor" "$board_vendor"
validate_identity_value "board product" "$board_product"
firmware_vendor_sed="$(escape_sed_replacement "$firmware_vendor")"
firmware_version_sed="$(escape_sed_replacement "$firmware_version")"
firmware_date_sed="$(escape_sed_replacement "$firmware_date")"
hsti_platform_sed="$(escape_sed_replacement "$hsti_platform")"

# SMBIOS Type 0 stores numeric BIOS release components separately from the
# printable version. Keep both fields tied to the same host firmware string;
# do not generate a random version/date that contradicts the factory key
# provider shown elsewhere in the guest firmware.
bios_digits="$(printf '%s' "$firmware_version" | tr -cd '0-9')"
if [[ ${#bios_digits} -ge 2 ]]; then
  bios_major_release="${bios_digits:0:2}"
  bios_minor_release="${bios_digits:2:2}"
elif [[ ${#bios_digits} -eq 1 ]]; then
  bios_major_release="$bios_digits"
  bios_minor_release=0
else
  bios_major_release=0
  bios_minor_release=0
fi
bios_major_release="${bios_major_release#0}"
bios_minor_release="${bios_minor_release#0}"
bios_major_release="${bios_major_release:-0}"
bios_minor_release="${bios_minor_release:-0}"

echo "  $file_MdeModulePkg"
echo "\"EDK II\"                                          -> \"${firmware_vendor}\""
echo "\"INTEL \"                                          -> \"ALASKA\""
echo "0x20202020324B4445                                -> 0x20202049204D2041" #"    2KDE","   I M A"
sed -i "$file_MdeModulePkg" -Ee "s|\"EDK II\"|\"${firmware_vendor_sed}\"|"
sed -i "$file_MdeModulePkg" -Ee "s/\"INTEL \"/\"ALASKA\"/"
sed -i "$file_MdeModulePkg" -Ee "s/0x20202020324B4445/0x20202049204D2041/"
echo "Firmware vendor/version/date -> ${firmware_vendor} / ${firmware_version} / ${firmware_date}"
sed -i "$file_MdeModulePkg" -Ee "s|(^[[:space:]]*gEfiMdeModulePkgTokenSpaceGuid\.PcdFirmwareVendor[|]L\")[^\"]*(\"[|]VOID.*)|\1${firmware_vendor_sed}\2|"
sed -i "$file_MdeModulePkg" -Ee "s|(^[[:space:]]*gEfiMdeModulePkgTokenSpaceGuid\.PcdFirmwareVersionString[|]L\")[^\"]*(\"[|]VOID.*)|\1${firmware_version_sed}\2|"
sed -i "$file_MdeModulePkg" -Ee "s|(^[[:space:]]*gEfiMdeModulePkgTokenSpaceGuid\.PcdFirmwareReleaseDateString[|]L\")[^\"]*(\"[|]VOID.*)|\1${firmware_date_sed}\2|"

echo "  $file_Dsdt"
echo "\"BHYVE\"                                           -> \"ALASKA\""
echo "\"BVDSDT\"                                          -> \"A M I   \""
sed -i "$file_Dsdt" -Ee "s/\"BHYVE\"/\"ALASKA\"/"
sed -i "$file_Dsdt" -Ee "s/\"BVDSDT\"/\"A M I   \"/"

echo "  $file_Facp"
echo "'B','V','F','A','C','P',' ',' '                   -> 'A',' ','M',' ','I',' ',' ',' '"
sed -i "$file_Facp" -Ee "s/'B','V','F','A','C','P',' ',' '/'A',' ','M',' ','I',' ',' ',' '/"

echo "  $file_Hpet"
echo "'B','V','H','P','E','T',' ',' '                   -> 'A',' ','M',' ','I',' ',' ',' '"
sed -i "$file_Hpet" -Ee "s/'B','V','H','P','E','T',' ',' '/'A',' ','M',' ','I',' ',' ',' '/"

echo "  $file_Madt"
echo "'B','V','M','A','D','T',' ',' '                   -> 'A',' ','M',' ','I',' ',' ',' '"
sed -i "$file_Madt" -Ee "s/'B','V','M','A','D','T',' ',' '/'A',' ','M',' ','I',' ',' ',' '/"

echo "  $file_Mcfg"
echo "'B','V','M','C','F','G',' ',' '                   -> 'A',' ','M',' ','I',' ',' ',' '"
sed -i "$file_Mcfg" -Ee "s/'B','V','M','C','F','G',' ',' '/'A',' ','M',' ','I',' ',' ',' '/"

echo "  $file_Platform"
echo "'B','H','Y','V','E',' '                           -> 'A','L','A','S','K','A'"
echo "'B','H','Y','V'                                   -> 'A','M','I',' '"
sed -i "$file_Platform" -Ee "s/'B','H','Y','V','E',' '/'A','L','A','S','K','A'/"
sed -i "$file_Platform" -Ee "s/'B','H','Y','V'/'A','M','I',' '/"

echo "  $file_Spcr"
echo "'B','V','S','P','C','R',' ',' '                   -> 'A',' ','M',' ','I',' ',' ',' '"
sed -i "$file_Spcr" -Ee "s/'B','V','S','P','C','R',' ',' '/'A',' ','M',' ','I',' ',' ',' '/"

echo "  $file_VbeShim"
get_new_string 4 1
echo "\"VESA\"                                            -> \"$new_string\""
sed -i "$file_VbeShim" -Ee "s/\"VESA\"/\"$new_string\"/"
get_new_string 4 1
echo "\"FBSD\"                                            -> \"$new_string\""
sed -i "$file_VbeShim" -e  '/OemNameAddress/{n;d;}'
sed -i "$file_VbeShim" -Ee "/OemNameAddress/a\  CopyMem (Ptr, \"$new_string\", 5);"
#get_new_string 4 1
echo "\"FBSD\"                                            -> \"$new_string\""
sed -i "$file_VbeShim" -e  '/VendorNameAddress/{n;d;}'
sed -i "$file_VbeShim" -Ee "/VendorNameAddress/a\  CopyMem (Ptr, \"$new_string\", 5);"

echo "  $file_BhyveX64"
echo "\"BHYVE\"                                           -> \"ALASKA\""
sed -i "$file_BhyveX64" -Ee "s/\"BHYVE\"/\"ALASKA\"/"

echo "  $file_BhyveSmbiosPlatformDxe"
echo "\"EFI Development Kit II / OVMF\\0\"                           -> \"${firmware_vendor}\\0\""
echo "\"0.0.0\\0\"                                                   -> \"${firmware_version}\\0\""
echo "\"02/06/2015\\0\"                                              -> \"${firmware_date}\\0\""
sed -i "$file_BhyveSmbiosPlatformDxe" -Ee "s|\"EFI Development Kit II / OVMF\\\\0\"|\"${firmware_vendor_sed}\\\\0\"|"
sed -i "$file_BhyveSmbiosPlatformDxe" -Ee "s|\"0.0.0\\\\0\"|\"${firmware_version_sed}\\\\0\"|"
sed -i "$file_BhyveSmbiosPlatformDxe" -Ee "s#\"02/06/2015\\\\0\"#\"${firmware_date_sed}\\\\0\"#"
echo "0xE800, // UINT16                    BiosSegment            -> 0xE000, // UINT16                    BiosSegment"
echo "0,      // UINT8                     BiosSize               -> 0xFF,   // UINT8                     BiosSize"
echo "1,   // BiosCharacteristicsNotSupported                     -> 0,   // BiosCharacteristicsNotSupported"
sed -i "$file_BhyveSmbiosPlatformDxe" -Ee "s/0xE800, \/\/ UINT16                    BiosSegment/0xE000, \/\/ UINT16                    BiosSegment/"
sed -i "$file_BhyveSmbiosPlatformDxe" -Ee "s/0,      \/\/ UINT8                     BiosSize/0xFF,   \/\/ UINT8                     BiosSize/"
sed -i "$file_BhyveSmbiosPlatformDxe" -Ee "s/1,   \/\/ BiosCharacteristicsNotSupported/0,   \/\/ BiosCharacteristicsNotSupported/"
echo "           // Remaining BiosCharacteristics bits left unset :60"
echo "           v v v v v v v v v v v v v v v v v v v v v v v v v v"
echo "           0    // ReservedForVendor                        :32"
sed -i "$file_BhyveSmbiosPlatformDxe" -Ee "/           \/\/ Remaining BiosCharacteristics bits left unset :60/a\      0,   // IsaIsSupported                                :1\n\
      0,   // McaIsSupported                                :1\n\
      0,   // EisaIsSupported                               :1\n\
      1,   // PciIsSupported                                :1\n\
      0,   // PcmciaIsSupported                             :1\n\
      0,   // PlugAndPlayIsSupported                        :1\n\
      0,   // ApmIsSupported                                :1\n\
      1,   // BiosIsUpgradable                              :1\n\
      1,   // BiosShadowingAllowed                          :1\n\
      0,   // VlVesaIsSupported                             :1\n\
      0,   // EscdSupportIsAvailable                        :1\n\
      1,   // BootFromCdIsSupported                         :1\n\
      1,   // SelectableBootIsSupported                     :1\n\
      0,   // RomBiosIsSocketed                             :1\n\
      0,   // BootFromPcmciaIsSupported                     :1\n\
      1,   // EDDSpecificationIsSupported                   :1\n\
      0,   // JapaneseNecFloppyIsSupported                  :1\n\
      0,   // JapaneseToshibaFloppyIsSupported              :1\n\
      0,   // Floppy525_360IsSupported                      :1\n\
      0,   // Floppy525_12IsSupported                       :1\n\
      0,   // Floppy35_720IsSupported                       :1\n\
      0,   // Floppy35_288IsSupported                       :1\n\
      0,   // PrintScreenIsSupported                        :1\n\
      0,   // Keyboard8042IsSupported                       :1\n\
      1,   // SerialIsSupported                             :1\n\
      1,   // PrinterIsSupported                            :1\n\
      0,   // CgaMonoIsSupported                            :1\n\
      0,   // NecPc98                                       :1\n\
0x400013   // ReservedForVendor                             :32"
echo "0,   // BiosReserved                                        -> 0x03, // BiosReserved"
echo "0x1C // SystemReserved                                      -> 0x0D // SystemReserved"
echo "0,     // UINT8                     SystemBiosMajorRelease  -> $bios_major_release,     // UINT8                     SystemBiosMajorRelease"
echo "0,     // UINT8                     SystemBiosMinorRelease  -> $bios_minor_release,    // UINT8                     SystemBiosMinorRelease"
sed -i "$file_BhyveSmbiosPlatformDxe" -Ee "s/0,   \/\/ BiosReserved/0x03, \/\/ BiosReserved/"
sed -i "$file_BhyveSmbiosPlatformDxe" -Ee "s/0x1C \/\/ SystemReserved/0x0D \/\/ SystemReserved/"
sed -i "$file_BhyveSmbiosPlatformDxe" -Ee "s/0,     \/\/ UINT8                     SystemBiosMajorRelease/$bios_major_release,     \/\/ UINT8                     SystemBiosMajorRelease/"
sed -i "$file_BhyveSmbiosPlatformDxe" -Ee "s/0,     \/\/ UINT8                     SystemBiosMinorRelease/$bios_minor_release,    \/\/ UINT8                     SystemBiosMinorRelease/"

echo "  $file_SmbiosPlatformDxe"
echo "0xE800, // UINT16                    BiosSegment            -> 0xE000, // UINT16                    BiosSegment"
echo "0,      // UINT8                     BiosSize               -> 0xFF,   // UINT8                     BiosSize"
echo "1,   // BiosCharacteristicsNotSupported                     -> 0,   // BiosCharacteristicsNotSupported"
sed -i "$file_SmbiosPlatformDxe" -Ee "s/0xE800, \/\/ UINT16                    BiosSegment/0xE000, \/\/ UINT16                    BiosSegment/"
sed -i "$file_SmbiosPlatformDxe" -Ee "s/0,      \/\/ UINT8                     BiosSize/0xFF,   \/\/ UINT8                     BiosSize/"
sed -i "$file_SmbiosPlatformDxe" -Ee "s/1,   \/\/ BiosCharacteristicsNotSupported/0,   \/\/ BiosCharacteristicsNotSupported/"
echo "    // Remaining BiosCharacteristics bits left unset :60"
echo "    v v v v v v v v v v v v v v v v v v v v v v v v v v"
echo "    0    // ReservedForVendor                        :32"
sed -i "$file_SmbiosPlatformDxe" -Ee "/    \/\/ Remaining BiosCharacteristics bits left unset :60/a\    0,   // IsaIsSupported                                :1\n\
    0,   // McaIsSupported                                :1\n\
    0,   // EisaIsSupported                               :1\n\
    1,   // PciIsSupported                                :1\n\
    0,   // PcmciaIsSupported                             :1\n\
    0,   // PlugAndPlayIsSupported                        :1\n\
    0,   // ApmIsSupported                                :1\n\
    1,   // BiosIsUpgradable                              :1\n\
    1,   // BiosShadowingAllowed                          :1\n\
    0,   // VlVesaIsSupported                             :1\n\
    0,   // EscdSupportIsAvailable                        :1\n\
    1,   // BootFromCdIsSupported                         :1\n\
    1,   // SelectableBootIsSupported                     :1\n\
    0,   // RomBiosIsSocketed                             :1\n\
    0,   // BootFromPcmciaIsSupported                     :1\n\
    1,   // EDDSpecificationIsSupported                   :1\n\
    0,   // JapaneseNecFloppyIsSupported                  :1\n\
    0,   // JapaneseToshibaFloppyIsSupported              :1\n\
    0,   // Floppy525_360IsSupported                      :1\n\
    0,   // Floppy525_12IsSupported                       :1\n\
    0,   // Floppy35_720IsSupported                       :1\n\
    0,   // Floppy35_288IsSupported                       :1\n\
    0,   // PrintScreenIsSupported                        :1\n\
    0,   // Keyboard8042IsSupported                       :1\n\
    1,   // SerialIsSupported                             :1\n\
    1,   // PrinterIsSupported                            :1\n\
    0,   // CgaMonoIsSupported                            :1\n\
    0,   // NecPc98                                       :1\n\
0x400013 // ReservedForVendor                             :32"
echo "0,   // BiosReserved                                        -> 0x03, // BiosReserved"
echo "0x1C // SystemReserved                                      -> 0x0D // SystemReserved"
echo "0,     // UINT8                     SystemBiosMajorRelease  -> $bios_major_release,     // UINT8                     SystemBiosMajorRelease"
echo "0,     // UINT8                     SystemBiosMinorRelease  -> $bios_minor_release,    // UINT8                     SystemBiosMinorRelease"
sed -i "$file_SmbiosPlatformDxe" -Ee "s/0,   \/\/ BiosReserved/0x03, \/\/ BiosReserved/"
sed -i "$file_SmbiosPlatformDxe" -Ee "s/0x1C \/\/ SystemReserved/0x0D \/\/ SystemReserved/"
sed -i "$file_SmbiosPlatformDxe" -Ee "s/0,     \/\/ UINT8                     SystemBiosMajorRelease/$bios_major_release,     \/\/ UINT8                     SystemBiosMajorRelease/"
sed -i "$file_SmbiosPlatformDxe" -Ee "s/0,     \/\/ UINT8                     SystemBiosMinorRelease/$bios_minor_release,    \/\/ UINT8                     SystemBiosMinorRelease/"
echo "VendStr = L\"unknown\";                                       -> VendStr = L\"${firmware_vendor}\";"
echo "VersStr = L\"unknown\";                                       -> VersStr = L\"${firmware_version}\";"
echo "DateStr = L\"02/02/2022\";                                    -> DateStr = L\"${firmware_date}\";"
sed -i "$file_SmbiosPlatformDxe" -Ee "s|VendStr = L\"unknown\";|VendStr = L\"${firmware_vendor_sed}\";|"
sed -i "$file_SmbiosPlatformDxe" -Ee "s|VersStr = L\"unknown\";|VersStr = L\"${firmware_version_sed}\";|"
sed -i "$file_SmbiosPlatformDxe" -Ee "s#DateStr = L\"02/02/2022\";#DateStr = L\"${firmware_date_sed}\";#"

echo "HSTI platform descriptor -> ${hsti_platform}"
sed -i "$file_QemuQ35Hsti" -Ee "s|L\"OVMF \\(Qemu Q35\\)\"|L\"${hsti_platform_sed}\"|"
sed -i "$file_QemuPCHsti" -Ee "s|L\"OVMF \\(Qemu PC\\)\"|L\"${hsti_platform_sed}\"|"
sed -i "$file_PlatformUni" -Ee "s|OVMF Platform Configuration|${hsti_platform_sed} Platform Configuration|g; s|OVMF Settings|${firmware_vendor_sed} Settings|g; s|OVMF|${firmware_vendor_sed}|g"
sed -i "$file_SioComponentName" -Ee "s|OVMF Sio Bus Driver|${firmware_vendor_sed} Sio Bus Driver|"
sed -i "$file_X86QemuLoadImageLib" -Ee "s|OVMF:|${firmware_vendor_sed}:|g"

echo "  $file_QemuFwCfgCacheInit"
get_new_string 4 1
echo "QEMU FW CFG                                       -> $new_string FW CFG"
sed -i "$file_QemuFwCfgCacheInit" -Ee "s/QEMU FW CFG/$new_string FW CFG/"

echo "  $file_FwBlockService"
#get_new_string 4 1
echo "QEMU flash                                        -> $new_string Flash"
echo "QEMU Flash                                        -> $new_string Flash"
sed -i "$file_FwBlockService" -Ee "s/QEMU flash/$new_string Flash/"
sed -i "$file_FwBlockService" -Ee "s/QEMU Flash/$new_string Flash/"

echo "  $file_QemuFlash"
#get_new_string 4 1
echo "\"QEMU                                             -> \"$new_string"
sed -i "$file_QemuFlash" -Ee "s/\"QEMU/\"$new_string/"
echo "\"QemuFlashDetected                                -> \"${prefix}${suffix}FlashDetected"
sed -i "$file_QemuFlash" -Ee "s/\"QemuFlashDetected/\"${prefix}${suffix}FlashDetected/"

echo "  $file_ComponentName"
#get_new_string 4 1
echo "L\"QEMU                                            -> L\"$new_string"
sed -i "$file_ComponentName" -Ee "s/L\"QEMU/L\"$new_string/"

echo "  $file_Driver"
#get_new_string 4 1
echo "L\"QEMU                                            -> L\"$new_string"
sed -i "$file_Driver" -Ee "s/L\"QEMU/L\"$new_string/"
cpu_vendor="$(awk -F: '/^vendor_id[[:space:]]*:/ {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}' /proc/cpuinfo)"
if [[ "$cpu_vendor" != "AuthenticAMD" && "$cpu_vendor" != "GenuineIntel" ]]; then
  echo "Unsupported x86 CPU vendor: ${cpu_vendor:-unknown}" >&2
  exit 1
fi
if [[ "$cpu_vendor" == "AuthenticAMD" ]]; then
  echo "0x1234                                            -> 0x1022"
  echo "0x1b36                                            -> 0x1022"
  echo "0x1af4                                            -> 0x1022"
  echo "0x15ad                                            -> 0x1022"
  sed -i "$file_Driver" -Ee "s/0x1234/0x1022/"
  sed -i "$file_Driver" -Ee "s/0x1b36/0x1022/"
  sed -i "$file_Driver" -Ee "s/0x1af4/0x1022/"
  sed -i "$file_Driver" -Ee "s/0x15ad/0x1022/"
else
  echo "0x1234                                            -> 0x8086"
  echo "0x1b36                                            -> 0x8086"
  echo "0x1af4                                            -> 0x8086"
  echo "0x15ad                                            -> 0x8086"
  sed -i "$file_Driver" -Ee "s/0x1234/0x8086/"
  sed -i "$file_Driver" -Ee "s/0x1b36/0x8086/"
  sed -i "$file_Driver" -Ee "s/0x1af4/0x8086/"
  sed -i "$file_Driver" -Ee "s/0x15ad/0x8086/"
fi
echo "0x1111                                            -> 0x$device"
sed -i "$file_Driver" -Ee "s/0x1111/0x$device/"

echo "  $file_ShellPkg"
echo "\"EDK II\"                                          -> \"${firmware_vendor}\""
sed -i "$file_ShellPkg" -Ee "s|\"EDK II\"|\"${firmware_vendor_sed}\"|"

echo "  $file_QemuBootOrderLib"
get_new_string $(shuf -i 5-7 -n 1) 3
echo "\"VMMBootOrder%04x\"                                -> \"${prefix}${suffix}%04x\""
sed -i "$file_QemuBootOrderLib" -Ee "s/\"VMMBootOrder%04x\"/\"${prefix}${suffix}%04x\"/"

echo "  $file_AuthServiceInternal"
get_new_string $(shuf -i 5-7 -n 1) 3
echo "L\"certdb\"                                         -> L\"db${prefix}${suffix}\""
sed -i "$file_AuthServiceInternal" -Ee "s/L\"certdb\"/L\"db${prefix}${suffix}\"/"
echo "L\"certdbv\"                                        -> L\"dbv${prefix}${suffix}\""
sed -i "$file_AuthServiceInternal" -Ee "s/L\"certdbv\"/L\"dbv${prefix}${suffix}\"/"

echo "  $file_Q35MchIch9"
if [[ "$cpu_vendor" == "AuthenticAMD" ]]; then
  echo "INTEL_Q35_MCH_DEVICE_ID  0x29C0                   -> INTEL_Q35_MCH_DEVICE_ID  0x$edk2bridge_1022"
  sed -i "$file_Q35MchIch9" -Ee "s/INTEL_Q35_MCH_DEVICE_ID  0x29C0/INTEL_Q35_MCH_DEVICE_ID  0x$edk2bridge_1022/"
else
  echo "INTEL_Q35_MCH_DEVICE_ID  0x29C0                   -> INTEL_Q35_MCH_DEVICE_ID  0x$edk2bridge_8086"
  sed -i "$file_Q35MchIch9" -Ee "s/INTEL_Q35_MCH_DEVICE_ID  0x29C0/INTEL_Q35_MCH_DEVICE_ID  0x$edk2bridge_8086/"
fi
echo "ICH9_CPU_HOTPLUG_BASE  0x0CD8                     -> ICH9_CPU_HOTPLUG_BASE  0x$( printf '%X' $cpu )"
sed -i "$file_Q35MchIch9" -Ee "s/ICH9_CPU_HOTPLUG_BASE  0x0CD8/ICH9_CPU_HOTPLUG_BASE  0x$( printf '%X' $cpu )/"

echo "  $file_BhyveDefines"
echo "0x800000                                          -> 0x810000"
sed -i "$file_BhyveDefines" -Ee "s/0x800000/0x810000/"

echo "  $file_OvmfPkgDefines"
echo "0x800000                                          -> 0x810000"
sed -i "$file_OvmfPkgDefines" -Ee "s/0x800000/0x810000/"

read -p $'Continue? [y/\e[1mN\e[0m]> ' -n 1 -r
if [[ $REPLY =~ ^[Yy]$ ]]; then
  echo ""
else
  echo ""
  exit 0
fi

cd ovmf
export WORKSPACE="$(pwd)"
export EDK_TOOLS_PATH="${WORKSPACE}/BaseTools"
export CONF_PATH="${WORKSPACE}/Conf"

build_firmware() {
  echo "Building BaseTools (EDK II build tools)..."
  make -C BaseTools; source edksetup.sh
  echo "Compiling OVMF with Secure Boot and TPM support..."
  build \
    -D SECURE_BOOT_ENABLE \
    -D SMM_REQUIRE -D TPM1_ENABLE -D TPM2_ENABLE \
    -a X64 -p OvmfPkg/OvmfPkgX64.dsc \
    -b RELEASE -t GCC5 -n 0 \
    -s -q
}

if [[ -f "$VARS_DEST" ]]; then
  echo -e "${EDK2_DEST}/\e[1m${VARS_FILE}\e[0m found."
  read -p $'Rebuild? [y/\e[1mN\e[0m]> ' -n 1 -r
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    build_firmware
  else
    echo ""
  fi
else
  build_firmware
fi

sudo mkdir -p "$EDK2_DEST"
qemu-img convert -f raw -O qcow2 Build/OvmfX64/RELEASE_GCC5/FV/OVMF_CODE.fd $CODE_DEST
qemu-img convert -f raw -O qcow2 Build/OvmfX64/RELEASE_GCC5/FV/OVMF_VARS.fd $VARS_DEST
echo "$CODE_DEST"
echo "$VARS_DEST"

read -p $'Set EFI variables? [\e[1mY\e[0m/n]> ' -n 1 -r
if [[ $REPLY =~ ^[Nn]$ ]]; then
  echo ""
  cp -f "$VARS_DEST" "$VARS_DEST_2"
  echo "$VARS_DEST_2"
  exit 0
else
  echo ""
fi
# Do not copy host UEFI variables into a build artifact. The deployer reads
# only the motherboard factory variables at Secure Boot configuration time,
# combines them with Microsoft keys, and removes custom key material.
virt-fw-vars --input "$VARS_DEST" --output "$VARS_DEST_2" \
  --set-false CustomMode \
  --set-false SecureBootEnable
