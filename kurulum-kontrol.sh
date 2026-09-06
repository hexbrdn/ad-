#!/usr/bin/env bash
#
#  AD Pentest Araç Kurulum & Kontrol Scripti  (Kali Linux)
#  ------------------------------------------------------
#  Kullanım:
#     chmod +x kurulum-kontrol.sh
#     ./kurulum-kontrol.sh            # sadece KONTROL eder (hangi araç var/yok)
#     sudo ./kurulum-kontrol.sh -i    # eksik araçları KURAR
#     ./kurulum-kontrol.sh -h         # yardım
#
#  Not: -i (install) modu apt + pipx kullanır. Windows araçları
#       (PowerView, SharpHound, PingCastle, PurpleKnight, ADExplorer)
#       Kali'ye kurulmaz; script sadece nereden alacağını gösterir.
#
set -o pipefail

# ---------- renkler ----------
G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; B='\033[0;34m'; C='\033[0;36m'; N='\033[0m'; BOLD='\033[1m'
OK="${G}[ VAR ]${N}"; NO="${R}[ YOK ]${N}"; WIN="${C}[ WIN ]${N}"

INSTALL=0
[[ "$1" == "-i" || "$1" == "--install" ]] && INSTALL=1
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
  echo "Kullanim: $0            -> sadece kontrol"
  echo "          sudo $0 -i    -> eksikleri kur"
  exit 0
fi

echo -e "${BOLD}${B}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║      AD PENTEST ARAÇ KURULUM & KONTROL (KALI)         ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${N}"
[[ $INSTALL -eq 1 ]] && echo -e "${Y}>> KURULUM MODU AKTIF (-i): eksikler kurulacak${N}\n" \
                     || echo -e "${C}>> Sadece kontrol modu. Kurmak icin:  sudo $0 -i${N}\n"

# pipx yoksa (kurulum modunda) hazirla
ensure_pipx() {
  if ! command -v pipx &>/dev/null; then
    echo -e "${Y}   pipx bulunamadi, kuruluyor...${N}"
    apt-get install -y pipx >/dev/null 2>&1
    pipx ensurepath >/dev/null 2>&1
  fi
}

TOTAL=0; FOUND=0; MISSING=0

# check <no> <gorunen ad> <komut> <kurulum tipi:apt|pipx|win> <paket/kaynak>
check() {
  local no="$1" name="$2" cmd="$3" type="$4" pkg="$5"
  TOTAL=$((TOTAL+1))
  printf "  ${BOLD}%2s${N}  %-20s " "$no" "$name"

  if [[ "$type" == "win" ]]; then
    echo -e "$WIN  ${C}Windows araci${N} → $pkg"
    return
  fi

  if command -v "$cmd" &>/dev/null; then
    echo -e "$OK  $(command -v "$cmd")"
    FOUND=$((FOUND+1))
  else
    echo -e "$NO"
    MISSING=$((MISSING+1))
    if [[ $INSTALL -eq 1 ]]; then
      echo -e "       ${Y}↳ kuruluyor ($type: $pkg)...${N}"
      case "$type" in
        apt)  apt-get install -y $pkg >/dev/null 2>&1 ;;
        pipx) ensure_pipx; pipx install $pkg >/dev/null 2>&1 ;;
      esac
      if command -v "$cmd" &>/dev/null; then
        echo -e "       ${G}↳ kuruldu ✔${N}"; FOUND=$((FOUND+1)); MISSING=$((MISSING-1))
      else
        echo -e "       ${R}↳ otomatik kurulamadi — manuel bak: $pkg${N}"
      fi
    else
      echo -e "       ${C}↳ kur: $type → $pkg${N}"
    fi
  fi
}

echo -e "${BOLD}── Kali araçları ─────────────────────────────────────────${N}"
check  1  "Nmap"              nmap                 apt  "nmap"
check  2  "NetExec (nxc)"     nxc                  apt  "netexec"
check  3  "enum4linux-ng"     enum4linux-ng        apt  "enum4linux-ng"
check  4  "smbclient"         smbclient            apt  "smbclient"
check  5  "rpcclient"         rpcclient            apt  "samba-common-bin"
check  6  "ldapsearch"        ldapsearch           apt  "ldap-utils"
check  7  "ldapdomaindump"    ldapdomaindump       pipx "ldapdomaindump"
check  8  "Impacket"          impacket-GetUserSPNs apt  "impacket-scripts python3-impacket"
check  9  "Kerbrute"          kerbrute             apt  "kerbrute"
check 10  "Responder"         responder            apt  "responder"
check 12  "Certipy"           certipy              pipx "certipy-ad"
check 14  "bloodhound-python" bloodhound-python    pipx "bloodhound"
check 15  "BloodHound"        bloodhound           apt  "bloodhound"
check 16  "Wireshark"         wireshark            apt  "wireshark"

echo ""
echo -e "${BOLD}── Windows araçları (Kali'ye kurulmaz) ───────────────────${N}"
check 11  "PowerView"    _ win "github.com/PowerShellMafia/PowerSploit (Recon/PowerView.ps1)"
check 13  "SharpHound"   _ win "github.com/BloodHoundAD/SharpHound/releases"
check 17  "ADExplorer"   _ win "learn.microsoft.com/sysinternals/downloads/adexplorer"
check 18  "PingCastle"   _ win "github.com/netwrix/pingcastle/releases"
check 19  "Purple Knight" _ win "semperis.com/purple-knight"

# ---------- ozet ----------
echo ""
echo -e "${BOLD}${B}══════════════════════ ÖZET ══════════════════════${N}"
echo -e "  Kali araçları:  ${G}${FOUND} kurulu${N} / ${R}${MISSING} eksik${N}"
if [[ $MISSING -gt 0 && $INSTALL -eq 0 ]]; then
  echo -e "  ${Y}Eksikleri kurmak için:  ${BOLD}sudo $0 -i${N}"
elif [[ $MISSING -eq 0 ]]; then
  echo -e "  ${G}Tüm Kali araçların hazır — sahaya gidebilirsin! 🚀${N}"
fi
echo -e "  ${C}Windows araçlarını (PowerView/SharpHound/PingCastle/PurpleKnight/ADExplorer)"
echo -e "  ayrı bir Windows makinesine yukaridaki linklerden indir.${N}"
echo ""
echo -e "  Yol haritası:  ${BOLD}AD-Pentest-Yol-Haritasi.html${N}  (tarayıcıda aç)"
echo ""
