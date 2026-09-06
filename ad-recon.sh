#!/usr/bin/env bash
#
# ad-recon.sh  —  Active Directory Guvenlik Test / Kesif Scripti (Kali Linux)
# =============================================================================
#  YALNIZCA yetkili oldugunuz kendi laboratuvar / pentest ortamlariniz icin.
#  Varsayilan mod: NON-DESTRUCTIVE  (enumeration agirlikli, exploit calistirmaz,
#  parola spraying yapmaz, kalicilik olusturmaz).
#
#  Kullanim:   ./ad-recon.sh            (interaktif menu)
#              ./ad-recon.sh --help
# =============================================================================

set -o pipefail

# ----------------------------------------------------------------------------
# GLOBAL CONFIG / DEGISKENLER
# ----------------------------------------------------------------------------
TARGET=""          # tek IP veya subnet (orn: 192.168.11.51  ya da 192.168.11.0/24)
SUBNET=""          # ag blogu
DOMAIN=""          # orn: thm.loc
DC_IP=""           # Domain Controller IP
DC_HOST=""         # orn: DC01
USERNAME=""        # yetkili kullanici (opsiyonel)
PASSWORD=""        # parola (opsiyonel)
NTHASH=""          # NTLM hash (opsiyonel, PtH)
IFACE="eth0"       # varsayilan arayuz

# Cikti dizini (calisma anininda olusturulur)
BASEDIR="ad-pentest_$(date +%Y%m%d_%H%M%S)"
FINDINGS=""        # findings veritabani (add_finding doldurur)
LOGFILE=""

# Renkler
R="\033[1;31m"; G="\033[1;32m"; Y="\033[1;33m"; B="\033[1;34m"; C="\033[1;36m"; W="\033[1;37m"; N="\033[0m"

# ----------------------------------------------------------------------------
# CEKIRDEK YARDIMCI FONKSIYONLAR
# ----------------------------------------------------------------------------
banner() {
cat <<'EOF'
   _   ___    ___
  /_\ |   \  | _ \___ __ ___ _ _
 / _ \| |) | |   / -_) _/ _ \ ' \
/_/ \_\___/  |_|_\___\__\___/_||_|
  Active Directory Recon & Security Assessment  (non-destructive)
EOF
echo -e "${Y}  Sadece YETKILI oldugunuz ortamlarda kullanin.${N}\n"
}

log()   { echo -e "${C}[*]${N} $*" | tee -a "$LOGFILE" 2>/dev/null; }
ok()    { echo -e "${G}[+]${N} $*" | tee -a "$LOGFILE" 2>/dev/null; }
warn()  { echo -e "${Y}[!]${N} $*" | tee -a "$LOGFILE" 2>/dev/null; }
err()   { echo -e "${R}[-]${N} $*" | tee -a "$LOGFILE" 2>/dev/null; }
section(){ echo -e "\n${B}==== $* ====${N}" | tee -a "$LOGFILE" 2>/dev/null; }

# add_finding SEVERITY "Ad" "Etkilenen" "Tespit yontemi" "Aciklama" "Risk" "Kanit" "Duzeltme"
add_finding() {
    local sev="$1" name="$2" affected="$3" method="$4" desc="$5" risk="$6" evidence="$7" remediation="$8"
    # Alan icindeki | ve yeni satirlari temizle
    evidence=$(echo "$evidence" | tr '\n' ' ' | sed 's/|/\//g' | cut -c1-500)
    printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
        "$sev" "$name" "$affected" "$method" "$desc" "$risk" "$evidence" "$remediation" >> "$FINDINGS"
    case "$sev" in
        CRITICAL) echo -e "   ${R}[CRITICAL]${N} $name — $affected" ;;
        HIGH)     echo -e "   ${R}[HIGH]${N} $name — $affected" ;;
        MEDIUM)   echo -e "   ${Y}[MEDIUM]${N} $name — $affected" ;;
        LOW)      echo -e "   ${Y}[LOW]${N} $name — $affected" ;;
        *)        echo -e "   ${C}[INFO]${N} $name — $affected" ;;
    esac
}

have() { command -v "$1" >/dev/null 2>&1; }

# Kimlik argumanlarini olustur (nxc icin)
nxc_auth() {
    local a=""
    [ -n "$USERNAME" ] && a="-u $USERNAME"
    if   [ -n "$PASSWORD" ]; then a="$a -p $PASSWORD"
    elif [ -n "$NTHASH" ];   then a="$a -H $NTHASH"
    else a="$a -u '' -p ''"; fi
    echo "$a"
}

has_creds() { [ -n "$USERNAME" ] && { [ -n "$PASSWORD" ] || [ -n "$NTHASH" ]; }; }

pause() { echo; read -rp "Devam etmek icin ENTER..."; }

# ----------------------------------------------------------------------------
# BASLANGIC: dizin iskeleti + arac kontrolu
# ----------------------------------------------------------------------------
init_dirs() {
    mkdir -p "$BASEDIR"/{scans,smb,ldap,kerberos,users,bloodhound,logs,report}
    FINDINGS="$BASEDIR/report/findings.db"
    LOGFILE="$BASEDIR/logs/run.log"
    : > "$FINDINGS"
    : > "$LOGFILE"
    ok "Cikti dizini olusturuldu: ${W}$BASEDIR/${N}"
}

REQUIRED_TOOLS=(nmap ldapsearch smbclient rpcclient dig nslookup)
OPTIONAL_TOOLS=(nxc crackmapexec enum4linux-ng impacket-GetUserSPNs impacket-GetNPUsers \
                impacket-lookupsid bloodhound-python nbtscan smbmap)

check_tools() {
    section "ARAC KONTROLU"
    local missing_req=() missing_opt=()
    for t in "${REQUIRED_TOOLS[@]}"; do
        if have "$t"; then ok "bulundu:  $t"; else err "EKSIK (gerekli): $t"; missing_req+=("$t"); fi
    done
    for t in "${OPTIONAL_TOOLS[@]}"; do
        if have "$t"; then ok "bulundu:  $t"; else warn "eksik (opsiyonel): $t"; missing_opt+=("$t"); fi
    done
    # nxc/crackmapexec en az biri
    if ! have nxc && ! have crackmapexec; then
        warn "NetExec (nxc) veya CrackMapExec bulunamadi — bazi kontroller atlanacak."
    fi
    echo
    if [ ${#missing_req[@]} -gt 0 ]; then
        err "Eksik GEREKLI araclar: ${missing_req[*]}"
        echo -e "   Kurulum ornekleri:"
        echo -e "     sudo apt install -y nmap ldap-utils smbclient samba-common-bin dnsutils nbtscan smbmap enum4linux-ng"
    fi
    if [ ${#missing_opt[@]} -gt 0 ]; then
        warn "Eksik opsiyonel araclar: ${missing_opt[*]}"
        echo -e "     pipx install netexec impacket bloodhound"
    fi
    pause
}

# NetExec ikili adini sec (nxc yoksa crackmapexec)
NXC="nxc"
pick_nxc() { if have nxc; then NXC="nxc"; elif have crackmapexec; then NXC="crackmapexec"; else NXC=""; fi; }

# ----------------------------------------------------------------------------
# HEDEF / KIMLIK BILGISI GIRISI
# ----------------------------------------------------------------------------
set_target() {
    section "HEDEF & KIMLIK BILGILERI"
    read -rp "Hedef IP veya subnet [${TARGET}]: " x; [ -n "$x" ] && TARGET="$x"
    read -rp "Ag blogu / subnet (orn 192.168.11.0/24) [${SUBNET}]: " x; [ -n "$x" ] && SUBNET="$x"
    read -rp "Domain adi (orn thm.loc) [${DOMAIN}]: " x; [ -n "$x" ] && DOMAIN="$x"
    read -rp "Domain Controller IP [${DC_IP}]: " x; [ -n "$x" ] && DC_IP="$x"
    read -rp "DC hostname (orn DC01) [${DC_HOST}]: " x; [ -n "$x" ] && DC_HOST="$x"
    read -rp "Ag arayuzu [${IFACE}]: " x; [ -n "$x" ] && IFACE="$x"
    echo
    read -rp "Yetkili kimlik girmek ister misiniz? (yoksa anonymous devam) [e/H]: " yn
    if [[ "$yn" =~ ^[eEyY]$ ]]; then
        read -rp "  Kullanici adi: " USERNAME
        read -rp "  Parola (bos birakip hash kullanabilirsiniz): " PASSWORD
        [ -z "$PASSWORD" ] && read -rp "  NTLM hash (LM:NT ya da :NT): " NTHASH
    fi
    # SUBNET bos ise TARGET'tan turet
    [ -z "$SUBNET" ] && [ -n "$TARGET" ] && SUBNET="$TARGET"
    # DC_IP bos ise TARGET
    [ -z "$DC_IP" ] && [ -n "$TARGET" ] && [[ "$TARGET" != *"/"* ]] && DC_IP="$TARGET"
    echo
    ok "Hedef: ${W}${TARGET:-yok}${N} | Subnet: ${W}${SUBNET:-yok}${N} | Domain: ${W}${DOMAIN:-yok}${N} | DC: ${W}${DC_IP:-yok}${N} (${DC_HOST:-?})"
    has_creds && ok "Kimlik: ${W}${USERNAME}${N} (kimlikli mod)" || warn "Kimlik yok — anonymous / unauthenticated mod"
    pause
}

need_target() { [ -z "$TARGET" ] && [ -z "$SUBNET" ] && { err "Once hedef girin (menu > T)."; return 1; }; return 0; }
need_dc()     { [ -z "$DC_IP" ] && { err "DC IP gerekli (menu > T)."; return 1; }; return 0; }

# ============================================================================
# MODUL 1 — AG KESFI
# ============================================================================
mod_network() {
    need_target || { pause; return; }
    section "MODUL 1 — AG KESFI"
    local scope="${SUBNET:-$TARGET}"
    local out="$BASEDIR/scans"

    if have nmap; then
        log "Canli host kesfi (ping/ARP sweep): $scope"
        nmap -sn -n "$scope" -oG "$out/host_discovery.gnmap" 2>&1 | tee "$out/host_discovery.txt" >/dev/null
        local live; live=$(grep -c "Up" "$out/host_discovery.gnmap" 2>/dev/null)
        ok "Canli host sayisi: ${W}${live:-0}${N}  -> $out/host_discovery.txt"
        grep "Up" "$out/host_discovery.gnmap" 2>/dev/null | awk '{print $2}' > "$out/live_hosts.txt"

        log "AD servis portu taramasi (53,88,135,139,389,445,464,636,3268,3269,5985,5986)"
        nmap -Pn -p 53,88,135,139,389,445,464,636,3268,3269,5985,5986 --open -T4 \
            -oA "$out/ad_ports" "$scope" 2>&1 | tee "$out/ad_ports.txt" >/dev/null
        ok "AD port taramasi -> $out/ad_ports.txt"

        # Acik AD portu olan hostlari INFO olarak kaydet
        awk '/Ports:/{print}' "$out/ad_ports.gnmap" 2>/dev/null | while read -r line; do
            ip=$(echo "$line" | awk '{print $2}')
            openp=$(echo "$line" | grep -oE '[0-9]+/open' | tr '\n' ' ')
            [ -n "$openp" ] && add_finding INFO "Acik AD servis portlari" "$ip" "nmap" \
                "Host uzerinde AD ile iliskili acik portlar bulundu." "Bilgi toplama yuzeyi." "$openp" \
                "Gereksiz servisleri kapatin, ag segmentasyonu uygulayin."
        done
    else
        err "nmap yok — ag keşfi atlandi."
    fi

    if have nbtscan; then
        log "NetBIOS isim taramasi"
        nbtscan "$scope" 2>/dev/null | tee "$out/nbtscan.txt" >/dev/null
    fi
    ok "Modul 1 tamamlandi."
    pause
}

# ============================================================================
# MODUL 2 — DOMAIN / DC TESPITI
# ============================================================================
mod_dc_detect() {
    need_target || { pause; return; }
    section "MODUL 2 — DOMAIN / DC TESPITI"
    local ip="${DC_IP:-$TARGET}"
    local out="$BASEDIR/scans"
    [[ "$ip" == *"/"* ]] && { err "DC tespiti icin tek IP gerekli (DC_IP girin)."; pause; return; }

    if have nmap; then
        log "smb-os-discovery ile domain/hostname cikarimi ($ip)"
        nmap -Pn -p445 --script smb-os-discovery "$ip" 2>&1 | tee "$out/smb_os_discovery.txt" >/dev/null
        local d h fqdn
        d=$(grep -i "Domain name:" "$out/smb_os_discovery.txt" | head -1 | awk -F': ' '{print $2}' | tr -d ' \r')
        h=$(grep -i "NetBIOS computer name:" "$out/smb_os_discovery.txt" | head -1 | awk -F': ' '{print $2}' | tr -d ' \r' | sed 's/\\x00.*//')
        fqdn=$(grep -i "FQDN:" "$out/smb_os_discovery.txt" | head -1 | awk -F': ' '{print $2}' | tr -d ' \r')
        [ -n "$d" ] && { [ -z "$DOMAIN" ] && DOMAIN="$d"; ok "Domain: ${W}$d${N}"; }
        [ -n "$h" ] && { [ -z "$DC_HOST" ] && DC_HOST="$h"; ok "Hostname: ${W}$h${N}"; }
        [ -n "$fqdn" ] && ok "FQDN: ${W}$fqdn${N}"
    fi

    # LDAP rootDSE ile dogrulama (anonim)
    if have ldapsearch; then
        log "LDAP rootDSE (anonim) dogrulamasi"
        ldapsearch -x -H "ldap://$ip" -s base -b "" \
            defaultNamingContext dnsHostName serverName rootDomainNamingContext \
            2>/dev/null | tee "$out/rootdse.txt" | grep -iE 'NamingContext|dnsHostName|serverName' | while read -r l; do
                echo -e "   ${C}$l${N}"
            done
        local nc; nc=$(grep -i '^defaultNamingContext:' "$out/rootdse.txt" | awk '{print $2}')
        if [ -n "$nc" ]; then
            ok "defaultNamingContext: ${W}$nc${N}"
            [ -z "$DOMAIN" ] && DOMAIN=$(echo "$nc" | sed 's/DC=//g; s/,/./g')
        fi
    fi

    # DNS SRV kayitlari
    if [ -n "$DOMAIN" ] && have dig; then
        log "DNS SRV kayitlari ile DC dogrulama"
        dig @"$ip" "_ldap._tcp.dc._msdcs.$DOMAIN" SRV +short 2>/dev/null | tee "$out/dns_srv.txt"
    fi

    if [ -n "$DOMAIN" ]; then
        add_finding INFO "Active Directory domain tespit edildi" "${DC_HOST:-$ip} ($ip)" "nmap/ldap/dns" \
            "Domain: $DOMAIN — Domain Controller tespit edildi." "Bilgi." "domain=$DOMAIN dc=$ip host=${DC_HOST}" \
            "N/A (bilgilendirme)."
    fi
    ok "Modul 2 tamamlandi. Domain=${DOMAIN:-?} DC=${DC_IP:-$ip} Host=${DC_HOST:-?}"
    pause
}

# ============================================================================
# MODUL 3 — SMB ANALIZI
# ============================================================================
mod_smb() {
    need_target || { pause; return; }
    pick_nxc
    section "MODUL 3 — SMB ANALIZI"
    local ip="${DC_IP:-$TARGET}"
    local out="$BASEDIR/smb"

    # SMB signing + versiyon (nmap)
    if have nmap; then
        log "SMB security-mode / signing / SMBv1 kontrolu"
        nmap -Pn -p445 --script "smb2-security-mode,smb-security-mode,smb2-capabilities,smb-protocols" \
            "$ip" 2>&1 | tee "$out/smb_security.txt" >/dev/null

        if grep -qi "SMBv1" "$out/smb_security.txt" && grep -qiE "SMBv1.*(enabled|supported)" "$out/smb_security.txt"; then
            add_finding HIGH "SMBv1 etkin" "$ip" "nmap smb-protocols" \
                "Hedef eski ve guvensiz SMBv1 protokolunu destekliyor." \
                "SMBv1 EternalBlue (MS17-010) gibi kritik zafiyetlere ve MITM'e aciktir." \
                "$(grep -i smbv1 "$out/smb_security.txt" | head -1)" \
                "SMBv1'i devre disi birakin (Windows ozelligini kaldirin), yalnizca SMBv2/3 kullanin."
        fi
        if grep -qiE "message_signing:.*disabled|Message signing enabled but not required" "$out/smb_security.txt"; then
            add_finding MEDIUM "SMB signing zorunlu degil" "$ip" "nmap smb2-security-mode" \
                "SMB imzalama kapali veya zorunlu degil." \
                "NTLM relay saldirilarina imkan verir (kimlik dogrulama aktarimi)." \
                "$(grep -i signing "$out/smb_security.txt" | head -1)" \
                "Group Policy ile 'Microsoft network server: Digitally sign communications (always)' = Enabled."
        fi
    fi

    # nxc ile signing/versiyon + zafiyet ozeti
    if [ -n "$NXC" ]; then
        log "NetExec SMB profili"
        $NXC smb "$ip" 2>&1 | tee "$out/nxc_smb_info.txt" >/dev/null
        if grep -qi "signing:False" "$out/nxc_smb_info.txt"; then
            add_finding MEDIUM "SMB signing devre disi (nxc)" "$ip" "NetExec" \
                "signing:False raporlandi." "NTLM relay riski." \
                "$(grep -i signing "$out/nxc_smb_info.txt" | head -1)" \
                "SMB signing'i zorunlu yapin."
        fi

        log "Anonymous / guest SMB erisim testi"
        $NXC smb "$ip" -u '' -p '' 2>&1 | tee "$out/nxc_anon.txt" >/dev/null
        $NXC smb "$ip" -u 'guest' -p '' 2>&1 | tee "$out/nxc_guest.txt" >/dev/null
        if grep -qiE '\[\+\]' "$out/nxc_anon.txt"; then
            add_finding MEDIUM "Anonymous SMB erisimi" "$ip" "NetExec (null session)" \
                "Kimliksiz SMB oturumu kabul edildi." "Bilgi sizintisi (kullanici/paylasim numaralandirma)." \
                "null session basarili" "Anonim erisimi kisitlayin (RestrictNullSessAccess=1)."
        fi

        log "SMB paylasim listesi + yetkiler"
        $NXC smb "$ip" $(has_creds && echo "$(nxc_auth)" || echo "-u '' -p ''") --shares \
            2>&1 | tee "$out/nxc_shares.txt" >/dev/null
        if grep -qiE 'READ|WRITE' "$out/nxc_shares.txt"; then
            local shares; shares=$(grep -iE 'READ|WRITE' "$out/nxc_shares.txt" | awk '{print $5}' | tr '\n' ' ')
            add_finding LOW "Erisilebilir SMB paylasimlari" "$ip" "NetExec --shares" \
                "Okuma/yazma yetkili paylasimlar tespit edildi." \
                "Hassas dosya/GPP parolasi sizintisi olabilir." "$shares" \
                "Paylasim ACL'lerini gozden gecirin; SYSVOL/NETLOGON'da cpassword aramasi yapin."
        fi
    fi

    # smbclient ile anonim paylasim listesi (yedek)
    if have smbclient; then
        log "smbclient -N ile anonim paylasim listesi"
        smbclient -L "//$ip" -N 2>&1 | tee "$out/smbclient_anon.txt" >/dev/null
    fi

    # smbmap yetki matrisi
    if have smbmap && has_creds; then
        log "smbmap yetki matrisi (kimlikli)"
        smbmap -H "$ip" -u "$USERNAME" -p "${PASSWORD:-$NTHASH}" -R --depth 3 \
            2>&1 | tee "$out/smbmap.txt" >/dev/null
    fi

    ok "Modul 3 tamamlandi -> $out/"
    pause
}

# ============================================================================
# MODUL 4 — LDAP ANALIZI
# ============================================================================
mod_ldap() {
    need_dc || { pause; return; }
    section "MODUL 4 — LDAP ANALIZI"
    local ip="$DC_IP"
    local out="$BASEDIR/ldap"
    local base=""
    [ -n "$DOMAIN" ] && base="DC=$(echo "$DOMAIN" | sed 's/\./,DC=/g')"

    # Anonim LDAP erisim testi
    if have ldapsearch; then
        log "Anonymous LDAP baglanti testi"
        if ldapsearch -x -H "ldap://$ip" -s base -b "" defaultNamingContext >/dev/null 2>&1; then
            # rootDSE herkese aciktir; asil anonim veri okunabiliyor mu?
            local cnt
            cnt=$(ldapsearch -x -H "ldap://$ip" -b "$base" "(objectClass=user)" sAMAccountName 2>/dev/null | grep -c "sAMAccountName:")
            if [ "${cnt:-0}" -gt 0 ]; then
                add_finding HIGH "Anonymous LDAP bind ile veri okuma" "$ip" "ldapsearch (anonim)" \
                    "Kimlik dogrulamadan LDAP dizininden kullanici objeleri okunabiliyor." \
                    "Tum domain kullanici/grup yapisi ifsa olur (recon)." "$cnt kullanici okundu" \
                    "Anonymous bind'i kapatin (dsHeuristics), en az ayricalik ilkesini uygulayin."
                ldapsearch -x -H "ldap://$ip" -b "$base" "(objectClass=user)" sAMAccountName \
                    2>/dev/null > "$out/anon_users.txt"
            else
                add_finding INFO "LDAP rootDSE erisilebilir" "$ip" "ldapsearch" \
                    "rootDSE okunabiliyor (normal), anonim veri okuma tespit edilmedi." "Dusuk." "rootDSE ok" \
                    "N/A."
            fi
        fi
    fi

    # LDAP signing / channel binding (nmap script veya nxc)
    pick_nxc
    if [ -n "$NXC" ]; then
        log "LDAP signing / channel binding kontrolu (nxc)"
        $NXC ldap "$ip" $(has_creds && echo "$(nxc_auth)") -M ldap-checker 2>&1 | tee "$out/ldap_checker.txt" >/dev/null
        if grep -qiE 'signing.*not required|channel binding.*(not|disabled)' "$out/ldap_checker.txt"; then
            add_finding MEDIUM "LDAP signing / channel binding zayif" "$ip" "NetExec ldap-checker" \
                "LDAP signing veya channel binding zorunlu degil." \
                "LDAP relay saldirilarina imkan verir." "$(grep -iE 'signing|binding' "$out/ldap_checker.txt" | head -2 | tr '\n' ' ')" \
                "LDAP signing ve LDAPS channel binding'i zorunlu yapin (KB4520412 ilkeleri)."
        fi
    fi

    # Kimlikli LDAP dump
    if has_creds && have ldapsearch; then
        log "Kimlikli LDAP: kullanicilar/gruplar/bilgisayarlar cekiliyor"
        local bind="${USERNAME}@${DOMAIN}"
        local pw="${PASSWORD}"
        ldapsearch -x -LLL -H "ldap://$ip" -D "$bind" -w "$pw" -b "$base" \
            "(objectClass=user)" sAMAccountName 2>/dev/null > "$out/users.txt"
        ldapsearch -x -LLL -H "ldap://$ip" -D "$bind" -w "$pw" -b "$base" \
            "(objectClass=group)" cn 2>/dev/null > "$out/groups.txt"
        ldapsearch -x -LLL -H "ldap://$ip" -D "$bind" -w "$pw" -b "$base" \
            "(objectClass=computer)" dNSHostName operatingSystem 2>/dev/null > "$out/computers.txt"
        ok "LDAP dump -> $out/{users,groups,computers}.txt"

        # Eski isletim sistemleri
        if grep -qiE 'Windows (2000|2003|2008|XP|7|Server 2008)' "$out/computers.txt"; then
            local oldos; oldos=$(grep -iE 'Windows (2000|2003|2008|XP|7)' "$out/computers.txt" | head -5 | tr '\n' ' ')
            add_finding HIGH "Eski / destek disi isletim sistemleri" "$DOMAIN" "LDAP operatingSystem" \
                "Destegi bitmis Windows surumleri tespit edildi." \
                "Yamalanmayan kritik zafiyetler; lateral movement hedefi." "$oldos" \
                "EOL sistemleri yukseltin veya izole edin."
        fi
    else
        warn "Kimlik yok — kimlikli LDAP dump atlandi."
    fi
    ok "Modul 4 tamamlandi -> $out/"
    pause
}

# ============================================================================
# MODUL 5 — KERBEROS ANALIZI  (aday tespiti; parola KIRMAZ)
# ============================================================================
mod_kerberos() {
    need_dc || { pause; return; }
    section "MODUL 5 — KERBEROS ANALIZI (aday tespiti, non-destructive)"
    local ip="$DC_IP"
    local out="$BASEDIR/kerberos"
    local base=""
    [ -n "$DOMAIN" ] && base="DC=$(echo "$DOMAIN" | sed 's/\./,DC=/g')"

    # Kerberos servis kontrolu
    if have nmap; then
        log "Kerberos (88) servis kontrolu"
        nmap -Pn -p88 "$ip" 2>&1 | tee "$out/krb_port.txt" >/dev/null
    fi

    if ! has_creds; then
        warn "Kimlik yok — SPN ve AS-REP aday tespiti icin genelde kimlik gerekir."
        warn "Elinizde kullanici listesi (users.txt) varsa AS-REP adaylari icin manuel komut asagida."
        echo -e "   ${C}impacket-GetNPUsers ${DOMAIN}/ -usersfile users.txt -dc-ip $ip -no-pass -format hashcat${N}"
        pause; return
    fi

    # AS-REP roastable ADAYLAR (LDAP UAC biti — parola gerektirmeyen hesaplar)
    if have ldapsearch; then
        log "AS-REP Roasting adaylari (DONT_REQUIRE_PREAUTH) LDAP ile tespit"
        ldapsearch -x -LLL -H "ldap://$ip" -D "${USERNAME}@${DOMAIN}" -w "$PASSWORD" -b "$base" \
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName \
            2>/dev/null | grep -i sAMAccountName | awk '{print $2}' > "$out/asrep_candidates.txt"
        local n1; n1=$(wc -l < "$out/asrep_candidates.txt" 2>/dev/null)
        if [ "${n1:-0}" -gt 0 ]; then
            add_finding HIGH "AS-REP Roasting adaylari" "$DOMAIN" "LDAP userAccountControl" \
                "On kimlik dogrulamasi (pre-auth) kapali $n1 hesap bulundu." \
                "Bu hesaplarin AS-REP bileti kimlik dogrulamadan cekilip offline kirilabilir." \
                "$(tr '\n' ' ' < "$out/asrep_candidates.txt")" \
                "Bu hesaplarda 'Do not require Kerberos preauthentication' ozelligini kapatin; guclu parola atayin."
            warn "DOGRULAMA (opsiyonel, hash cekimi — kirma DEGIL):"
            echo -e "   ${C}impacket-GetNPUsers ${DOMAIN}/${USERNAME}:'***' -dc-ip $ip -request -format hashcat -outputfile $out/asrep.hash${N}"
        else
            ok "AS-REP roastable hesap bulunamadi."
        fi
    fi

    # SPN atanmis kullanicilar (Kerberoast adaylari) — LDAP ile listele, bilet ISTEMEZ
    if have ldapsearch; then
        log "Kerberoast adaylari (servicePrincipalName tanimli kullanicilar)"
        ldapsearch -x -LLL -H "ldap://$ip" -D "${USERNAME}@${DOMAIN}" -w "$PASSWORD" -b "$base" \
            "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName \
            2>/dev/null > "$out/spn_accounts.txt"
        local n2; n2=$(grep -c "sAMAccountName:" "$out/spn_accounts.txt" 2>/dev/null)
        if [ "${n2:-0}" -gt 0 ]; then
            add_finding HIGH "Kerberoast adaylari (SPN'li hesaplar)" "$DOMAIN" "LDAP servicePrincipalName" \
                "SPN atanmis $n2 kullanici hesabi bulundu." \
                "TGS biletleri cekilip offline kirilabilir; servis hesaplari genelde yuksek yetkilidir." \
                "$(grep -i sAMAccountName: "$out/spn_accounts.txt" | awk '{print $2}' | tr '\n' ' ')" \
                "Servis hesaplarina uzun/rastgele parola (gMSA) atayin; gereksiz SPN'leri kaldirin."
            warn "DOGRULAMA (opsiyonel, bilet cekimi — kirma DEGIL):"
            echo -e "   ${C}impacket-GetUserSPNs ${DOMAIN}/${USERNAME}:'***' -dc-ip $ip -request -outputfile $out/kerberoast.hash${N}"
        else
            ok "SPN'li kullanici hesabi bulunamadi."
        fi
    fi
    ok "Modul 5 tamamlandi -> $out/"
    pause
}

# ============================================================================
# MODUL 6 — KULLANICI / GRUP / POLICY
# ============================================================================
mod_users() {
    section "MODUL 6 — KULLANICI, GRUP ve PAROLA POLITIKASI"
    local ip="${DC_IP:-$TARGET}"
    local out="$BASEDIR/users"
    pick_nxc

    # rpcclient null session ile kullanici/grup
    if have rpcclient; then
        log "rpcclient ile kullanici/grup listesi"
        if has_creds; then
            RPCU="${DOMAIN:+$DOMAIN\\}$USERNAME%${PASSWORD}"
        else
            RPCU="%"
        fi
        rpcclient -U "$RPCU" "$ip" -c 'enumdomusers' 2>/dev/null > "$out/rpc_users.txt"
        rpcclient -U "$RPCU" "$ip" -c 'enumdomgroups' 2>/dev/null > "$out/rpc_groups.txt"
        rpcclient -U "$RPCU" "$ip" -c 'getdompwinfo' 2>/dev/null > "$out/rpc_pwpolicy.txt"
        local uc; uc=$(grep -c "user:" "$out/rpc_users.txt" 2>/dev/null)
        [ "${uc:-0}" -gt 0 ] && ok "Kullanici: ${W}$uc${N} -> $out/rpc_users.txt"
    fi

    # nxc ile daha zengin veri (kimlikli)
    if [ -n "$NXC" ] && has_creds; then
        log "NetExec: kullanicilar, gruplar, parola politikasi"
        $NXC smb "$ip" $(nxc_auth) --users 2>&1 | tee "$out/nxc_users.txt" >/dev/null
        $NXC smb "$ip" $(nxc_auth) --groups 2>&1 | tee "$out/nxc_groups.txt" >/dev/null
        $NXC smb "$ip" $(nxc_auth) --pass-pol 2>&1 | tee "$out/nxc_passpol.txt" >/dev/null

        # Password policy analizi
        if grep -qiE 'Minimum password length: *[0-7]\b' "$out/nxc_passpol.txt"; then
            add_finding MEDIUM "Zayif minimum parola uzunlugu" "$DOMAIN" "NetExec --pass-pol" \
                "Minimum parola uzunlugu 8 karakterin altinda." "Kaba kuvvet/spray kolaylasir." \
                "$(grep -i 'Minimum password length' "$out/nxc_passpol.txt" | head -1)" \
                "Minimum 14 karakter + karmasiklik politikasi uygulayin."
        fi
        if grep -qiE 'Account Lockout Threshold: *(None|0)\b' "$out/nxc_passpol.txt"; then
            add_finding MEDIUM "Hesap kilitleme esigi yok" "$DOMAIN" "NetExec --pass-pol" \
                "Account lockout threshold tanimli degil (0/None)." \
                "Sinirsiz parola denemesi (spraying/brute) mumkun." \
                "$(grep -i 'Lockout Threshold' "$out/nxc_passpol.txt" | head -1)" \
                "Makul bir lockout esigi (orn 5-10) ve gozlem penceresi tanimlayin."
        fi

        # Domain Admins ve yuksek yetkili gruplar
        log "Yuksek yetkili grup uyeleri"
        for grp in "Domain Admins" "Enterprise Admins" "Administrators" "Schema Admins"; do
            $NXC ldap "$ip" $(nxc_auth) --groups "$grp" 2>/dev/null >> "$out/high_priv_groups.txt"
        done

        # admincount=1 (korumali/yuksek yetkili) hesap sayisi
        if have ldapsearch; then
            local base; base="DC=$(echo "$DOMAIN" | sed 's/\./,DC=/g')"
            ldapsearch -x -LLL -H "ldap://$ip" -D "${USERNAME}@${DOMAIN}" -w "$PASSWORD" -b "$base" \
                "(&(objectClass=user)(admincount=1))" sAMAccountName 2>/dev/null > "$out/admincount.txt"
            local ac; ac=$(grep -c sAMAccountName: "$out/admincount.txt")
            [ "${ac:-0}" -gt 12 ] && add_finding MEDIUM "Cok sayida ayricalikli hesap" "$DOMAIN" "LDAP admincount=1" \
                "admincount=1 olan $ac hesap var (beklenenden fazla olabilir)." \
                "Genis yetki yuzeyi; ayricalik yayilmasi." "$ac ayricalikli hesap" \
                "Yetkileri gozden gecirin, kullanilmayan admin haklarini kaldirin."

            # Parolasi suresiz hesaplar
            ldapsearch -x -LLL -H "ldap://$ip" -D "${USERNAME}@${DOMAIN}" -w "$PASSWORD" -b "$base" \
                "(userAccountControl:1.2.840.113556.1.4.803:=65536)" sAMAccountName 2>/dev/null > "$out/pw_never_expires.txt"
            local ne; ne=$(grep -c sAMAccountName: "$out/pw_never_expires.txt")
            [ "${ne:-0}" -gt 0 ] && add_finding LOW "Parolasi suresiz hesaplar" "$DOMAIN" "LDAP UAC 0x10000" \
                "$ne hesabin parolasi hic bitmiyor." "Eski/zayif parolalarin surekli gecerli kalma riski." \
                "$(grep sAMAccountName: "$out/pw_never_expires.txt" | awk '{print $2}' | head -10 | tr '\n' ' ')" \
                "DONT_EXPIRE_PASSWORD bitini kaldirin, duzenli rotasyon uygulayin."

            # Devre disi hesaplar (bilgi)
            ldapsearch -x -LLL -H "ldap://$ip" -D "${USERNAME}@${DOMAIN}" -w "$PASSWORD" -b "$base" \
                "(userAccountControl:1.2.840.113556.1.4.803:=2)" sAMAccountName 2>/dev/null > "$out/disabled.txt"
        fi
    elif ! has_creds; then
        warn "Kimlik yok — kullanici/grup/policy detaylari sinirli (yalnizca null session denendi)."
    fi
    ok "Modul 6 tamamlandi -> $out/"
    pause
}

# ============================================================================
# MODUL 7 — AD GUVENLIK KONTROLLERI (derleme + ek kontroller)
# ============================================================================
mod_adsec() {
    section "MODUL 7 — AD GUVENLIK KONTROLLERI"
    local ip="${DC_IP:-$TARGET}"
    pick_nxc

    # WinRM erisimi
    if have nmap; then
        log "WinRM (5985/5986) kontrolu"
        nmap -Pn -p5985,5986 --open "$ip" 2>&1 | tee "$BASEDIR/scans/winrm.txt" >/dev/null
        if grep -qE '5985/tcp +open|5986/tcp +open' "$BASEDIR/scans/winrm.txt"; then
            add_finding INFO "WinRM erisilebilir" "$ip" "nmap" \
                "WinRM (5985/5986) portu acik." "Kimlik ele gecirilirse uzaktan komut yolu." "5985/5986 open" \
                "WinRM'i yalnizca gerekli yonetim ag/hesaplari ile kisitlayin."
        fi
    fi

    # MS17-010 (EternalBlue) — sadece TESPIT, exploit YOK
    if have nmap; then
        log "MS17-010 (EternalBlue) zafiyet TESPITI (exploit calistirilmaz)"
        nmap -Pn -p445 --script smb-vuln-ms17-010 "$ip" 2>&1 | tee "$BASEDIR/smb/ms17-010.txt" >/dev/null
        if grep -qi "VULNERABLE" "$BASEDIR/smb/ms17-010.txt"; then
            add_finding CRITICAL "MS17-010 (EternalBlue) potansiyel savunmasiz" "$ip" "nmap smb-vuln-ms17-010" \
                "Sistem MS17-010'a karsi savunmasiz gorunuyor (yama eksik)." \
                "Uzaktan kod calistirma (RCE) — tam sistem ele gecirme." \
                "$(grep -i state "$BASEDIR/smb/ms17-010.txt" | head -1)" \
                "MS17-010 yamasini uygulayin, SMBv1'i kapatin. DOGRULAMA (izinliyse): dedike test hostunda metasploit ms17_010 kontrol modulu."
        fi
    fi

    # zerologon on-belirti (yalnizca bilgi — otomatik exploit YOK)
    log "Not: Zerologon/PrintNightmare gibi zafiyetler otomatik DOGRULANMAZ (destructive risk)."
    add_finding INFO "Manuel dogrulama onerilen zafiyetler" "${DC_HOST:-$ip}" "policy" \
        "Zerologon (CVE-2020-1472), PrintNightmare, noPac gibi kontroller bu scriptte OTOMATIK calistirilmaz." \
        "Yanlis calistirma servis kesintisi yapabilir." "manuel" \
        "Yamalari kontrol edin; dogrulamayi yalnizca izinli, dedike test hostunda ilgili aracin 'check' moduyla yapin."

    ok "Modul 7 tamamlandi. Onceki modullerin bulgulari findings.db'de birikti."
    pause
}

# ============================================================================
# MODUL 8 — BLOODHOUND VERI TOPLAMA (opsiyonel, kimlik gerekli)
# ============================================================================
mod_bloodhound() {
    section "MODUL 8 — BLOODHOUND VERI TOPLAMA (opsiyonel)"
    if ! has_creds; then err "BloodHound icin yetkili kimlik gerekli (menu > T)."; pause; return; fi
    need_dc || { pause; return; }
    if ! have bloodhound-python; then
        err "bloodhound-python bulunamadi.  Kur: pipx install bloodhound"
        pause; return
    fi
    read -rp "BloodHound toplama baslatilsin mi? (Kimlikli, LDAP okuma) [e/H]: " yn
    [[ "$yn" =~ ^[eEyY]$ ]] || { warn "Iptal edildi."; pause; return; }

    local out="$BASEDIR/bloodhound"
    log "bloodhound-python -c All calistiriliyor..."
    ( cd "$out" && bloodhound-python -u "$USERNAME" -p "${PASSWORD:-}" \
        ${NTHASH:+--hashes ":$NTHASH"} -d "$DOMAIN" -ns "$DC_IP" -c All --zip 2>&1 ) \
        | tee "$out/collect.log"
    if ls "$out"/*.zip >/dev/null 2>&1; then
        ok "BloodHound verisi toplandi -> $out/*.zip"
        add_finding INFO "BloodHound verisi toplandi" "$DOMAIN" "bloodhound-python" \
            "AD iliski grafigi verisi (.zip) uretildi." "Analiz icin." "$(ls "$out"/*.zip)" \
            "BloodHound CE'ye yukleyip 'Shortest Path to Domain Admins' analizini calistirin."
    else
        err "Toplama basarisiz — collect.log inceleyin."
    fi
    pause
}

# ============================================================================
# MODUL 10 — RAPOR OLUSTUR (Markdown + HTML)
# ============================================================================
gen_report() {
    section "RAPOR OLUSTURULUYOR"
    local md="$BASEDIR/report/RAPOR.md"
    local html="$BASEDIR/report/RAPOR.html"
    [ -s "$FINDINGS" ] || { warn "Henuz bulgu yok. Once bir modul calistirin."; pause; return; }

    # Ozet sayimlar
    local c h m l i
    c=$(grep -c '^CRITICAL|' "$FINDINGS"); h=$(grep -c '^HIGH|' "$FINDINGS")
    m=$(grep -c '^MEDIUM|' "$FINDINGS"); l=$(grep -c '^LOW|' "$FINDINGS"); i=$(grep -c '^INFO|' "$FINDINGS")

    # ---- Markdown ----
    {
      echo "# Active Directory Guvenlik Degerlendirme Raporu"
      echo
      echo "- **Tarih:** $(date '+%Y-%m-%d %H:%M')"
      echo "- **Domain:** ${DOMAIN:-N/A}"
      echo "- **Domain Controller:** ${DC_HOST:-?} (${DC_IP:-N/A})"
      echo "- **Hedef/Subnet:** ${TARGET:-N/A} / ${SUBNET:-N/A}"
      echo "- **Mod:** Non-destructive / Enumeration"
      echo
      echo "## Ozet"
      echo
      echo "| Onem | Adet |"
      echo "|------|------|"
      echo "| CRITICAL | $c |"
      echo "| HIGH | $h |"
      echo "| MEDIUM | $m |"
      echo "| LOW | $l |"
      echo "| INFO | $i |"
      echo
      echo "## Bulgular"
      for sev in CRITICAL HIGH MEDIUM LOW INFO; do
        grep "^$sev|" "$FINDINGS" | while IFS='|' read -r s name aff meth desc risk ev rem; do
          echo
          echo "### [$s] $name"
          echo "- **Etkilenen:** $aff"
          echo "- **Tespit yontemi:** $meth"
          echo "- **Teknik aciklama:** $desc"
          echo "- **Guvenlik riski:** $risk"
          echo "- **Kanit:** \`$ev\`"
          echo "- **Onerilen duzeltme:** $rem"
        done
      done
    } > "$md"

    # ---- HTML ----
    {
      cat <<HTMLHEAD
<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AD Guvenlik Raporu — ${DOMAIN}</title>
<style>
body{background:#0d1117;color:#e6edf3;font-family:Segoe UI,Arial,sans-serif;line-height:1.6;max-width:1100px;margin:0 auto;padding:24px}
h1{color:#58a6ff}h2{border-bottom:1px solid #2b3648;padding-bottom:6px;margin-top:32px}
.meta{background:#161b22;border:1px solid #2b3648;border-radius:8px;padding:14px 18px}
table{border-collapse:collapse;width:100%;margin:14px 0}th,td{border:1px solid #2b3648;padding:8px 12px;text-align:left}
th{background:#1c2530}
.card{background:#161b22;border:1px solid #2b3648;border-radius:8px;padding:16px 18px;margin:14px 0;border-left:5px solid #8b98a9}
.CRITICAL{border-left-color:#f85149}.HIGH{border-left-color:#ff7b72}.MEDIUM{border-left-color:#f0883e}.LOW{border-left-color:#e3b341}.INFO{border-left-color:#58a6ff}
.badge{display:inline-block;padding:2px 10px;border-radius:14px;font-size:.75rem;font-weight:700;color:#04101f}
.b-CRITICAL{background:#f85149}.b-HIGH{background:#ff7b72}.b-MEDIUM{background:#f0883e}.b-LOW{background:#e3b341}.b-INFO{background:#58a6ff}
code{background:#0a0e14;padding:2px 6px;border-radius:4px;color:#a5d6ff;font-size:.85rem}
.kv{color:#8b98a9}
</style></head><body>
<h1>Active Directory Guvenlik Degerlendirme Raporu</h1>
<div class="meta">
<b>Tarih:</b> $(date '+%Y-%m-%d %H:%M') &nbsp;|&nbsp;
<b>Domain:</b> ${DOMAIN:-N/A} &nbsp;|&nbsp;
<b>DC:</b> ${DC_HOST:-?} (${DC_IP:-N/A}) &nbsp;|&nbsp;
<b>Hedef:</b> ${TARGET:-N/A} / ${SUBNET:-N/A} &nbsp;|&nbsp;
<b>Mod:</b> Non-destructive
</div>
<h2>Ozet</h2>
<table><tr><th>Onem</th><th>Adet</th></tr>
<tr><td><span class="badge b-CRITICAL">CRITICAL</span></td><td>$c</td></tr>
<tr><td><span class="badge b-HIGH">HIGH</span></td><td>$h</td></tr>
<tr><td><span class="badge b-MEDIUM">MEDIUM</span></td><td>$m</td></tr>
<tr><td><span class="badge b-LOW">LOW</span></td><td>$l</td></tr>
<tr><td><span class="badge b-INFO">INFO</span></td><td>$i</td></tr></table>
<h2>Bulgular</h2>
HTMLHEAD

      for sev in CRITICAL HIGH MEDIUM LOW INFO; do
        grep "^$sev|" "$FINDINGS" | while IFS='|' read -r s name aff meth desc risk ev rem; do
          # HTML ozel karakter kacisi (basit)
          esc(){ echo "$1" | sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g'; }
          echo "<div class=\"card $s\">"
          echo "<span class=\"badge b-$s\">$s</span> <b>$(esc "$name")</b>"
          echo "<p><span class=\"kv\">Etkilenen:</span> $(esc "$aff")<br>"
          echo "<span class=\"kv\">Tespit yontemi:</span> $(esc "$meth")<br>"
          echo "<span class=\"kv\">Teknik aciklama:</span> $(esc "$desc")<br>"
          echo "<span class=\"kv\">Guvenlik riski:</span> $(esc "$risk")<br>"
          echo "<span class=\"kv\">Kanit:</span> <code>$(esc "$ev")</code><br>"
          echo "<span class=\"kv\">Onerilen duzeltme:</span> $(esc "$rem")</p></div>"
        done
      done
      echo "<p style=\"color:#8b98a9;margin-top:30px\">Bu rapor yalnizca yetkili test ortami icin uretilmistir. Non-destructive mod.</p>"
      echo "</body></html>"
    } > "$html"

    ok "Rapor olusturuldu:"
    echo -e "   ${W}$md${N}"
    echo -e "   ${W}$html${N}"
    echo -e "   Ozet: ${R}CRITICAL:$c${N} ${R}HIGH:$h${N} ${Y}MEDIUM:$m${N} ${Y}LOW:$l${N} ${C}INFO:$i${N}"
    pause
}

# ============================================================================
# MODUL 9 — TUM GUVENLI KONTROLLER
# ============================================================================
run_all_safe() {
    section "TUM GUVENLI KONTROLLER CALISTIRILIYOR"
    mod_network
    mod_dc_detect
    mod_smb
    mod_ldap
    mod_kerberos
    mod_users
    mod_adsec
    gen_report
    ok "Tum guvenli kontroller tamamlandi."
}

# ============================================================================
# MENU
# ============================================================================
show_menu() {
    clear; banner
    echo -e "  Hedef: ${W}${TARGET:-?}${N} | Domain: ${W}${DOMAIN:-?}${N} | DC: ${W}${DC_IP:-?}${N} | Kimlik: $(has_creds && echo "${G}var${N}" || echo "${Y}yok${N}")"
    echo -e "  Cikti: ${W}${BASEDIR}/${N}"
    echo "  ---------------------------------------------------"
    echo -e "  ${C}[1]${N} Ag Kesfi"
    echo -e "  ${C}[2]${N} Domain Controller Tespiti"
    echo -e "  ${C}[3]${N} SMB Analizi"
    echo -e "  ${C}[4]${N} LDAP Analizi"
    echo -e "  ${C}[5]${N} Kerberos Analizi (aday tespiti)"
    echo -e "  ${C}[6]${N} Kullanici / Grup / Policy Analizi"
    echo -e "  ${C}[7]${N} AD Guvenlik Kontrolleri"
    echo -e "  ${C}[8]${N} BloodHound Veri Toplama (opsiyonel)"
    echo -e "  ${C}[9]${N} TUM Guvenli Kontrolleri Calistir"
    echo -e "  ${C}[10]${N} Rapor Olustur"
    echo "  ---------------------------------------------------"
    echo -e "  ${C}[T]${N} Hedef / Kimlik Bilgilerini Gir"
    echo -e "  ${C}[C]${N} Arac Kontrolu"
    echo -e "  ${C}[Q]${N} Cikis"
    echo
    read -rp "  Secim: " choice
    case "$choice" in
        1) mod_network ;;
        2) mod_dc_detect ;;
        3) mod_smb ;;
        4) mod_ldap ;;
        5) mod_kerberos ;;
        6) mod_users ;;
        7) mod_adsec ;;
        8) mod_bloodhound ;;
        9) run_all_safe ;;
        10) gen_report ;;
        T|t) set_target ;;
        C|c) check_tools ;;
        Q|q) echo -e "\n${G}Cikiliyor. Ciktilar: $BASEDIR/${N}\n"; exit 0 ;;
        *) warn "Gecersiz secim." ; sleep 1 ;;
    esac
}

usage() {
cat <<EOF
ad-recon.sh — Active Directory kesif & guvenlik degerlendirme (non-destructive)

KULLANIM:
  ./ad-recon.sh              Interaktif menu
  ./ad-recon.sh --help       Bu yardim

Once 'T' ile hedef/kimlik girin, sonra modulleri secin.
Kimlik verilmezse anonymous/unauthenticated testlerle devam eder.
YALNIZCA yetkili oldugunuz ortamlarda kullanin.
EOF
}

# ----------------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------------
main() {
    [[ "$1" == "--help" || "$1" == "-h" ]] && { usage; exit 0; }
    banner
    init_dirs
    pick_nxc
    echo -e "${Y}Yasal uyari:${N} Bu araci yalnizca YAZILI IZIN aldiginiz sistemlerde kullanin."
    read -rp "Yetkili oldugunuzu onayliyor musunuz? [e/H]: " ok_yn
    [[ "$ok_yn" =~ ^[eEyY]$ ]] || { err "Onay verilmedi. Cikiliyor."; exit 1; }
    check_tools
    while true; do show_menu; done
}

main "$@"
