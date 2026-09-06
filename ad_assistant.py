#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ad_assistant.py  —  Active Directory Pentest Assistant / Command Center
========================================================================
Bulguya gore ilerleyen (decision-engine) bir AD kesif & yanlis-yapilandirma
analiz asistani.  ARAC DEGIL MANTIK merkezdedir:

    KESFET -> YORUMLA -> KARAR VER -> SONRAKI TESTI SEC -> DOGRULA -> RAPORLA

Varsayilan mod: NON-DESTRUCTIVE (enumeration).  Exploit / password-spray /
kalicilik YOK.  Potansiyel saldiri yollari yalnizca ISARETLENIR ve pasif
dogrulama komutu onerilir; otomatik istismar edilmez.

YALNIZCA yazili izin aldiginiz kendi laboratuvar / pentest ortamlariniz icin.

Kullanim:
    python3 ad_assistant.py --target 192.168.1.0/24
    python3 ad_assistant.py --target 192.168.1.10 --domain example.local \
            --username claire --password 'Password123!'
    python3 ad_assistant.py --resume ad-assessment_20260906_1200
    python3 ad_assistant.py --target 10.0.0.0/24 --auto      # onaysiz (yine non-destructive)
"""

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Callable, Dict, List, Optional

# --------------------------------------------------------------------------
# Renkler
# --------------------------------------------------------------------------
class C:
    R = "\033[1;31m"; G = "\033[1;32m"; Y = "\033[1;33m"; B = "\033[1;34m"
    CY = "\033[1;36m"; W = "\033[1;37m"; GREY = "\033[0;90m"; N = "\033[0m"

def c(txt, col): return f"{col}{txt}{C.N}"

# --------------------------------------------------------------------------
# Cikti isaretleri  (kullanicinin ornegindeki stil)
# --------------------------------------------------------------------------
def p_info(msg):  print(f"{C.CY}[+]{C.N} {msg}")
def p_act(msg):   print(f"{C.B}[>]{C.N} {msg}")
def p_warn(msg):  print(f"{C.Y}[!]{C.N} {msg}")
def p_err(msg):   print(f"{C.R}[-]{C.N} {msg}")
def p_good(msg):  print(f"{C.G}[+]{C.N} {msg}")

def phase_banner(num, title):
    print()
    print(c("=" * 66, C.B))
    print(c(f"  PHASE {num} — {title}", C.W))
    print(c("=" * 66, C.B))

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_COL = {"CRITICAL": C.R, "HIGH": C.R, "MEDIUM": C.Y, "LOW": C.Y, "INFO": C.CY}

# ==========================================================================
# VERI MODELLERI
# ==========================================================================
@dataclass
class Finding:
    id: str
    title: str
    severity: str
    host: str
    service: str
    evidence: str
    technical: str
    impact: str
    validation: str
    remediation: str

@dataclass
class Context:
    """Calisma boyunca tasinan / diske kaydedilen durum."""
    target: str = ""
    subnet: str = ""
    domain: str = ""
    dc_ip: str = ""
    dc_host: str = ""
    username: str = ""
    password: str = ""
    nthash: str = ""
    iface: str = "eth0"
    assessment_dir: str = ""

    live_hosts: List[str] = field(default_factory=list)
    host_ports: Dict[str, List[int]] = field(default_factory=dict)   # ip -> [portlar]
    dc_candidates: List[str] = field(default_factory=list)

    flags: Dict[str, bool] = field(default_factory=dict)
    done: List[str] = field(default_factory=list)       # tamamlanan adim anahtarlari
    findings: List[dict] = field(default_factory=list)
    completed_phases: List[int] = field(default_factory=list)

    def flag(self, key, default=False):
        return self.flags.get(key, default)

    def set_flag(self, key, val=True):
        self.flags[key] = val

    def has_creds(self):
        return bool(self.username) and (bool(self.password) or bool(self.nthash))

    # ---- persistence ----
    def save(self):
        path = os.path.join(self.assessment_dir, "state.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, indent=2, ensure_ascii=False)

    @staticmethod
    def load(assessment_dir):
        path = os.path.join(assessment_dir, "state.json")
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        ctx = Context(**data)
        return ctx

# ==========================================================================
# GLOBAL AYARLAR (calisma modu)
# ==========================================================================
class Mode:
    auto = False       # True: her adimi onaysiz calistir (yine non-destructive)
    assume_yes = False # True: onaylari otomatik evet
    dry = False        # True: komutlari yalnizca goster, calistirma

# ==========================================================================
# ARAC KONTROLU
# ==========================================================================
TOOLS = {
    "nmap": "sudo apt install -y nmap",
    "ldapsearch": "sudo apt install -y ldap-utils",
    "smbclient": "sudo apt install -y smbclient",
    "rpcclient": "sudo apt install -y samba-common-bin",
    "dig": "sudo apt install -y dnsutils",
    "nxc": "pipx install netexec",
    "enum4linux-ng": "sudo apt install -y enum4linux-ng",
    "impacket-GetUserSPNs": "pipx install impacket",
    "impacket-GetNPUsers": "pipx install impacket",
    "bloodhound-python": "pipx install bloodhound",
    "certipy": "pipx install certipy-ad",
    "nbtscan": "sudo apt install -y nbtscan",
}

def have(tool):
    return shutil.which(tool) is not None

def nxc_bin():
    if have("nxc"):
        return "nxc"
    if have("crackmapexec"):
        return "crackmapexec"
    return None

def tool_check():
    print()
    p_act("Arac kontrolu yapiliyor...")
    missing = []
    for t, inst in TOOLS.items():
        if have(t):
            print(f"    {c('OK', C.G)}  {t}")
        else:
            print(f"    {c('--', C.Y)}  {t}   {c('(kur: ' + inst + ')', C.GREY)}")
            missing.append(t)
    if not nxc_bin():
        p_warn("NetExec/CrackMapExec yok — SMB/LDAP guvenlik kontrollerinin bir kismi atlanacak.")
    return missing

# ==========================================================================
# KOMUT CALISTIRICI  (loglar + evidence saklar)
# ==========================================================================
class Runner:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.cmd_log = os.path.join(ctx.assessment_dir, "commands", "commands.sh")
        self.run_log = os.path.join(ctx.assessment_dir, "logs", "run.log")

    def _log_cmd(self, cmd):
        with open(self.cmd_log, "a", encoding="utf-8") as f:
            f.write(f"# {datetime.now():%Y-%m-%d %H:%M:%S}\n{cmd}\n\n")

    def _log_run(self, line):
        with open(self.run_log, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now():%H:%M:%S} {line}\n")

    def run(self, cmd: str, evidence_name: str, timeout: int = 300) -> str:
        """Komutu calistir, ciktiyi evidence/ altina kaydet, string dondur."""
        self._log_cmd(cmd)
        self._log_run(f"RUN: {cmd}")
        if Mode.dry:
            p_warn("--dry: komut calistirilmadi.")
            return ""
        print(c(f"    $ {cmd}", C.GREY))
        try:
            proc = subprocess.run(cmd, shell=True, capture_output=True,
                                  text=True, timeout=timeout)
            out = (proc.stdout or "") + (proc.stderr or "")
        except subprocess.TimeoutExpired:
            out = "[TIMEOUT] komut zaman asimina ugradi."
            p_err("Komut zaman asimina ugradi.")
        except Exception as e:
            out = f"[ERROR] {e}"
            p_err(f"Komut hatasi: {e}")
        # evidence kaydet
        ev_path = os.path.join(self.ctx.assessment_dir, "evidence", evidence_name)
        os.makedirs(os.path.dirname(ev_path), exist_ok=True)
        with open(ev_path, "w", encoding="utf-8") as f:
            f.write(f"# CMD: {cmd}\n# TIME: {datetime.now()}\n\n{out}")
        return out

# ==========================================================================
# FINDING YONETIMI
# ==========================================================================
class Findings:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self._counter = len(ctx.findings)

    def add(self, severity, title, host, service, evidence, technical,
            impact, validation, remediation):
        self._counter += 1
        fid = f"F-{self._counter:03d}"
        f = Finding(fid, title, severity, host, service, evidence[:600],
                    technical, impact, validation, remediation)
        self.ctx.findings.append(asdict(f))
        col = SEV_COL.get(severity, C.CY)
        print(f"\n    {c('BULGU', C.W)}  {c('[' + severity + ']', col)} {c(title, C.W)}  ({fid})")
        print(f"      {c('Host/Servis :', C.GREY)} {host} / {service}")
        print(f"      {c('Teknik      :', C.GREY)} {technical}")
        print(f"      {c('Risk        :', C.GREY)} {impact}")
        print(f"      {c('Kanit       :', C.GREY)} {evidence[:160]}")
        if severity in ("CRITICAL", "HIGH"):
            print(f"      {c('[!] POTANSIYEL SALDIRI YOLU / ZAFIYET — otomatik istismar EDILMEDI', C.R)}")
            print(f"      {c('Dogrulama   :', C.GREY)} {validation}")
        return f

# ==========================================================================
# ADIM MOTORU  —  her testin onunde Ne/Neden/Ne ogreniyoruz
# ==========================================================================
def run_step(ctx: Context, runner: Runner, key: str,
             what: str, why: str, learn: str,
             cmd: str, evidence_name: str,
             interpret: Callable[[str], None],
             tool: Optional[str] = None,
             timeout: int = 300):
    """
    Bir mantiksal test adimi.
    - Daha once calistiysa (key in ctx.done) tekrar calistirmaz.
    - Gerekli arac yoksa atlar.
    - Manuel modda onay ister.
    """
    if key in ctx.done:
        p_info(f"[atlandi — daha once yapildi] {what}")
        return None
    if tool and not have(tool) and not (tool == "nxc" and nxc_bin()):
        p_warn(f"[atlandi — arac yok: {tool}] {what}")
        return None

    print()
    p_act(c(what, C.W))
    print(f"    {c('Neden        :', C.GREY)} {why}")
    print(f"    {c('Ne ogreniyoruz:', C.GREY)} {learn}")

    if not Mode.auto and not Mode.assume_yes:
        ans = input(f"    {c('Bu adim calistirilsin mi? [E/a/g(oster)] ', C.Y)}").strip().lower()
        if ans == "a":
            p_warn("Adim atlandi (kullanici).")
            return None
        if ans == "g":
            print(c(f"    KOMUT: {cmd}", C.GREY))
            ans2 = input(f"    {c('Simdi calistirilsin mi? [E/a] ', C.Y)}").strip().lower()
            if ans2 == "a":
                return None

    out = runner.run(cmd, evidence_name, timeout=timeout)
    ctx.done.append(key)
    try:
        interpret(out)
    except Exception as e:
        p_err(f"Yorumlama hatasi: {e}")
    ctx.save()
    return out

def next_step_hint(text):
    print(f"\n    {c('[>] Sonraki mantikli adim:', C.B)} {text}")

# ==========================================================================
# YARDIMCILAR  (auth argumanlari, base dn)
# ==========================================================================
def base_dn(domain):
    if not domain:
        return ""
    return "DC=" + domain.replace(".", ",DC=")

def nxc_auth_args(ctx: Context, anon=False):
    if anon or not ctx.has_creds():
        return "-u '' -p ''"
    if ctx.password:
        return f"-u {shlex.quote(ctx.username)} -p {shlex.quote(ctx.password)}"
    return f"-u {shlex.quote(ctx.username)} -H {shlex.quote(ctx.nthash)}"

def ldap_bind_args(ctx: Context):
    """ldapsearch icin -D/-w (kimlikli) ya da -x (anonim)."""
    if ctx.has_creds() and ctx.password:
        return f"-D {shlex.quote(ctx.username + '@' + ctx.domain)} -w {shlex.quote(ctx.password)}"
    return ""   # anonim

# ==========================================================================
# PHASE 1 — NETWORK DISCOVERY
# ==========================================================================
AD_PORTS = "53,88,135,139,389,445,464,636,3268,3269,5985,5986"

def phase1_network(ctx, runner, findings):
    phase_banner(1, "NETWORK DISCOVERY")
    scope = ctx.subnet or ctx.target
    if not scope:
        p_err("Hedef yok."); return
    single = "/" not in scope

    if not single:
        def interp_sweep(out):
            hosts = re.findall(r"Nmap scan report for (?:\S+ \()?(\d+\.\d+\.\d+\.\d+)", out)
            ctx.live_hosts = sorted(set(hosts))
            p_good(f"{len(ctx.live_hosts)} canli host bulundu: {', '.join(ctx.live_hosts) or '-'}")
            print(f"    {c('Yorum:', C.GREY)} Her canli host DC degildir; servis parmak izine bakarak ayiracagiz.")
            next_step_hint("Canli hostlarda AD servis portlarini tara.")
        run_step(ctx, runner, "p1_sweep",
                 "Ag genelinde canli host kesfi",
                 "Once hangi sistemlerin ayakta oldugunu bilmeden hedef secemeyiz.",
                 " Agdaki canli IP'lerin listesi.",
                 f"nmap -sn -n {shlex.quote(scope)}",
                 "discovery/host_sweep.txt", interp_sweep, tool="nmap")
    else:
        ctx.live_hosts = [scope]
        p_info(f"Tek hedef modu: {scope}")

    # Her host icin AD port taramasi
    def interp_ports(out):
        # nmap ciktisindan ip -> acik portlar
        cur_ip = None
        for line in out.splitlines():
            m = re.search(r"Nmap scan report for (?:\S+ \()?(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                cur_ip = m.group(1); ctx.host_ports.setdefault(cur_ip, [])
            pm = re.match(r"(\d+)/tcp\s+open", line.strip())
            if pm and cur_ip:
                ctx.host_ports[cur_ip].append(int(pm.group(1)))
        # DC adaylari: 88 + 389 + 445
        ctx.dc_candidates = []
        for ip, ports in ctx.host_ports.items():
            pset = set(ports)
            if {88, 389, 445}.issubset(pset):
                ctx.dc_candidates.append(ip)
                p_good(f"{ip} -> acik portlar: {sorted(pset)}")
                p_info(f"Bu servis kombinasyonu (Kerberos+LDAP+SMB) {ip} sisteminin Domain Controller olabilecegini gosteriyor.")
                findings.add("INFO", "Domain Controller adayi", ip, "AD servisleri",
                             f"open: {sorted(pset)}",
                             "88/389/445 birlikte acik — tipik DC parmak izi.",
                             "Bilgi toplama yuzeyi.",
                             "smb-os-discovery + LDAP rootDSE ile dogrulanacak.",
                             "Gereksiz servisleri kapatin, yonetim yuzeyini kisitlayin.")
            elif pset:
                p_info(f"{ip} -> acik portlar: {sorted(pset)} (DC parmak izi yok; uye/uygulama sunucusu olabilir)")
        if ctx.dc_candidates:
            next_step_hint("PHASE 2 — DC adaylarini smb-os-discovery + LDAP ile dogrula.")
        else:
            p_warn("DC adayi bulunamadi. Domain ortami olmayabilir ya da portlar filtreli.")
    run_step(ctx, runner, "p1_ports",
             "AD servis portu taramasi",
             "AD ortamini tanimlayan portlari (DNS/Kerberos/LDAP/SMB/GC/WinRM) gorerek rol cikaracagiz.",
             "Her hostta hangi AD servisleri calisiyor?",
             f"nmap -Pn -p {AD_PORTS} --open -T4 {shlex.quote(scope)}",
             "discovery/ad_ports.txt", interp_ports, tool="nmap")

    ctx.completed_phases.append(1); ctx.save()

# ==========================================================================
# PHASE 2 — AD / DC IDENTIFICATION
# ==========================================================================
def phase2_dc(ctx, runner, findings):
    phase_banner(2, "AD / DC IDENTIFICATION")
    cand = ctx.dc_candidates or ([ctx.dc_ip] if ctx.dc_ip else ctx.live_hosts)
    if not cand:
        p_warn("DC adayi yok — bu faz atlaniyor."); return
    ip = ctx.dc_ip if ctx.dc_ip in cand else cand[0]
    ctx.dc_ip = ip
    p_act(f"Domain Controller dogrulamasi yapiliyor: {ip}")

    def interp_os(out):
        d = re.search(r"Domain name:\s*(\S+)", out)
        h = re.search(r"NetBIOS computer name:\s*([^\s\\]+)", out)
        fq = re.search(r"FQDN:\s*(\S+)", out)
        if d:
            ctx.domain = ctx.domain or d.group(1).strip(".")
            ctx.set_flag("DOMAIN_FOUND"); p_good(f"Domain: {ctx.domain}")
        if h:
            ctx.dc_host = ctx.dc_host or h.group(1)
            p_good(f"DC hostname: {ctx.dc_host}")
        if fq:
            p_good(f"FQDN: {fq.group(1)}")
        if d or h:
            ctx.set_flag("DC_FOUND")
    run_step(ctx, runner, "p2_smbos",
             "SMB uzerinden OS/domain parmak izi",
             "SMB, kimlik dogrulamadan bile domain ve hostname bilgisini sizdirir.",
             "Domain adi, DC hostname ve FQDN.",
             f"nmap -Pn -p445 --script smb-os-discovery {shlex.quote(ip)}",
             "discovery/smb_os_discovery.txt", interp_os, tool="nmap")

    def interp_root(out):
        nc = re.search(r"defaultNamingContext:\s*(\S+)", out)
        if nc:
            p_good(f"defaultNamingContext: {nc.group(1)}")
            if not ctx.domain:
                ctx.domain = nc.group(1).replace("DC=", "").replace(",", ".")
                ctx.set_flag("DOMAIN_FOUND")
        else:
            p_warn("rootDSE'den naming context alinamadi.")
    run_step(ctx, runner, "p2_rootdse",
             "LDAP rootDSE (anonim) dogrulamasi",
             "LDAP rootDSE ile domain yapisini ikinci bir kaynaktan teyit ederiz.",
             "defaultNamingContext / DNS host / server adi.",
             f"ldapsearch -x -H ldap://{ip} -s base -b '' defaultNamingContext dnsHostName serverName",
             "discovery/rootdse.txt", interp_root, tool="ldapsearch")

    # DNS SRV dogrulama
    if ctx.domain and have("dig"):
        def interp_srv(out):
            if out.strip():
                p_good("DNS SRV kaydi DC'yi dogruluyor.")
            else:
                p_info("SRV yaniti bos (DNS bu sunucuda AD-entegre olmayabilir).")
        run_step(ctx, runner, "p2_srv",
                 "DNS SRV kaydi ile DC dogrulama",
                 "AD, DC'leri _ldap._tcp.dc._msdcs altinda yayinlar; bu kaydin varligi DC'yi teyit eder.",
                 "DC'nin DNS'te ilan edilip edilmedigi.",
                 f"dig @{ip} _ldap._tcp.dc._msdcs.{ctx.domain} SRV +short",
                 "dns/srv.txt", interp_srv, tool="dig")

    # Port haritasindan servis bayraklari
    ports = set(ctx.host_ports.get(ip, []))
    ctx.set_flag("SMB_AVAILABLE", 445 in ports or bool(ports))
    ctx.set_flag("LDAP_AVAILABLE", 389 in ports or 636 in ports)
    ctx.set_flag("KERBEROS_AVAILABLE", 88 in ports)
    ctx.set_flag("WINRM_AVAILABLE", 5985 in ports or 5986 in ports)
    ctx.set_flag("GC_AVAILABLE", 3268 in ports or 3269 in ports)

    print()
    p_info("Context guncellendi:")
    for k in ("DOMAIN_FOUND","DC_FOUND","SMB_AVAILABLE","LDAP_AVAILABLE","KERBEROS_AVAILABLE","WINRM_AVAILABLE"):
        print(f"      {k} = {ctx.flag(k)}")
    hints = []
    if ctx.flag("SMB_AVAILABLE"): hints.append("SMB guvenlik analizi")
    if ctx.flag("LDAP_AVAILABLE"): hints.append("LDAP enumeration")
    if ctx.flag("KERBEROS_AVAILABLE"): hints.append("Kerberos aday kontrolleri")
    next_step_hint("PHASE 3/4 — " + ", ".join(hints) if hints else "servis bulunamadi.")
    ctx.completed_phases.append(2); ctx.save()

# ==========================================================================
# PHASE 3 — UNAUTHENTICATED ENUMERATION
# ==========================================================================
def phase3_unauth(ctx, runner, findings):
    phase_banner(3, "UNAUTHENTICATED ENUMERATION")
    ip = ctx.dc_ip or ctx.target
    nxc = nxc_bin()

    # --- SMB null session ---
    if ctx.flag("SMB_AVAILABLE", True):
        def interp_anon(out):
            if re.search(r"\[\+\]", out):
                ctx.set_flag("ANON_SMB", True)
                p_good("Anonymous (null session) SMB erisimi KABUL edildi.")
                findings.add("MEDIUM", "Anonymous SMB (null session)", ip, "SMB",
                             "null session basarili",
                             "Kimliksiz SMB oturumu kuruldu.",
                             "Kullanici/paylasim/policy bilgisi kimlik dogrulamadan sizabilir.",
                             "rpcclient -U '' -N ile enumdomusers denenerek dogrulanir.",
                             "RestrictNullSessAccess=1; anonim erisimi kapatin.")
                next_step_hint("Anonymous acik — rpcclient/enum4linux ile kullanici/policy enumeration'i genislet.")
            else:
                p_info("Anonymous SMB reddedildi (iyi). Unauth SMB enumeration sinirli.")
                next_step_hint("Kimlik yoksa authenticated testler PHASE 5'e ertelenir.")
        run_step(ctx, runner, "p3_smb_anon",
                 "Anonymous SMB (null session) testi",
                 "Null session acikse tum kullanici/paylasim yapisi kimliksiz okunabilir — kritik bilgi sizintisi.",
                 "Kimliksiz SMB oturumu kuruluyor mu?",
                 f"{nxc} smb {ip} -u '' -p ''" if nxc else f"smbclient -L //{ip} -N",
                 "smb/anon.txt", interp_anon, tool="nxc" if nxc else "smbclient")

        # guest
        if nxc:
            def interp_guest(out):
                if re.search(r"\[\+\]", out) and "guest" in out.lower():
                    findings.add("LOW", "Guest hesabi etkin", ip, "SMB", "guest login ok",
                                 "Guest hesabiyla SMB oturumu kuruldu.",
                                 "Sinirli da olsa kimliksiz erisim yuzeyi.",
                                 "nxc smb <ip> -u guest -p '' --shares",
                                 "Guest hesabini devre disi birakin.")
                else:
                    p_info("Guest erisimi yok (iyi).")
            run_step(ctx, runner, "p3_smb_guest",
                     "Guest hesabi SMB testi",
                     "Guest etkinse anonimden biraz daha fazla veri alinabilir.",
                     "Guest ile oturum kuruluyor mu?",
                     f"{nxc} smb {ip} -u 'guest' -p ''",
                     "smb/guest.txt", interp_guest, tool="nxc")

        # rpcclient null enumdomusers (yalnizca ANON_SMB ise mantikli)
        if ctx.flag("ANON_SMB") and have("rpcclient"):
            def interp_rpc(out):
                users = re.findall(r"user:\[([^\]]+)\]", out)
                if users:
                    p_good(f"Null session ile {len(users)} kullanici okundu: {', '.join(users[:10])}...")
                    findings.add("HIGH", "Null session ile kullanici numaralandirma", ip, "RPC/SMB",
                                 f"{len(users)} kullanici (orn: {', '.join(users[:5])})",
                                 "rpcclient enumdomusers kimliksiz calisti.",
                                 "Saldirgan tum kullanici listesini alarak spray/roast hedefleri belirler.",
                                 "rpcclient -U '' -N <ip> -c enumdomusers",
                                 "Anonim RPC erisimini kisitlayin.")
                    with open(os.path.join(ctx.assessment_dir, "users", "anon_users.txt"), "w") as f:
                        f.write("\n".join(users))
                else:
                    p_info("Null session kullanici listesi vermedi.")
            run_step(ctx, runner, "p3_rpc_users",
                     "RPC null session kullanici listesi",
                     "ANON_SMB acik oldugu icin kullanicilarin kimliksiz cekilip cekilemedigini test ediyoruz.",
                     "Kimliksiz domain kullanici listesi alinabiliyor mu?",
                     f"rpcclient -U '' -N {ip} -c enumdomusers",
                     "rpc/anon_enumdomusers.txt", interp_rpc, tool="rpcclient")

    # --- LDAP anonymous bind ---
    if ctx.flag("LDAP_AVAILABLE", True) and have("ldapsearch"):
        bdn = base_dn(ctx.domain)
        def interp_ldap_anon(out):
            n = len(re.findall(r"sAMAccountName:", out))
            if n > 0:
                ctx.set_flag("ANON_LDAP", True)
                p_good(f"Anonymous LDAP bind ile {n} kullanici okundu.")
                findings.add("HIGH", "Anonymous LDAP bind ile veri okuma", ip, "LDAP",
                             f"{n} kullanici anonim okundu",
                             "Kimlik dogrulamadan LDAP dizininden obje okunabiliyor.",
                             "Tum domain kullanici/grup/ACL yapisi ifsa olur.",
                             "ldapsearch -x -H ldap://<ip> -b <base> '(objectClass=user)'",
                             "Anonymous bind'i kapatin (dsHeuristics 7. karakter != 2).")
                next_step_hint("Anonim LDAP acik — kullanici/grup/bilgisayar cikarimini genislet.")
            else:
                p_info("Anonymous LDAP veri okuma BASARISIZ (iyi).")
                next_step_hint("Unauth LDAP burada durur; authenticated enumeration icin kimlik gerekli (PHASE 5).")
        run_step(ctx, runner, "p3_ldap_anon",
                 "Anonymous LDAP bind testi",
                 "Anonim bind veri okuyabiliyorsa bu dogrudan HIGH bir bilgi sizintisidir.",
                 "Kimliksiz LDAP ile kullanici objesi okunabiliyor mu?",
                 f"ldapsearch -x -H ldap://{ip} -b {shlex.quote(bdn)} '(objectClass=user)' sAMAccountName",
                 "ldap/anon_bind.txt", interp_ldap_anon, tool="ldapsearch")

    # enum4linux-ng ozet (varsa)
    if have("enum4linux-ng") and (ctx.flag("ANON_SMB") or ctx.has_creds()):
        cred = f"-u {shlex.quote(ctx.username)} -p {shlex.quote(ctx.password)}" if ctx.has_creds() and ctx.password else ""
        run_step(ctx, runner, "p3_e4l",
                 "enum4linux-ng ozet taramasi",
                 "SMB/RPC uzerinden users/groups/shares/policy'yi tek arac ile derler.",
                 "Genel domain envanteri.",
                 f"enum4linux-ng -A {cred} {ip}",
                 "smb/enum4linux.txt", lambda o: p_info("enum4linux-ng ciktisi evidence/smb/enum4linux.txt"),
                 tool="enum4linux-ng")

    ctx.completed_phases.append(3); ctx.save()

# ==========================================================================
# PHASE 4 — SERVICE SECURITY ANALYSIS
# ==========================================================================
def phase4_service(ctx, runner, findings):
    phase_banner(4, "SERVICE SECURITY ANALYSIS")
    ip = ctx.dc_ip or ctx.target
    nxc = nxc_bin()

    # SMB signing + SMBv1
    if ctx.flag("SMB_AVAILABLE", True):
        def interp_smbsec(out):
            low = out.lower()
            if "smbv1" in low and re.search(r"smbv1.*(enabled|supported)", low):
                findings.add("HIGH", "SMBv1 etkin", ip, "SMB",
                             next((l for l in out.splitlines() if "smbv1" in l.lower()), "SMBv1"),
                             "Hedef eski SMBv1 protokolunu destekliyor.",
                             "MS17-010 (EternalBlue) ve MITM riski.",
                             "nmap -p445 --script smb-protocols <ip>",
                             "SMBv1 ozelligini kaldirin; yalnizca SMBv2/3.")
            if re.search(r"signing.*(disabled|not required)", low) or "enabled but not required" in low:
                findings.add("MEDIUM", "SMB signing zorunlu degil", ip, "SMB",
                             next((l for l in out.splitlines() if "signing" in l.lower()), "signing"),
                             "SMB imzalama kapali/zorunsuz.",
                             "NTLM relay saldirilari mumkun hale gelir.",
                             "nxc smb <ip> (signing:False) — relay senaryosu icin ntlmrelayx ile pasif dogrulama.",
                             "GPO: 'Digitally sign communications (always)' = Enabled.")
                next_step_hint("SMB signing kapali — agdaki DIGER SMB hostlarinda da signing durumunu kontrol et (relay hedef listesi).")
            else:
                p_info("SMB signing zorunlu gorunuyor (iyi).")
        run_step(ctx, runner, "p4_smbsec",
                 "SMB signing / SMBv1 guvenlik analizi",
                 "Signing kapaliligi relay'e, SMBv1 ise kritik RCE'lere kapi acar.",
                 "SMB imzalama zorunlu mu? Eski protokol var mi?",
                 f"nmap -Pn -p445 --script smb2-security-mode,smb-security-mode,smb-protocols {ip}",
                 "smb/security_mode.txt", interp_smbsec, tool="nmap")

    # LDAP signing / channel binding
    if ctx.flag("LDAP_AVAILABLE", True) and nxc:
        def interp_ldapsec(out):
            low = out.lower()
            if re.search(r"signing.*(not required|none)", low) or re.search(r"channel binding.*(never|not|disabled)", low):
                findings.add("MEDIUM", "LDAP signing / channel binding zayif", ip, "LDAP",
                             next((l for l in out.splitlines() if "sign" in l.lower() or "binding" in l.lower()), "ldap-checker"),
                             "LDAP signing veya channel binding zorunlu degil.",
                             "LDAP relay (ntlmrelayx -t ldap) ile ayricalik yukseltme yolu.",
                             "nxc ldap <ip> -M ldap-checker",
                             "LDAP signing + LDAPS channel binding'i zorunlu yapin (2020 sertlestirme ilkeleri).")
            else:
                p_info("LDAP signing/channel binding korumali gorunuyor ya da tespit edilemedi.")
        run_step(ctx, runner, "p4_ldapsec",
                 "LDAP signing / channel binding kontrolu",
                 "Bu iki koruma kapaliysa LDAP relay ile domain ele gecirme yolu acilir.",
                 "LDAP relay korumalari aktif mi?",
                 f"{nxc} ldap {ip} {nxc_auth_args(ctx)} -M ldap-checker",
                 "ldap/ldap_checker.txt", interp_ldapsec, tool="nxc")

    # WinRM yuzeyi
    if ctx.flag("WINRM_AVAILABLE"):
        findings.add("INFO", "WinRM yonetim yuzeyi acik", ip, "WinRM",
                     "5985/5986 open",
                     "WinRM uzaktan yonetim portu erisilebilir.",
                     "Gecerli kimlik ele gecerse uzaktan komut/oturum yuzeyi.",
                     "nxc winrm <ip> -u <user> -p <pass>  (kimlik varsa)",
                     "WinRM'i yonetim ag/hesaplariyla kisitlayin, HTTPS (5986) tercih edin.")

    # MS17-010 guvenli TESPIT
    if ctx.flag("SMB_AVAILABLE", True):
        def interp_ms17(out):
            if "VULNERABLE" in out:
                findings.add("CRITICAL", "MS17-010 (EternalBlue) potansiyel savunmasiz", ip, "SMB",
                             next((l for l in out.splitlines() if "State" in l), "VULNERABLE"),
                             "smb-vuln-ms17-010 hedefi savunmasiz raporladi.",
                             "Uzaktan kod calistirma — tam sistem ele gecirme.",
                             "IZINLIYSE dedike test hostunda metasploit 'auxiliary/scanner/smb/smb_ms17_010' CHECK modu.",
                             "MS17-010 yamasini uygulayin, SMBv1 kapatin.")
            else:
                p_info("MS17-010 belirtisi yok (yamali gorunuyor).")
        run_step(ctx, runner, "p4_ms17",
                 "MS17-010 (EternalBlue) guvenli tespiti",
                 "Yalnizca nmap 'check' scripti — exploit CALISTIRILMAZ.",
                 "Sistem EternalBlue'ya yamali mi?",
                 f"nmap -Pn -p445 --script smb-vuln-ms17-010 {ip}",
                 "smb/ms17-010.txt", interp_ms17, tool="nmap")

    ctx.completed_phases.append(4); ctx.save()

# ==========================================================================
# PHASE 5 — AUTHENTICATED ENUMERATION
# ==========================================================================
def phase5_authed(ctx, runner, findings):
    phase_banner(5, "AUTHENTICATED ENUMERATION")
    if not ctx.has_creds():
        p_warn("Kimlik bilgisi yok — authenticated enumeration ATLANDI.")
        p_info("Kimlik saglarsaniz: --username/--password veya --hash ile yeniden calistirin.")
        return
    ip = ctx.dc_ip or ctx.target
    nxc = nxc_bin()

    # kimlik dogrulama
    if nxc:
        def interp_val(out):
            if re.search(r"\[\+\]", out):
                ctx.set_flag("VALID_CREDENTIALS", True)
                p_good("Kimlik dogrulandi (gecerli credential).")
                if "Pwn3d" in out:
                    findings.add("HIGH", "Saglanan hesap bu hostta yerel yonetici", ip, "SMB",
                                 "(Pwn3d!)", "nxc '(Pwn3d!)' dondurdu.",
                                 "Hesap ile hedefte admin — secretsdump/lateral movement yuzeyi.",
                                 "nxc smb <ip> -u <user> -p <pass> --sam (izinliyse)",
                                 "Ayricalikli hesap kullanimini sinirlayin, tiering uygulayin.")
            else:
                p_err("Kimlik DOGRULANAMADI — parola/hash/hesap kontrol edin.")
        run_step(ctx, runner, "p5_validate",
                 "Saglanan kimligin dogrulanmasi",
                 "Authenticated testlere gecmeden once credential'in gecerli oldugunu teyit ederiz.",
                 "Verilen kullanici/parola gecerli mi, hedefte admin mi?",
                 f"{nxc} smb {ip} {nxc_auth_args(ctx)}",
                 "logs/cred_validate.txt", interp_val, tool="nxc")

    if not ctx.flag("VALID_CREDENTIALS"):
        p_warn("Gecerli kimlik onaylanamadi — devam eden authenticated adimlar atlanabilir.")

    # LDAP kimlikli dump
    if have("ldapsearch"):
        bdn = base_dn(ctx.domain); bind = ldap_bind_args(ctx)
        run_step(ctx, runner, "p5_ldap_users",
                 "Kimlikli LDAP: kullanici/grup/bilgisayar dumpu",
                 "Yetkili LDAP ile domain envanterini eksiksiz cikaririz.",
                 "Kullanicilar, gruplar, bilgisayarlar ve OS surumleri.",
                 f"ldapsearch -x -LLL -H ldap://{ip} {bind} -b {shlex.quote(bdn)} "
                 f"'(objectClass=computer)' dNSHostName operatingSystem",
                 "ldap/computers.txt",
                 lambda out: _interp_oldos(out, ip, ctx, findings),
                 tool="ldapsearch")

    ctx.completed_phases.append(5); ctx.save()

def _interp_oldos(out, ip, ctx, findings):
    old = re.findall(r"operatingSystem:\s*(.*(?:2000|2003|2008|XP|Windows 7|Vista).*)", out)
    if old:
        findings.add("HIGH", "Eski / destek disi isletim sistemleri", ctx.domain, "OS",
                     "; ".join(sorted(set(old))[:5]),
                     "Destegi bitmis Windows surumleri domain'de mevcut.",
                     "Yamalanmayan kritik zafiyetler; lateral movement hedefi.",
                     "ldapsearch ... '(objectClass=computer)' operatingSystem",
                     "EOL sistemleri yukseltin veya agdan izole edin.")
    else:
        p_info("Belirgin eski OS tespit edilmedi.")

# ==========================================================================
# PHASE 6 — IDENTITY & PRIVILEGE ANALYSIS
# ==========================================================================
def phase6_identity(ctx, runner, findings):
    phase_banner(6, "IDENTITY & PRIVILEGE ANALYSIS")
    if not ctx.has_creds():
        p_warn("Kimlik yok — kimlik/ayricalik analizi buyuk olcude atlaniyor.")
    ip = ctx.dc_ip or ctx.target
    nxc = nxc_bin()

    if nxc and ctx.has_creds():
        def interp_passpol(out):
            m = re.search(r"Minimum password length:\s*(\d+)", out)
            if m and int(m.group(1)) < 8:
                findings.add("MEDIUM", "Zayif minimum parola uzunlugu", ctx.domain, "Policy",
                             m.group(0), f"Minimum parola uzunlugu {m.group(1)} (<8).",
                             "Kaba kuvvet/spray kolaylasir.",
                             "nxc smb <ip> -u .. -p .. --pass-pol",
                             "Min 14 karakter + karmasiklik.")
            if re.search(r"Account Lockout Threshold:\s*(None|0)\b", out):
                findings.add("MEDIUM", "Hesap kilitleme esigi yok", ctx.domain, "Policy",
                             "Lockout Threshold: None",
                             "Account lockout threshold tanimsiz.",
                             "Sinirsiz parola denemesi (spray/brute) mumkun.",
                             "nxc smb <ip> --pass-pol",
                             "Makul lockout esigi (5-10) + gozlem penceresi.")
            else:
                p_info("Parola politikasi degerlendirildi.")
        run_step(ctx, runner, "p6_passpol",
                 "Parola & hesap kilitleme politikasi",
                 "Zayif politika, spray/brute icin ortami musait kilar; lockout yoksa risk artar.",
                 "Min uzunluk, karmasiklik, lockout esigi.",
                 f"{nxc} smb {ip} {nxc_auth_args(ctx)} --pass-pol",
                 "users/pass_policy.txt", interp_passpol, tool="nxc")

        run_step(ctx, runner, "p6_admins",
                 "Yuksek yetkili grup uyelikleri",
                 "Domain/Enterprise Admins uyeligi, saldiri yuzeyinin en kritik parcasidir.",
                 "Ayricalikli grup uyeleri kimler?",
                 f"{nxc} ldap {ip} {nxc_auth_args(ctx)} --groups 'Domain Admins'",
                 "users/domain_admins.txt",
                 lambda o: p_info("Domain Admins uyeleri evidence/users/domain_admins.txt"),
                 tool="nxc")

        # LDAP: admincount, pw-never-expires
        if have("ldapsearch"):
            bdn = base_dn(ctx.domain); bind = ldap_bind_args(ctx)
            def interp_admincount(out):
                n = len(re.findall(r"sAMAccountName:", out))
                if n > 12:
                    findings.add("MEDIUM", "Cok sayida ayricalikli hesap (admincount=1)", ctx.domain, "Identity",
                                 f"{n} hesap",
                                 f"admincount=1 olan {n} hesap (beklenenden fazla olabilir).",
                                 "Genis ayricalik yuzeyi; yetki yayilmasi.",
                                 "ldapsearch ... '(admincount=1)'",
                                 "Kullanilmayan admin haklarini kaldirin, AdminSDHolder'i denetleyin.")
                else:
                    p_info(f"admincount=1 hesap sayisi: {n} (makul).")
            run_step(ctx, runner, "p6_admincount",
                     "Ayricalikli (admincount=1) hesap sayisi",
                     "Fazla protected hesap, yetki yayilmasinin gostergesidir.",
                     "Korumali/ayricalikli hesap sayisi.",
                     f"ldapsearch -x -LLL -H ldap://{ip} {bind} -b {shlex.quote(bdn)} "
                     f"'(&(objectClass=user)(admincount=1))' sAMAccountName",
                     "users/admincount.txt", interp_admincount, tool="ldapsearch")

            def interp_neverexp(out):
                names = re.findall(r"sAMAccountName:\s*(\S+)", out)
                if names:
                    findings.add("LOW", "Parolasi suresiz hesaplar", ctx.domain, "Identity",
                                 ", ".join(names[:10]),
                                 f"{len(names)} hesabin parolasi hic bitmiyor (UAC 0x10000).",
                                 "Eski/zayif parolalarin surekli gecerli kalma riski.",
                                 "ldapsearch ... UAC:...=65536",
                                 "DONT_EXPIRE_PASSWORD bitini kaldirin, rotasyon uygulayin.")
                else:
                    p_info("Parolasi suresiz hesap yok.")
            run_step(ctx, runner, "p6_neverexp",
                     "Parolasi suresiz hesaplar",
                     "Bu hesaplar cogu zaman eski, zayif ve rotasyonsuz parolalar tasir.",
                     "PW-never-expires hesaplari.",
                     f"ldapsearch -x -LLL -H ldap://{ip} {bind} -b {shlex.quote(bdn)} "
                     f"'(userAccountControl:1.2.840.113556.1.4.803:=65536)' sAMAccountName",
                     "users/pw_never_expires.txt", interp_neverexp, tool="ldapsearch")

    ctx.completed_phases.append(6); ctx.save()

# ==========================================================================
# PHASE 7 — AD MISCONFIGURATION ANALYSIS  (Kerberos adaylari + AD CS)
# ==========================================================================
def phase7_misconfig(ctx, runner, findings):
    phase_banner(7, "AD MISCONFIGURATION ANALYSIS")
    ip = ctx.dc_ip or ctx.target
    nxc = nxc_bin()
    bdn = base_dn(ctx.domain); bind = ldap_bind_args(ctx)

    if not ctx.flag("KERBEROS_AVAILABLE", True):
        p_info("Kerberos (88) yok — Kerberos aday kontrolleri atlaniyor.")
    else:
        # AS-REP roast adaylari
        if ctx.has_creds() and have("ldapsearch"):
            def interp_asrep(out):
                names = re.findall(r"sAMAccountName:\s*(\S+)", out)
                if names:
                    findings.add("HIGH", "AS-REP Roasting adaylari", ctx.domain, "Kerberos",
                                 ", ".join(names),
                                 f"{len(names)} hesapta pre-auth kapali (DONT_REQ_PREAUTH).",
                                 "AS-REP bileti kimlik dogrulamadan cekilip offline kirilabilir.",
                                 "impacket-GetNPUsers <domain>/<user>:'***' -dc-ip <ip> -request -format hashcat  (hash cekimi; KIRMA otomatik degil)",
                                 "'Do not require preauth' ozelligini kapatin; guclu parola.")
                    print(f"      {c('[!] POTENTIAL ATTACK PATH: AS-REP Roasting', C.R)}")
                else:
                    p_info("AS-REP roastable hesap yok.")
            run_step(ctx, runner, "p7_asrep",
                     "AS-REP Roasting adaylarinin tespiti (LDAP)",
                     "Pre-auth kapali hesaplar, kimlik dogrulamadan hash sizdirir.",
                     "Hangi hesaplarda pre-auth kapali?",
                     f"ldapsearch -x -LLL -H ldap://{ip} {bind} -b {shlex.quote(bdn)} "
                     f"'(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' sAMAccountName",
                     "kerberos/asrep_candidates.txt", interp_asrep, tool="ldapsearch")
        elif not ctx.has_creds():
            p_warn("Kimlik yok — AS-REP adaylari icin kullanici listesi ile manuel yol:")
            print(c(f"      impacket-GetNPUsers {ctx.domain}/ -usersfile users.txt -dc-ip {ip} -no-pass -format hashcat", C.GREY))

        # Kerberoast adaylari (SPN) — bilet ISTEMEZ
        if ctx.has_creds() and have("ldapsearch"):
            def interp_spn(out):
                blocks = out.split("\n\n")
                names = re.findall(r"sAMAccountName:\s*(\S+)", out)
                spns = re.findall(r"servicePrincipalName:\s*(\S+)", out)
                if names:
                    findings.add("HIGH", "Kerberoast adaylari (SPN'li hesaplar)", ctx.domain, "Kerberos",
                                 f"users={', '.join(sorted(set(names)))} | spn={', '.join(spns[:6])}",
                                 f"{len(set(names))} kullanici hesabinda SPN tanimli.",
                                 "TGS biletleri cekilip offline kirilabilir; servis hesaplari genelde yuksek yetkili.",
                                 "impacket-GetUserSPNs <domain>/<user>:'***' -dc-ip <ip> -request  (bilet cekimi; KIRMA otomatik degil)",
                                 "Servis hesaplarina gMSA/uzun rastgele parola; gereksiz SPN'leri kaldirin.")
                    print(f"      {c('[!] POTENTIAL ATTACK PATH: Kerberoasting', C.R)}")
                    print(f"      {c('Servis/kullanici/SPN eslesmesi:', C.GREY)}")
                    for nme, spn in zip(names, spns):
                        print(f"        - {nme}  ->  {spn}")
                else:
                    p_info("SPN'li kullanici hesabi yok.")
            run_step(ctx, runner, "p7_spn",
                     "Kerberoast adaylarinin tespiti (SPN'li hesaplar)",
                     "SPN'li kullanici hesaplari Kerberoast icin birincil hedeftir.",
                     "Hangi kullanicilarda servicePrincipalName dolu?",
                     f"ldapsearch -x -LLL -H ldap://{ip} {bind} -b {shlex.quote(bdn)} "
                     f"'(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))' sAMAccountName servicePrincipalName",
                     "kerberos/spn_accounts.txt", interp_spn, tool="ldapsearch")

    # AD CS tespiti
    if ctx.has_creds() and nxc:
        def interp_adcs(out):
            if re.search(r"(Certificate Authorit|CA Name|pKIEnrollmentService|Found PKI)", out, re.I) or "adcs" in out.lower() and "found" in out.lower():
                ctx.set_flag("ADCS_FOUND", True)
                p_good("AD CS (Certificate Services) tespit edildi.")
                findings.add("INFO", "AD CS mevcut", ctx.domain, "AD CS",
                             "Enrollment service bulundu",
                             "Ortamda Certificate Authority var.",
                             "Yanlis template yapilandirmalari (ESC1-8) ayricalik yukseltmeye yol acabilir.",
                             "certipy find -u <user>@<domain> -p '***' -dc-ip <ip> -vulnerable -stdout",
                             "Template ACL/EKU ayarlarini denetleyin.")
                next_step_hint("AD CS var — certipy ile savunmasiz template taramasi (read-only) yapilabilir.")
            else:
                p_info("AD CS tespit edilmedi — AD CS testleri atlanacak.")
        run_step(ctx, runner, "p7_adcs_detect",
                 "AD CS (sertifika servisi) tespiti",
                 "AD CS yoksa tum ESC testleri gereksizdir; once varligini dogrularız.",
                 "Ortamda Certificate Authority var mi?",
                 f"{nxc} ldap {ip} {nxc_auth_args(ctx)} -M adcs",
                 "adcs/detect.txt", interp_adcs, tool="nxc")

        if ctx.flag("ADCS_FOUND") and have("certipy"):
            def interp_certipy(out):
                if re.search(r"ESC\d", out):
                    escs = ", ".join(sorted(set(re.findall(r"ESC\d+", out))))
                    findings.add("HIGH", "Savunmasiz AD CS template yapilandirmasi", ctx.domain, "AD CS",
                                 escs,
                                 f"certipy savunmasiz template(ler) raporladi: {escs}.",
                                 "Standart kullanici DA'ya yukselebilir (sertifika tabanli).",
                                 "certipy find ... -vulnerable -stdout  (read-only tespit; istismar otomatik DEGIL)",
                                 "Ilgili template ACL/EKU/flag ayarlarini duzeltin (ornegin ENROLLEE_SUPPLIES_SUBJECT kapatin).")
                    print(f"      {c('[!] POTENTIAL ATTACK PATH: AD CS ESC', C.R)}")
                else:
                    p_info("Savunmasiz template bulunamadi.")
            run_step(ctx, runner, "p7_certipy",
                     "AD CS savunmasiz template taramasi (read-only)",
                     "certipy find yalnizca okur; sertifika TALEP ETMEZ, istismar YOK.",
                     "ESC1-8 gibi riskli template yapilandirmalari var mi?",
                     f"certipy find -u {shlex.quote(ctx.username + '@' + ctx.domain)} "
                     f"-p {shlex.quote(ctx.password)} -dc-ip {ip} -vulnerable -stdout",
                     "adcs/certipy_find.txt", interp_certipy, tool="certipy", timeout=240)

    if ctx.has_creds():
        ctx.set_flag("BLOODHOUND_READY", True)
        next_step_hint("Yetkili kimlik mevcut — PHASE 8'de BloodHound ile yetki yollari analizi onerilir.")
    ctx.completed_phases.append(7); ctx.save()

# ==========================================================================
# PHASE 8 — ATTACK-PATH / BLOODHOUND ANALYSIS  (opsiyonel)
# ==========================================================================
def phase8_bloodhound(ctx, runner, findings):
    phase_banner(8, "ATTACK-PATH / BLOODHOUND ANALYSIS")
    if not ctx.has_creds():
        p_warn("Kimlik yok — BloodHound toplama icin yetkili kimlik gerekir. Atlaniyor."); return
    if not have("bloodhound-python"):
        p_warn("bloodhound-python yok (pipx install bloodhound). Atlaniyor."); return
    ip = ctx.dc_ip or ctx.target

    if not Mode.auto and not Mode.assume_yes:
        ans = input(f"    {c('BloodHound veri toplama baslatilsin mi? (LDAP okuma, non-destructive) [E/a] ', C.Y)}").strip().lower()
        if ans == "a":
            p_warn("BloodHound atlandi."); return

    outdir = os.path.join(ctx.assessment_dir, "bloodhound")
    hopt = f"--hashes ':{ctx.nthash}'" if ctx.nthash and not ctx.password else ""
    ppt = f"-p {shlex.quote(ctx.password)}" if ctx.password else ""
    cmd = (f"cd {shlex.quote(outdir)} && bloodhound-python -u {shlex.quote(ctx.username)} {ppt} {hopt} "
           f"-d {shlex.quote(ctx.domain)} -ns {ip} -c All --zip")
    def interp_bh(out):
        if re.search(r"\.zip", out) or any(f.endswith(".zip") for f in os.listdir(outdir)):
            p_good("BloodHound verisi toplandi (.zip).")
            findings.add("INFO", "BloodHound verisi toplandi", ctx.domain, "BloodHound",
                         "collector zip uretildi",
                         "AD iliski grafigi verisi hazir.",
                         "Analiz icin.",
                         "BloodHound CE'ye yukle -> 'Shortest Path to Domain Admins'.",
                         "Tespit edilen tehlikeli ACL/yol'lari duzeltin.")
        else:
            p_err("Toplama basarisiz — evidence/bloodhound/collect.log inceleyin.")
    run_step(ctx, runner, "p8_bloodhound",
             "BloodHound (Linux collector) veri toplama",
             "AD icindeki yetki iliskilerini ve yanlis yapilandirma yollarini grafik olarak cikarir.",
             "Bir kullanicidan DA'ya giden yetki zincirleri var mi?",
             cmd, "bloodhound/collect.log", interp_bh, tool="bloodhound-python", timeout=600)
    ctx.completed_phases.append(8); ctx.save()

# ==========================================================================
# PHASE 9 — FINDING VALIDATION  (pasif — komut onerir, calistirmaz)
# ==========================================================================
def phase9_validation(ctx, runner, findings):
    phase_banner(9, "FINDING VALIDATION (pasif — komutlar yalnizca ONERILIR)")
    attack = [f for f in ctx.findings if f["severity"] in ("CRITICAL", "HIGH")]
    if not attack:
        p_info("Dogrulanacak CRITICAL/HIGH bulgu yok.")
        return
    p_warn(f"{len(attack)} potansiyel saldiri yolu / zafiyet ISARETLENDI. "
           "Bunlar OTOMATIK istismar EDILMEZ; asagidaki dogrulama komutlari izinliyse elle calistirilir:")
    for f in attack:
        print(f"\n  {c(f['id'] + ' [' + f['severity'] + ']', SEV_COL[f['severity']])} {c(f['title'], C.W)}")
        print(f"    Host/Servis : {f['host']} / {f['service']}")
        print(f"    Kanit       : {f['evidence'][:140]}")
        print(f"    {c('Dogrulama   : ' + f['validation'], C.CY)}")
    print()
    p_warn("Hatirlatma: password spraying, exploit ve secretsdump gibi AKTIF adimlar bu asistan tarafindan calistirilmaz.")

# ==========================================================================
# PHASE 10 — REPORTING
# ==========================================================================
def phase10_report(ctx, runner, findings):
    phase_banner(10, "REPORTING")
    if not ctx.findings:
        p_warn("Bulgu yok — once bir faz calistirin."); return
    rep = os.path.join(ctx.assessment_dir, "report")
    counts = {s: sum(1 for f in ctx.findings if f["severity"] == s) for s in SEV_ORDER}

    # Markdown
    md = os.path.join(rep, "RAPOR.md")
    with open(md, "w", encoding="utf-8") as f:
        f.write(f"# Active Directory Guvenlik Degerlendirme Raporu\n\n")
        f.write(f"- Tarih: {datetime.now():%Y-%m-%d %H:%M}\n")
        f.write(f"- Domain: {ctx.domain or 'N/A'}\n")
        f.write(f"- DC: {ctx.dc_host or '?'} ({ctx.dc_ip or 'N/A'})\n")
        f.write(f"- Hedef: {ctx.target} / {ctx.subnet}\n")
        f.write(f"- Mod: Non-destructive / Enumeration\n\n")
        f.write("## Ozet\n\n| Onem | Adet |\n|---|---|\n")
        for s in SEV_ORDER:
            f.write(f"| {s} | {counts[s]} |\n")
        f.write("\n## Bulgular\n")
        for s in SEV_ORDER:
            for fd in [x for x in ctx.findings if x["severity"] == s]:
                f.write(f"\n### {fd['id']} — [{s}] {fd['title']}\n")
                f.write(f"- Affected Host: {fd['host']}\n- Service: {fd['service']}\n")
                f.write(f"- Evidence: `{fd['evidence']}`\n")
                f.write(f"- Technical Explanation: {fd['technical']}\n")
                f.write(f"- Security Impact: {fd['impact']}\n")
                f.write(f"- Recommended Validation: {fd['validation']}\n")
                f.write(f"- Remediation: {fd['remediation']}\n")

    # HTML
    html = os.path.join(rep, "RAPOR.html")
    def esc(x): return (x or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    with open(html, "w", encoding="utf-8") as f:
        f.write(f"""<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>AD Guvenlik Raporu — {esc(ctx.domain)}</title>
<style>body{{background:#0d1117;color:#e6edf3;font-family:Segoe UI,Arial,sans-serif;line-height:1.6;max-width:1100px;margin:0 auto;padding:24px}}
h1{{color:#58a6ff}}h2{{border-bottom:1px solid #2b3648;padding-bottom:6px;margin-top:30px}}
.meta{{background:#161b22;border:1px solid #2b3648;border-radius:8px;padding:14px 18px}}
table{{border-collapse:collapse;width:100%;margin:14px 0}}th,td{{border:1px solid #2b3648;padding:8px 12px;text-align:left}}th{{background:#1c2530}}
.card{{background:#161b22;border:1px solid #2b3648;border-radius:8px;padding:16px 18px;margin:14px 0;border-left:5px solid #8b98a9}}
.CRITICAL{{border-left-color:#f85149}}.HIGH{{border-left-color:#ff7b72}}.MEDIUM{{border-left-color:#f0883e}}.LOW{{border-left-color:#e3b341}}.INFO{{border-left-color:#58a6ff}}
.badge{{display:inline-block;padding:2px 10px;border-radius:14px;font-size:.75rem;font-weight:700;color:#04101f}}
.b-CRITICAL{{background:#f85149}}.b-HIGH{{background:#ff7b72}}.b-MEDIUM{{background:#f0883e}}.b-LOW{{background:#e3b341}}.b-INFO{{background:#58a6ff}}
code{{background:#0a0e14;padding:2px 6px;border-radius:4px;color:#a5d6ff}}.kv{{color:#8b98a9}}</style></head><body>
<h1>Active Directory Guvenlik Degerlendirme Raporu</h1>
<div class="meta"><b>Tarih:</b> {datetime.now():%Y-%m-%d %H:%M} | <b>Domain:</b> {esc(ctx.domain) or 'N/A'} |
<b>DC:</b> {esc(ctx.dc_host) or '?'} ({esc(ctx.dc_ip) or 'N/A'}) | <b>Hedef:</b> {esc(ctx.target)} | <b>Mod:</b> Non-destructive</div>
<h2>Ozet</h2><table><tr><th>Onem</th><th>Adet</th></tr>""")
        for s in SEV_ORDER:
            f.write(f'<tr><td><span class="badge b-{s}">{s}</span></td><td>{counts[s]}</td></tr>')
        f.write("</table><h2>Bulgular</h2>")
        for s in SEV_ORDER:
            for fd in [x for x in ctx.findings if x["severity"] == s]:
                f.write(f"""<div class="card {s}"><span class="badge b-{s}">{s}</span> <b>{esc(fd['title'])}</b> <span class="kv">({fd['id']})</span>
<p><span class="kv">Affected Host:</span> {esc(fd['host'])}<br><span class="kv">Service:</span> {esc(fd['service'])}<br>
<span class="kv">Technical:</span> {esc(fd['technical'])}<br><span class="kv">Impact:</span> {esc(fd['impact'])}<br>
<span class="kv">Evidence:</span> <code>{esc(fd['evidence'])}</code><br>
<span class="kv">Validation:</span> {esc(fd['validation'])}<br><span class="kv">Remediation:</span> {esc(fd['remediation'])}</p></div>""")
        f.write('<p class="kv" style="margin-top:30px">Non-destructive mod. Yalnizca yetkili test ortami icin.</p></body></html>')

    p_good("Rapor olusturuldu:")
    print(f"    {c(md, C.W)}")
    print(f"    {c(html, C.W)}")
    parts = "  ".join(f"{c(s+':'+str(counts[s]), SEV_COL[s])}" for s in SEV_ORDER)
    print(f"    Ozet: {parts}")

# ==========================================================================
# DECISION ENGINE  —  fazlari context'e gore sirala/atla
# ==========================================================================
PHASES = [
    (1, "Network Discovery",           phase1_network,   lambda ctx: True),
    (2, "AD / DC Identification",      phase2_dc,        lambda ctx: bool(ctx.live_hosts) or bool(ctx.dc_ip)),
    (3, "Unauthenticated Enumeration", phase3_unauth,    lambda ctx: ctx.flag("SMB_AVAILABLE", True) or ctx.flag("LDAP_AVAILABLE", True)),
    (4, "Service Security Analysis",   phase4_service,   lambda ctx: ctx.flag("SMB_AVAILABLE", True) or ctx.flag("LDAP_AVAILABLE", True)),
    (5, "Authenticated Enumeration",   phase5_authed,    lambda ctx: ctx.has_creds()),
    (6, "Identity & Privilege",        phase6_identity,  lambda ctx: ctx.has_creds()),
    (7, "AD Misconfiguration",         phase7_misconfig, lambda ctx: ctx.flag("KERBEROS_AVAILABLE", True) or ctx.has_creds()),
    (8, "Attack-Path / BloodHound",    phase8_bloodhound,lambda ctx: ctx.has_creds()),
    (9, "Finding Validation",          phase9_validation,lambda ctx: True),
    (10, "Reporting",                  phase10_report,   lambda ctx: True),
]

def run_pipeline(ctx, runner, findings, only=None):
    for num, title, fn, guard in PHASES:
        if only and num not in only:
            continue
        if not guard(ctx):
            p_info(f"[PHASE {num} — {title}] on kosul saglanmadi, ATLANDI.")
            continue
        fn(ctx, runner, findings)

# ==========================================================================
# MENU
# ==========================================================================
def menu(ctx, runner, findings):
    while True:
        print()
        print(c("="*60, C.B))
        print(c("  AD PENTEST ASSISTANT — Command Center", C.W))
        print(c("="*60, C.B))
        creds = c("var", C.G) if ctx.has_creds() else c("yok", C.Y)
        print(f"  Hedef: {ctx.target or ctx.subnet}  Domain: {ctx.domain or '?'}  DC: {ctx.dc_ip or '?'}  Kimlik: {creds}")
        fl = " ".join(f"{k}={int(v)}" for k, v in ctx.flags.items())
        if fl: print(c("  flags: " + fl, C.GREY))
        print(f"  Bulgu: {len(ctx.findings)}  |  Cikti: {ctx.assessment_dir}/")
        print("  " + "-"*56)
        for num, title, *_ in PHASES:
            mark = c("✓", C.G) if num in ctx.completed_phases else " "
            print(f"  [{num:>2}] {mark} {title}")
        print("  " + "-"*56)
        print("  [A] Akilli pipeline (bulguya gore tum uygun fazlar)")
        print("  [C] Arac kontrolu    [S] State goster    [Q] Cikis")
        ch = input(c("  Secim: ", C.Y)).strip().lower()
        if ch == "q":
            ctx.save(); p_good(f"Cikildi. Devam: python3 ad_assistant.py --resume {ctx.assessment_dir}"); return
        elif ch == "a":
            run_pipeline(ctx, runner, findings)
        elif ch == "c":
            tool_check()
        elif ch == "s":
            print(json.dumps({"flags": ctx.flags, "done": ctx.done,
                              "dc_candidates": ctx.dc_candidates,
                              "completed_phases": ctx.completed_phases}, indent=2, ensure_ascii=False))
        elif ch.isdigit():
            n = int(ch)
            ph = next((p for p in PHASES if p[0] == n), None)
            if ph:
                _, title, fn, guard = ph
                if not guard(ctx):
                    p_warn(f"PHASE {n} on kosulu saglanmiyor (ornegin kimlik/servis yok). Yine de deneniyor...")
                fn(ctx, runner, findings)
            else:
                p_err("Gecersiz faz.")
        else:
            p_err("Gecersiz secim.")

# ==========================================================================
# KURULUM / MAIN
# ==========================================================================
def make_dirs(base):
    for d in ("discovery","dns","smb","ldap","kerberos","rpc","winrm","adcs",
              "bloodhound","evidence","commands","logs","report"):
        os.makedirs(os.path.join(base, d), exist_ok=True)

def default_flags():
    return {}

def build_context(args):
    if args.resume:
        if not os.path.isdir(args.resume):
            p_err(f"Resume dizini yok: {args.resume}"); sys.exit(1)
        ctx = Context.load(args.resume)
        ctx.assessment_dir = args.resume
        p_good(f"Onceki session yuklendi: {args.resume}  (tamamlanan faz: {ctx.completed_phases})")
        # CLI ile gelen yeni kimlik varsa guncelle
        if args.username: ctx.username = args.username
        if args.password: ctx.password = args.password
        if getattr(args, "hash"): ctx.nthash = args.hash
        return ctx

    if not args.target:
        p_err("--target gerekli (veya --resume). Ornek: --target 192.168.1.0/24"); sys.exit(1)
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    base = f"ad-assessment_{ts}"
    make_dirs(base)
    ctx = Context(
        target=args.target,
        subnet=args.target if "/" in args.target else "",
        domain=args.domain or "",
        dc_ip=args.dc_ip or ("" if "/" in args.target else args.target),
        username=args.username or "",
        password=args.password or "",
        nthash=args.hash or "",
        iface=args.interface,
        assessment_dir=base,
        flags=default_flags(),
    )
    ctx.save()
    p_good(f"Yeni assessment: {base}/")
    return ctx

def parse_args():
    ap = argparse.ArgumentParser(description="AD Pentest Assistant (decision-engine, non-destructive)")
    ap.add_argument("--target", help="Hedef IP veya subnet (orn 192.168.1.0/24)")
    ap.add_argument("--domain", help="Domain adi (orn example.local)")
    ap.add_argument("--dc-ip", dest="dc_ip", help="Domain Controller IP")
    ap.add_argument("--username", help="Yetkili kullanici (opsiyonel)")
    ap.add_argument("--password", help="Parola (opsiyonel)")
    ap.add_argument("--hash", help="NTLM hash (opsiyonel, PtH)")
    ap.add_argument("--interface", default="eth0", help="Ag arayuzu")
    ap.add_argument("--resume", help="Onceki assessment dizinini yukle")
    ap.add_argument("--auto", action="store_true", help="Adimlari onaysiz calistir (yine non-destructive)")
    ap.add_argument("--yes", action="store_true", help="Onaylari otomatik evet")
    ap.add_argument("--dry", action="store_true", help="Komutlari yalnizca goster, calistirma")
    ap.add_argument("--run-all", action="store_true", help="Menu yerine dogrudan akilli pipeline'i calistir")
    return ap.parse_args()

BANNER = r"""
    _   ___    _              _    _              _
   /_\ |   \  /_\   ___ ___ (_) __| |_ __ _ _ _ | |_
  / _ \| |) |/ _ \ (_-<(_-< | |(_-<|  _/ _` | ' \|  _|
 /_/ \_\___//_/ \_\/__//__/ |_|/__/ \__\__,_|_||_|\__|
   Active Directory Pentest Assistant  ·  decision-engine
   NON-DESTRUCTIVE · yalnizca yetkili test ortami icin
"""

def main():
    args = parse_args()
    Mode.auto = args.auto
    Mode.assume_yes = args.yes or args.auto
    Mode.dry = args.dry
    print(c(BANNER, C.B))

    if os.name == "nt":
        p_warn("Windows tespit edildi. Bu asistan hedef araclari (nmap/nxc/ldapsearch...) Kali/Linux'ta calistirir.")
        p_warn("Windows'ta yalnizca akis/menu denenebilir; gercek testler icin Kali kullanin.\n")

    ctx = build_context(args)

    if not (Mode.auto or Mode.assume_yes):
        ans = input(c("Yetkili oldugunuzu onayliyor musunuz? [e/H]: ", C.Y)).strip().lower()
        if ans not in ("e", "y"):
            p_err("Onay verilmedi. Cikiliyor."); sys.exit(1)

    runner = Runner(ctx)
    findings = Findings(ctx)
    missing = tool_check()
    if "nmap" in missing:
        p_warn("nmap yok — network discovery sinirli olacak.")

    if args.run_all:
        run_pipeline(ctx, runner, findings)
        phase10_report(ctx, runner, findings)
    else:
        menu(ctx, runner, findings)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + c("[!] Kesildi. State kaydedildi; --resume ile devam edebilirsiniz.", C.Y))
