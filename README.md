# AD Lab — Active Directory Pentest Çalışma Ortamı

Yetkili **kendi laboratuvar / pentest ortamı** için hazırlanmış Active Directory
güvenlik test materyalleri, rehberler ve otomasyon araçları.

> ⚠️ **Yasal / Etik uyarı:** Buradaki tüm içerik ve araçlar yalnızca **yazılı izin
> (scope/authorization)** aldığınız sistemlerde kullanılmalıdır. Password spraying,
> Responder aktif modu, exploit ve credential dump gibi işlemler **aktif müdahaledir**;
> account-lockout, hizmet kesintisi ve yasal sonuç doğurabilir. İzinsiz kullanım yasaktır.

## İçerik

### 📄 Rehberler (HTML)
| Dosya | Açıklama |
|-------|----------|
| `AD-Ilk-Kesif.html` | Sıfırdan bilgi toplama: Host → Domain → Share → Kullanıcı → Parola → SPN, bol komutlu adım adım rehber. |
| `AD-Pentest-Yol-Haritasi.html` | 24 aracın sıralı, öğrenme odaklı rehberi (enumeration → analiz → ileri istismar → raporlama), zengin komut/parametre setleriyle. |
| `AD-Guvenlik-Checklist.html` | AD güvenlik kontrol listesi. |
| `ad-pentest-command-center.html` | Pentest komut merkezi. |
| `ad-pentest-rapor-sablonu.html` | Pentest rapor şablonu. |
| `ad-saldiri-akademisi.html` | AD saldırı teknikleri akademisi. |

### 🛠️ Araçlar (Kali Linux)
| Dosya | Açıklama |
|-------|----------|
| `ad_assistant.py` | **Bulguya göre ilerleyen** AD Pentest Assistant (decision-engine). State/context tutar, her komut öncesi "Ne/Neden/Ne öğreniyoruz" açıklar, non-destructive, `--resume` ile session devamı, MD+HTML rapor. |
| `ad-recon.sh` | Menü tabanlı, non-destructive AD keşif & güvenlik değerlendirme scripti (10 modül, CRITICAL→INFO raporlama). |
| `kurulum-kontrol.sh` | Gerekli araçların kurulum kontrolü. |

### 📝 Notlar
- `Yeni Microsoft Word Belgesi.docx` — araç bazlı çalışma notları (corp.local lab).

## Hızlı başlangıç

```bash
# Decision-engine asistan (Kali)
python3 ad_assistant.py --target 192.168.1.0/24
python3 ad_assistant.py --target 192.168.1.10 --domain example.local \
        --username claire --password 'Password123!'
python3 ad_assistant.py --resume ad-assessment_YYYYMMDD_HHMM

# Menü tabanlı recon scripti
chmod +x ad-recon.sh && ./ad-recon.sh
```

Rehberleri (`*.html`) doğrudan tarayıcıda açabilirsiniz.

## Varsayılan çalışma modu

- Non-destructive / enumeration ağırlıklı
- Exploit / password-spray / persistence **otomatik çalıştırılmaz**
- Potansiyel saldırı yolları yalnızca **işaretlenir** ve pasif doğrulama komutu önerilir
