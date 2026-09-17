# WILY — WiFi Security & Rogue AP Auditing Tool

[Türkçe](#türkçe) | [English](#english)

---

<a name="türkçe"></a>
# Türkçe

```
 __        __ ___  _      __   __
 \ \      / /|_ _|| |     \ \ / /
  \ \ /\ / /  | | | |      \ V / 
   \ V  V /   | | | |___    | |  
    \_/\_/   |___||_____|   |_|  
```

Wily, kablosuz ağ güvenliği denetimi, WPA 4-way handshake analizi, hash doğrulama, deauthentication testi, sahte erişim noktası (Evil Twin) ve Captive Portal farkındalık testlerini tek bir akışta sunan kablosuz ağ analiz aracıdır. Kali Linux ve Python 3.8+ ile tam uyumludur.

---

## Özellikler

| Özellik | Açıklama |
|---|---|
| **Kablosuz Ağ Taraması** | Çevredeki erişim noktalarını ve bağlı istemcileri (BSSID, kanal, sinyal, şifreleme) listeleme |
| **WPA Handshake Yakalama** | Hedef ağdan 4-way handshake yakalayarak `.cap` dosyası olarak kaydetme |
| **Anlık Hash Doğrulama** | Portala girilen parolayı PBKDF2 / HMAC-SHA1 ile yakalanan handshake üzerinden anlık doğrulama |
| **Sahte Erişim Noktası (Evil Twin)** | Hostapd ile hedef ağ parametrelerinde test erişim noktası oluşturma |
| **Trafik Yönlendirme (Captive Portal)** | Dnsmasq ve iptables ile HTTP/DNS isteklerini test portalına yönlendirme |
| **İşletim Sistemi Algılama** | Android, iOS, Windows ve macOS sistemlerde portal bildirimlerini tetikleme |
| **Deauthentication Testi** | İstemcilerin yeniden kimlik doğrulama sürecini test etmek için deauth paketleri gönderme |
| **Çift Adaptör Desteği** | İkinci kablosuz ağ kartı varlığında arka planda eşzamanlı deauth testi çalıştırma |
| **Otomatik Arayüz Yönetimi** | Airmon-ng, NetworkManager ve IP yönlendirme ayarlarını otomatik yönetme |
| **Temiz Çıkış ve Sıfırlama** | Çıkış esnasında tüm ağ kurallarını, servisleri ve adaptör modlarını varsayılana döndürme |

---

## Kurulum

### Gereksinimler

- **İşletim Sistemi:** Kali Linux (Önerilen), Debian, Ubuntu veya diğer Linux güvenlik dağıtımları
- **Donanım:** Monitor mod ve paket enjeksiyonu destekleyen kablosuz ağ adaptörü (Atheros AR9271, Ralink RT3070/RT5370, Realtek RTL8812AU vb.)
- **Python:** Python 3.8 veya üzeri

### 1. Otomatik Kurulum (Önerilen)

```bash
git clone https://github.com/erensogutlu/wily.git
cd wily
sudo bash kurulum.sh
```

### 2. Manuel Kurulum

```bash
# Sistem paketleri
sudo apt update
sudo apt install -y hostapd dnsmasq aircrack-ng iptables python3-pip python3-scapy

# Çalıştırma yetkisi
chmod +x wily.py
```

### Python Sürüm Uyumluluğu

| Python Sürümü | Durum |
|---|---|
| Python 3.8 | Desteklenir |
| Python 3.9 | Desteklenir |
| Python 3.10 | Desteklenir |
| Python 3.11 | Desteklenir |
| Python 3.12+ | Desteklenir |

---

## Kullanım — Adım Adım Rehber

Temel kavramlar:

1. **Monitor Mod:** Kablosuz ağ trafiğini ham 802.11 çerçeveleri düzeyinde dinleme modu.
2. **Handshake:** İstemci ile modem arasındaki 4 adımlı kriptografik kimlik doğrulama paketi.
3. **Evil Twin:** Hedef ağ ile aynı SSID ve kanal parametrelerine sahip test erişim noktası.
4. **Captive Portal:** Kullanıcı sahte ağa bağlandığında açılan test bilgilendirme ve giriş sayfası.

---

### 1. İnteraktif Menü (Varsayılan)

```bash
sudo python3 wily.py
```

**Ana Menü:**
```
  ┌──────────────────────────────────────┐
  │         ANA MENÜ - WILY              │
  ├──────────────────────────────────────┤
  │  [1] otomatik akış (adım adım)      │
  │  [2] sadece ağ taraması              │
  │  [3] sadece deauth testi             │
  │  [4] sadece test ap oluştur          │
  │  [5] yakalanan bilgileri göster      │
  │  [0] çıkış                           │
  └──────────────────────────────────────┘
```

---

### 2. Otomatik Test Akışı (7 Adımlı Senaryo)

```
[1] KABLOSUZ AĞ TARAMASI
    └─ Kanallar taranır, erişim noktaları ve sinyal seviyeleri listelenir.
[2] HEDEF SEÇİMİ VE İSTEMCİ BELİRLEME
    └─ Hedef erişim noktası seçilir ve bağlı istemci MAC adresleri listelenir.
[3] WPA HANDSHAKE YAKALAMA
    └─ Deauth sinyali ile istemcinin yeniden bağlanması sağlanarak 4-way handshake kaydedilir.
[4] DEAUTH SİNYALİ GÖNDERİMİ
    └─ İstemcinin test erişim noktasına yönelmesi için bağlantı kesme sinyalleri gönderilir.
[5] SAHTE ERİŞİM NOKTASI VE PORTAL YAYINI
    └─ Hedef SSID ile klon erişim noktası, DHCP/DNS ve HTTP portal servisi başlatılır.
[6] EŞZAMANLI DEAUTH TESTİ
    └─ İkinci adaptör varsa orijinal ağa yönelik deauth sinyalleri sürdürülür.
[7] PAROLA DOĞRULAMA VE SONLANDIRMA
    └─ Girilen parola handshake hash'i ile anlık doğrulanır ve test tamamlanır.
```

---

### 3. Komut Satırı Parametreleri

| Parametre | Açıklama |
|---|---|
| `--tara` | Sadece kablosuz ağ taraması yapar ve listeler |
| `--deauth` | Sadece deauthentication testi çalıştırır |
| `--sahte-ap` | Bağımsız sahte erişim noktası ve portal başlatır |
| `--bilgiler` | Kaydedilen parola ve form girdilerini listeler |
| `--surum` | Sürüm bilgisini gösterir |
| `-h`, `--help` | Yardım menüsünü görüntüler |

---

### 4. Proje Yapısı

```
wily/
├── wily.py                  # ana çalıştırma dosyası
├── requirements.txt         # python bağımlılıkları (scapy)
├── README.md               # proje dokümantasyonu
├── kurulum.sh              # otomatik kurulum betiği
├── cekirdek/               # çekirdek modüller
│   ├── __init__.py         # paket başlatıcı
│   ├── yapilandirma.py     # yapılandırma ve renk sabitleri
│   ├── arayuz.py           # arayüz ve monitor mod yöneticisi
│   ├── tarayici.py         # 802.11 ağ ve istemci tarayıcısı
│   ├── deauth.py           # deauthentication motoru
│   ├── handshake.py        # handshake yakalama ve doğrulama
│   ├── sahte_ap.py         # hostapd ve dnsmasq yöneticisi
│   └── portal.py           # captive portal sunucusu
├── sablonlar/              # web arayüz şablonları
│   ├── giris.html          # portal giriş sayfası
│   └── basarili.html       # bağlantı başarılı sayfası
└── kayitlar/               # kayıt dizini
    └── .gitkeep
```

---

### 5. Sık Sorulan Sorular

**S: Root yetkisi neden gereklidir?**
Monitor mod yönetimi, ham paket enjeksiyonu ve iptables yönlendirmeleri için root yetkisi zorunludur (`sudo python3 wily.py`).

**S: Handshake neden yakalanamıyor?**
Handshake yakalanabilmesi için hedef ağda aktif bir istemcinin bulunması ve veri alışverişi yapması gerekir.

**S: Parola doğrulaması nasıl çalışır?**
Portal formuna girilen parola, yakalanan 4-way handshake paketindeki parametreler (ANonce, SNonce, MAC adresleri) ve PBKDF2/HMAC-SHA1 algoritmasıyla anlık olarak test edilir.

**S: Çıkış yapıldığında sistem ayarları sıfırlanır mı?**
Evet. Wily kapatıldığında tüm iptables kuralları sıfırlanır, çalışan servisler kapatılır ve NetworkManager yeniden başlatılır.

---

### 6. Savunma Önlemleri

| Tehdit | Korunma Yöntemi |
|---|---|
| **Deauthentication** | 802.11w (PMF - Protected Management Frames) veya WPA3 kullanımı |
| **Evil Twin** | Bilinmeyen ve açık ağlara otomatik bağlanmayı devre dışı bırakma |
| **Captive Portal** | Güvenilmeyen web sayfalarına WiFi parolası girmeme |
| **Ağ Trafiği** | Açık ağlarda şifreli VPN tünelleri kullanma |

---

### 7. Yasal Uyarı

Bu araç **yalnızca eğitim ve yetkili güvenlik testleri** amacıyla geliştirilmiştir. Yetkisiz sistemler üzerinde test gerçekleştirmek yasalara aykırıdır. Hukuki sorumluluk kullanıcıya aittir.

---

<a name="english"></a>
# English

```
 __        __ ___  _      __   __
 \ \      / /|_ _|| |     \ \ / /
  \ \ /\ / /  | | | |      \ V / 
   \ V  V /   | | | |___    | |  
    \_/\_/   |___||_____|   |_|  
```

Wily is a wireless security auditing and awareness testing tool combining network reconnaissance, WPA 4-way handshake analysis, hash verification, deauthentication testing, rogue access point (Evil Twin) deployment, and Captive Portal workflows. Fully compatible with Kali Linux and Python 3.8+.

---

## Features

| Feature | Description |
|---|---|
| **Wireless Scanning** | Enumerates nearby APs and connected clients (BSSID, channel, signal, encryption) |
| **Handshake Capture** | Captures 4-way handshakes from target networks and stores them as `.cap` files |
| **Instant Verification** | Verifies entered credentials in real time using PBKDF2 / HMAC-SHA1 against captured handshakes |
| **Rogue Access Point (Evil Twin)** | Clones target AP configurations using hostapd |
| **Traffic Redirection** | Routes HTTP/DNS requests to the portal using dnsmasq and iptables |
| **OS Detection** | Triggers native captive portal login popups across major operating systems |
| **Deauthentication Testing** | Injects 802.11 deauth frames to audit client reconnection security |
| **Dual Adapter Support** | Supports secondary adapter usage for parallel background operations |
| **Interface Automation** | Automates airmon-ng, NetworkManager, and routing tables |
| **Clean Restoration** | Restores all firewall rules, background processes, and interfaces upon exit |

---

## Installation

### Prerequisites

- **OS:** Kali Linux (Recommended), Debian, Ubuntu, or other Linux distributions
- **Hardware:** Wireless adapter supporting monitor mode and packet injection (Atheros AR9271, Ralink RT3070/RT5370, Realtek RTL8812AU, etc.)
- **Python:** Python 3.8 or higher

### 1. Automated Installation (Recommended)

```bash
git clone https://github.com/erensogutlu/wily.git
cd wily
sudo bash kurulum.sh
```

### 2. Manual Installation

```bash
# System packages
sudo apt update
sudo apt install -y hostapd dnsmasq aircrack-ng iptables python3-pip python3-scapy

# Execution permissions
chmod +x wily.py
```

### Python Version Support

| Python Version | Status |
|---|---|
| Python 3.8 | Supported |
| Python 3.9 | Supported |
| Python 3.10 | Supported |
| Python 3.11 | Supported |
| Python 3.12+ | Supported |

---

## Usage — Step-by-Step Guide

Core concepts:

1. **Monitor Mode:** Wireless adapter configuration allowing passive capture of raw 802.11 frames.
2. **Handshake:** The 4-step cryptographic key exchange established between client and access point.
3. **Evil Twin:** A simulated access point configured with identical network attributes for testing.
4. **Captive Portal:** A localized web authentication page presented to connecting devices.

---

### 1. Interactive Menu (Default)

```bash
sudo python3 wily.py
```

**Main Menu Interface:**
```
  ┌──────────────────────────────────────┐
  │         MAIN MENU - WILY             │
  ├──────────────────────────────────────┤
  │  [1] automated workflow (step by step)│
  │  [2] network scanning only           │
  │  [3] deauthentication test only      │
  │  [4] rogue AP only                   │
  │  [5] view captured credentials       │
  │  [0] exit                            │
  └──────────────────────────────────────┘
```

---

### 2. Automated Test Workflow (7-Step Scenario)

```
[1] WIRELESS SCANNING
    └─ Enumerates channels, identifying access points and signal levels.
[2] TARGET & CLIENT DISCOVERY
    └─ Selects the target network and identifies associated client devices.
[3] WPA HANDSHAKE CAPTURE
    └─ Emits brief deauth signals to capture the 4-way handshake into a .cap file.
[4] DEAUTHENTICATION SIGNALING
    └─ Evaluates client roaming behavior by signaling disconnection from the source AP.
[5] ROGUE AP & PORTAL DEPLOYMENT
    └─ Initiates cloned AP, DHCP/DNS services, and the local HTTP captive portal.
[6] BACKGROUND DEAUTH AUDITING
    └─ Uses secondary wireless adapter (if present) to maintain active testing.
[7] PASSWORD VERIFICATION & CONCLUSION
    └─ Validates entered credentials in real-time against the captured cryptographic hash.
```

---

### 3. Command-Line Arguments

| Argument | Description |
|---|---|
| `--tara` | Executes wireless network discovery scan |
| `--deauth` | Executes targeted deauthentication test |
| `--sahte-ap` | Initiates standalone rogue access point and portal |
| `--bilgiler` | Displays recorded credentials and test logs |
| `--surum` | Shows software version |
| `-h`, `--help` | Displays help information and CLI flags |

---

### 4. Project Structure

```
wily/
├── wily.py                  # main execution entry point
├── requirements.txt         # python dependencies (scapy)
├── README.md               # project documentation
├── kurulum.sh              # automated installer
├── cekirdek/               # core system modules
│   ├── __init__.py         # package initializer
│   ├── yapilandirma.py     # configuration and color constants
│   ├── arayuz.py           # interface and monitor mode manager
│   ├── tarayici.py         # 802.11 network scanner
│   ├── deauth.py           # deauthentication test engine
│   ├── handshake.py        # handshake capture & verification
│   ├── sahte_ap.py         # hostapd and dnsmasq controller
│   └── portal.py           # captive portal web server
├── sablonlar/              # html templates
│   ├── giris.html          # captive portal login page
│   └── basarili.html       # connection success template
└── kayitlar/               # logs and data directory
    └── .gitkeep
```

---

### 5. Frequently Asked Questions

**Q: Why are root privileges required?**
Managing monitor mode interfaces, injecting raw 802.11 frames, and modifying iptables rules require administrative privileges (`sudo python3 wily.py`).

**Q: Why was the handshake not captured?**
An active client must be connected to the target access point and actively transmitting authentication frames to capture a valid 4-way handshake.

**Q: How does hash verification work?**
Credentials submitted via the portal are computed using PBKDF2/HMAC-SHA1 alongside handshake parameters (ANonce, SNonce, MACs) to verify the Message Integrity Code (MIC) without external wordlists.

**Q: Does exiting reset network configurations?**
Yes. On termination, Wily flushes iptables modifications, terminates hostapd/dnsmasq instances, and restarts NetworkManager.

---

### 6. Defensive Countermeasures

| Threat | Mitigation |
|---|---|
| **Deauthentication** | Deploy 802.11w (Protected Management Frames) or WPA3 |
| **Evil Twin** | Prevent automatic connections to open/unsecured networks |
| **Captive Portal** | Avoid entering WiFi pre-shared keys into browser forms |
| **Network Traffic** | Use encrypted VPN tunnels across untrusted access points |

---

### 7. Legal Disclaimer

This utility is designed **strictly for authorized security assessments and educational purposes**. Unauthorized testing against wireless systems is prohibited by law. The user assumes all legal liability.
