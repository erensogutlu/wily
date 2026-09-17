#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# wily - evil twin yapılandırma modülü

import os


class Renkler:
    """ansi renk kodları."""

    KIRMIZI = '\033[91m'
    YESIL = '\033[92m'
    SARI = '\033[93m'
    MAVI = '\033[94m'
    MOR = '\033[95m'
    CYAN = '\033[96m'
    BEYAZ = '\033[97m'
    SIFIRLA = '\033[0m'
    KALIN = '\033[1m'


# proje sabitleri
PROJE_ADI = 'wily'
SURUM = '1.0.0'

# varsayılan ağ ayarları
VARSAYILAN_AG_GECIDI = '10.0.0.1'
VARSAYILAN_ALT_AG_MASKESI = '255.255.255.0'
DHCP_ARALIK_BASLANGIC = '10.0.0.10'
DHCP_ARALIK_BITIS = '10.0.0.100'
DNS_SUNUCU = '10.0.0.1'

# varsayılan ayarlar
VARSAYILAN_AYARLAR = {
    'deauth_paket_sayisi': 100,
    'deauth_aralik': 0.1,
    'portal_port': 80,
    'dhcp_baslangic': DHCP_ARALIK_BASLANGIC,
    'dhcp_bitis': DHCP_ARALIK_BITIS,
    'ag_gecidi': VARSAYILAN_AG_GECIDI,
    'alt_ag_maskesi': VARSAYILAN_ALT_AG_MASKESI,
    'dns_sunucu': DNS_SUNUCU,
}

# hostapd şablonu
HOSTAPD_SABLON = """interface={arayuz}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={kanal}
wmm_enabled=0
auth_algs=1
wpa=0
"""

# dnsmasq şablonu
DNSMASQ_SABLON = """interface={arayuz}
bind-interfaces
except-interface=lo
dhcp-range={dhcp_baslangic},{dhcp_bitis},{alt_ag_maskesi},12h
dhcp-option=3,{ag_gecidi}
dhcp-option=6,{dns_sunucu}
no-resolv
log-queries
log-dhcp
listen-address={ag_gecidi}
address=/#/{ag_gecidi}
"""

# geçici dosya yolları
HOSTAPD_YAPILANDIRMA_YOLU = '/tmp/wily_hostapd.conf'
DNSMASQ_YAPILANDIRMA_YOLU = '/tmp/wily_dnsmasq.conf'

# handshake ayarları
HANDSHAKE_YAKALAMA_SURESI = 30  # saniye
HANDSHAKE_DEAUTH_PAKETI = 5  # tetikleme deauth sayısı
HANDSHAKE_DEAUTH_ARALIGI = 3  # turlar arası bekleme (saniye)

# sürekli deauth ayarları
SUREKLI_DEAUTH_ARALIGI = 0.05  # paketler arası bekleme (saniye)
SUREKLI_DEAUTH_YOGUN_ARALIGI = 0.02  # yoğun mod aralığı


def banner_goster():
    """banner yazdırır."""

    banner = f"""
{Renkler.CYAN}{Renkler.KALIN}
 __        __ ___  _      __   __
 \\ \\      / /|_ _|| |     \\ \\ / /
  \\ \\ /\\ / /  | | | |      \\ V / 
   \\ V  V /   | | | |___    | |  
    \\_/\\_/   |___||_____|   |_|  
{Renkler.SIFIRLA}
{Renkler.SARI}  evil twin eğitim aracı v{SURUM}{Renkler.SIFIRLA}
{Renkler.KIRMIZI}  yalnızca eğitim amaçlıdır!{Renkler.SIFIRLA}
"""
    print(banner)


def log_dizini_olustur():
    """kayıt dizinini oluşturur."""

    betik_dizini = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    kayit_dizini = os.path.join(betik_dizini, 'kayitlar')

    if not os.path.exists(kayit_dizini):
        os.makedirs(kayit_dizini)
        print(f"{Renkler.YESIL}[+] kayıt dizini oluşturuldu: {kayit_dizini}{Renkler.SIFIRLA}")

    return kayit_dizini
