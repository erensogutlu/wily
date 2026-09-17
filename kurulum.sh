#!/bin/bash
# -*- coding: utf-8 -*-

# wily kurulum betiği

# betik dizini
BETIK_DIZINI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# renk kodları
KIRMIZI='\033[0;31m'
YESIL='\033[0;32m'
SARI='\033[1;33m'
MAVI='\033[0;34m'
SIFIRLA='\033[0m'

# başlık
echo -e "${MAVI}"
echo "╔══════════════════════════════════════╗"
echo "║          Wily Kurulum Betiği         ║"
echo "╚══════════════════════════════════════╝"
echo -e "${SIFIRLA}"

# root kontrolü
if [ "$EUID" -ne 0 ]; then
    echo -e "${KIRMIZI}[!] bu betiği root olarak çalıştırmalısınız.${SIFIRLA}"
    echo -e "${SARI}    sudo bash kurulum.sh${SIFIRLA}"
    exit 1
fi

echo -e "${MAVI}[*] sistem güncelleniyor...${SIFIRLA}"
apt update -y
if [ $? -ne 0 ]; then
    echo -e "${KIRMIZI}[!] sistem güncellemesi başarısız.${SIFIRLA}"
    exit 1
fi

echo -e "${MAVI}[*] gerekli paketler kuruluyor...${SIFIRLA}"
apt install -y hostapd dnsmasq aircrack-ng python3-pip
if [ $? -ne 0 ]; then
    echo -e "${KIRMIZI}[!] paket kurulumu başarısız.${SIFIRLA}"
    exit 1
fi

echo -e "${MAVI}[*] python bağımlılıkları kuruluyor...${SIFIRLA}"
apt install -y python3-scapy
if [ $? -ne 0 ]; then
    echo -e "${KIRMIZI}[!] python bağımlılıkları kurulamadı.${SIFIRLA}"
    exit 1
fi

echo -e "${MAVI}[*] dosya izinleri ayarlanıyor...${SIFIRLA}"
chmod +x "${BETIK_DIZINI}/wily.py"

echo -e "${MAVI}[*] kayıt dizini oluşturuluyor...${SIFIRLA}"
mkdir -p "${BETIK_DIZINI}/kayitlar"

echo ""
echo -e "${YESIL}╔══════════════════════════════════════╗${SIFIRLA}"
echo -e "${YESIL}║      kurulum başarıyla tamamlandı!   ║${SIFIRLA}"
echo -e "${YESIL}╚══════════════════════════════════════╝${SIFIRLA}"
echo ""
echo -e "${SARI}kullanım: sudo python3 wily.py${SIFIRLA}"
echo ""
