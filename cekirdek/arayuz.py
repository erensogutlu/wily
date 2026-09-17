#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# wily - evil twin arayüz yönetim modülü

import subprocess
import re

from .yapilandirma import Renkler


class ArayuzYoneticisi:
    """kablosuz ağ arayüzü yönetim sınıfı."""

    def __init__(self):
        """arayüz yöneticisini başlatır."""
        self.secili_arayuz = None
        self.monitor_arayuz = None
        self.orijinal_arayuz = None

    def kablosuz_arayuzleri_listele(self):
        """kablosuz arayüzleri listeler."""
        arayuzler = []

        try:
            sonuc = subprocess.run(
                ['iwconfig'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )

            satirlar = sonuc.stdout.split('\n')
            tum_arayuzler = []

            for satir in satirlar:
                # kablosuz arayüz isimlerini eşleştir
                eslesme = re.match(r'^([a-zA-Z0-9_.-]+)\s+IEEE 802\.11', satir)
                if eslesme:
                    arayuz_adi = eslesme.group(1)
                    tum_arayuzler.append(arayuz_adi)

            # monitor moddaki arayüzleri ayır
            for arayuz in tum_arayuzler:
                if arayuz.endswith('mon'):
                    orijinal = re.sub(r'[\._-]?mon$', '', arayuz)
                    print(f"{Renkler.SARI}[*] {arayuz} zaten monitor modda tespit edildi{Renkler.SIFIRLA}")
                    self.monitor_arayuz = arayuz
                    self.orijinal_arayuz = orijinal
                    if orijinal not in arayuzler:
                        arayuzler.append(orijinal)
                else:
                    if arayuz not in arayuzler:
                        arayuzler.append(arayuz)

            if not arayuzler:
                print(f"{Renkler.KIRMIZI}[-] kablosuz arayüz bulunamadı!{Renkler.SIFIRLA}")
            else:
                print(f"{Renkler.YESIL}[+] bulunan kablosuz arayüzler:{Renkler.SIFIRLA}")
                for i, arayuz in enumerate(arayuzler):
                    durum = " (monitor modda)" if self.monitor_arayuz and arayuz == self.orijinal_arayuz else ""
                    print(f"    {Renkler.CYAN}[{i}]{Renkler.SIFIRLA} {arayuz}{Renkler.SARI}{durum}{Renkler.SIFIRLA}")

        except FileNotFoundError:
            print(f"{Renkler.KIRMIZI}[-] iwconfig bulunamadı! wireless-tools yüklü mü?{Renkler.SIFIRLA}")
        except Exception as hata:
            print(f"{Renkler.KIRMIZI}[-] arayüz listeleme hatası: {hata}{Renkler.SIFIRLA}")

        return arayuzler

    def arayuz_sec(self, arayuz_adi):
        """belirtilen arayüzü seçer."""
        self.secili_arayuz = arayuz_adi
        if arayuz_adi.endswith("mon"):
            self.monitor_arayuz = arayuz_adi
            if not self.orijinal_arayuz or self.orijinal_arayuz.endswith("mon"):
                self.orijinal_arayuz = arayuz_adi[:-3]
        else:
            if not self.monitor_arayuz:
                self.orijinal_arayuz = arayuz_adi

        print(f"{Renkler.YESIL}[+] arayüz seçildi: {arayuz_adi}{Renkler.SIFIRLA}")

    def arayuz_ac(self, arayuz_adi=None):
        """arayüzü aktif duruma getirir."""
        hedef = arayuz_adi or self.monitor_arayuz or self.secili_arayuz
        if not hedef:
            return False

        try:
            subprocess.run(
                ['ip', 'link', 'set', hedef, 'up'],
                capture_output=True,
                text=True
            )
            return True
        except Exception as hata:
            print(f"{Renkler.KIRMIZI}[-] arayüz açma hatası: {hata}{Renkler.SIFIRLA}")
            return False

    def monitor_modu_baslat(self):
        """monitor modunu başlatır."""
        if not self.secili_arayuz:
            print(f"{Renkler.KIRMIZI}[-] önce bir arayüz seçin!{Renkler.SIFIRLA}")
            return False

        # zaten monitor moddaysa atla
        if self.monitor_arayuz:
            print(f"{Renkler.YESIL}[+] arayüz zaten monitor modda: {self.monitor_arayuz}{Renkler.SIFIRLA}")
            self.arayuz_ac(self.monitor_arayuz)
            return True

        try:
            # çakışan süreçleri durdur
            print(f"{Renkler.SARI}[*] çakışan süreçler durduruluyor...{Renkler.SIFIRLA}")
            subprocess.run(
                ['airmon-ng', 'check', 'kill'],
                capture_output=True,
                text=True
            )

            # monitor modu başlat
            print(f"{Renkler.SARI}[*] monitor modu başlatılıyor: {self.secili_arayuz}{Renkler.SIFIRLA}")
            sonuc = subprocess.run(
                ['airmon-ng', 'start', self.secili_arayuz],
                capture_output=True,
                text=True
            )

            # monitor arayüz adını tespit et
            monitor_adi = self.secili_arayuz + 'mon'

            eslesme = re.search(
                r'\(monitor mode.*enabled on ([a-zA-Z0-9_.-]+)\)',
                sonuc.stdout
            )
            if eslesme:
                monitor_adi = eslesme.group(1)
            else:
                # iwconfig ile kontrol et
                iw_sonuc = subprocess.run(['iwconfig'], capture_output=True, text=True)
                # doğrudan monitor moda geçtiyse
                if f"{self.secili_arayuz} " in iw_sonuc.stdout and "Mode:Monitor" in iw_sonuc.stdout:
                    monitor_adi = self.secili_arayuz
                else:
                    # aktif monitor arayüzü ara
                    monitor_eslesme = re.search(r'^([a-zA-Z0-9_.-]+)\s+IEEE 802\.11.*Mode:Monitor', iw_sonuc.stdout, re.MULTILINE)
                    if monitor_eslesme:
                        monitor_adi = monitor_eslesme.group(1)

            self.monitor_arayuz = monitor_adi
            self.arayuz_ac(self.monitor_arayuz)
            print(f"{Renkler.YESIL}[+] monitor modu aktif: {self.monitor_arayuz}{Renkler.SIFIRLA}")
            return True

        except FileNotFoundError:
            print(f"{Renkler.KIRMIZI}[-] airmon-ng bulunamadı! aircrack-ng yüklü mü?{Renkler.SIFIRLA}")
            return False
        except Exception as hata:
            print(f"{Renkler.KIRMIZI}[-] monitor modu hatası: {hata}{Renkler.SIFIRLA}")
            return False

    def monitor_modu_durdur(self):
        """monitor modunu durdurur."""
        if not self.monitor_arayuz:
            print(f"{Renkler.KIRMIZI}[-] aktif monitor arayüzü yok!{Renkler.SIFIRLA}")
            return False

        try:
            print(f"{Renkler.SARI}[*] monitor modu durduruluyor: {self.monitor_arayuz}{Renkler.SIFIRLA}")
            sonuc = subprocess.run(
                ['airmon-ng', 'stop', self.monitor_arayuz],
                capture_output=True,
                text=True
            )

            if sonuc.returncode == 0:
                print(f"{Renkler.YESIL}[+] monitor modu durduruldu{Renkler.SIFIRLA}")
                self.monitor_arayuz = None
                return True
            else:
                # monitor mod sonlandırıldı
                self.monitor_arayuz = None
                print(f"{Renkler.YESIL}[+] monitor modu sonlandırıldı{Renkler.SIFIRLA}")
                return True

        except Exception as hata:
            print(f"{Renkler.KIRMIZI}[-] monitor durdurma hatası: {hata}{Renkler.SIFIRLA}")
            return False

    def arayuz_durumunu_kontrol_et(self):
        """arayüzün aktifliğini kontrol eder."""
        kontrol_arayuz = self.monitor_arayuz or self.secili_arayuz

        if not kontrol_arayuz:
            print(f"{Renkler.KIRMIZI}[-] kontrol edilecek arayüz yok!{Renkler.SIFIRLA}")
            return False

        try:
            sonuc = subprocess.run(
                ['ip', 'link', 'show', kontrol_arayuz],
                capture_output=True,
                text=True
            )

            if sonuc.returncode == 0:
                # up durumunu kontrol et
                if 'UP' in sonuc.stdout:
                    print(f"{Renkler.YESIL}[+] arayüz aktif: {kontrol_arayuz}{Renkler.SIFIRLA}")
                    return True
                else:
                    print(f"{Renkler.SARI}[!] arayüz mevcut ama aktif değil: {kontrol_arayuz}{Renkler.SIFIRLA}")
                    return False
            else:
                print(f"{Renkler.KIRMIZI}[-] arayüz bulunamadı: {kontrol_arayuz}{Renkler.SIFIRLA}")
                return False

        except Exception as hata:
            print(f"{Renkler.KIRMIZI}[-] durum kontrol hatası: {hata}{Renkler.SIFIRLA}")
            return False

    def network_manager_durdur(self):
        """networkmanager servisini durdurur."""
        try:
            print(f"{Renkler.SARI}[*] networkmanager durduruluyor...{Renkler.SIFIRLA}")
            subprocess.run(
                ['systemctl', 'stop', 'NetworkManager'],
                capture_output=True,
                text=True
            )
            print(f"{Renkler.YESIL}[+] networkmanager durduruldu{Renkler.SIFIRLA}")

        except Exception as hata:
            print(f"{Renkler.KIRMIZI}[-] networkmanager durdurma hatası: {hata}{Renkler.SIFIRLA}")

    def network_manager_baslat(self):
        """networkmanager servisini başlatır."""
        try:
            print(f"{Renkler.SARI}[*] networkmanager başlatılıyor...{Renkler.SIFIRLA}")
            subprocess.run(
                ['systemctl', 'start', 'NetworkManager'],
                capture_output=True,
                text=True
            )
            print(f"{Renkler.YESIL}[+] networkmanager başlatıldı{Renkler.SIFIRLA}")

        except Exception as hata:
            print(f"{Renkler.KIRMIZI}[-] networkmanager başlatma hatası: {hata}{Renkler.SIFIRLA}")

    def temizle(self):
        """yapılan değişiklikleri geri alır."""
        print(f"{Renkler.SARI}[*] arayüz temizleniyor...{Renkler.SIFIRLA}")

        # monitor modu durdur
        if self.monitor_arayuz:
            self.monitor_modu_durdur()

        # networkmanager servisini başlat
        self.network_manager_baslat()

        # değişkenleri sıfırla
        self.secili_arayuz = self.orijinal_arayuz
        self.monitor_arayuz = None

        print(f"{Renkler.YESIL}[+] arayüz temizlendi{Renkler.SIFIRLA}")
