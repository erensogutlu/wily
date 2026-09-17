#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""sahte erişim noktası modülü."""

import subprocess
import os
import signal
import time

from .yapilandirma import (
    HOSTAPD_SABLON,
    DNSMASQ_SABLON,
    HOSTAPD_YAPILANDIRMA_YOLU,
    DNSMASQ_YAPILANDIRMA_YOLU,
    VARSAYILAN_AG_GECIDI,
    VARSAYILAN_ALT_AG_MASKESI,
    DHCP_ARALIK_BASLANGIC,
    DHCP_ARALIK_BITIS,
    DNS_SUNUCU,
    Renkler
)


class SahteErisimNoktasi:
    """sahte erişim noktası yönetim sınıfı."""

    def __init__(self, arayuz, ssid, kanal=6):
        """sahte erişim noktasını başlatır."""
        self.arayuz = arayuz
        self.ssid = ssid
        self.kanal = kanal
        self.hostapd_surec = None
        self.dnsmasq_surec = None
        self.aktif = False

    def yapilandirma_olustur(self):
        """hostapd ve dnsmasq yapılandırmalarını oluşturur."""
        # hostapd yapılandırması
        hostapd_icerik = HOSTAPD_SABLON.format(
            arayuz=self.arayuz,
            ssid=self.ssid,
            kanal=self.kanal
        )

        with open(HOSTAPD_YAPILANDIRMA_YOLU, 'w') as dosya:
            dosya.write(hostapd_icerik)

        print("{}[*] hostapd yapılandırması oluşturuldu: {}{}".format(
            Renkler.MAVI, HOSTAPD_YAPILANDIRMA_YOLU, Renkler.SIFIRLA
        ))

        # dnsmasq yapılandırması
        dnsmasq_icerik = DNSMASQ_SABLON.format(
            arayuz=self.arayuz,
            dhcp_baslangic=DHCP_ARALIK_BASLANGIC,
            dhcp_bitis=DHCP_ARALIK_BITIS,
            alt_ag_maskesi=VARSAYILAN_ALT_AG_MASKESI,
            ag_gecidi=VARSAYILAN_AG_GECIDI,
            dns_sunucu=DNS_SUNUCU,
        )

        with open(DNSMASQ_YAPILANDIRMA_YOLU, 'w') as dosya:
            dosya.write(dnsmasq_icerik)

        print("{}[*] dnsmasq yapılandırması oluşturuldu: {}{}".format(
            Renkler.MAVI, DNSMASQ_YAPILANDIRMA_YOLU, Renkler.SIFIRLA
        ))

    def _arayuz_yapilandir(self):
        """ağ arayüzünü yapılandırır."""
        komutlar = [
            ['ip', 'link', 'set', self.arayuz, 'down'],
            ['ip', 'addr', 'flush', 'dev', self.arayuz],
            ['ip', 'addr', 'add', '{}/24'.format(VARSAYILAN_AG_GECIDI), 'dev', self.arayuz],
            ['ip', 'link', 'set', self.arayuz, 'up']
        ]

        for komut in komutlar:
            try:
                subprocess.run(komut, check=True, capture_output=True)
            except subprocess.CalledProcessError as hata:
                print("{}[!] arayüz yapılandırma hatası: {} - {}{}".format(
                    Renkler.KIRMIZI, ' '.join(komut), hata, Renkler.SIFIRLA
                ))
                return False

        print("{}[*] arayüz yapılandırıldı: {} -> {}{}".format(
            Renkler.YESIL, self.arayuz, VARSAYILAN_AG_GECIDI, Renkler.SIFIRLA
        ))
        return True

    def _iptables_ayarla(self, internet_arayuzu='eth0'):
        """iptables kurallarını ayarlar."""
        # ip yönlendirmeyi devre dışı bırak
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as dosya:
                dosya.write('0')
            print("{}[*] ip yönlendirme devre dışı (tam izolasyon){}".format(
                Renkler.YESIL, Renkler.SIFIRLA
            ))
        except IOError as hata:
            print("{}[!] ip yönlendirme ayarlanamadı: {}{}".format(
                Renkler.KIRMIZI, hata, Renkler.SIFIRLA
            ))
            return False

        komutlar = [
            # 1. mevcut kuralları temizle
            ['iptables', '--flush'],
            ['iptables', '--table', 'nat', '--flush'],
            ['iptables', '--delete-chain'],
            ['iptables', '--table', 'nat', '--delete-chain'],

            # 2. varsayılan politikalar
            ['iptables', '-P', 'INPUT', 'DROP'],
            ['iptables', '-P', 'FORWARD', 'DROP'],
            ['iptables', '-P', 'OUTPUT', 'DROP'],

            # 3. loopback trafiği
            ['iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'],
            ['iptables', '-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'],

            # 4. bağlantı durumu trafiği
            ['iptables', '-A', 'INPUT', '-m', 'state', '--state',
             'ESTABLISHED,RELATED', '-j', 'ACCEPT'],
            ['iptables', '-A', 'OUTPUT', '-m', 'state', '--state',
             'ESTABLISHED,RELATED', '-j', 'ACCEPT'],

            # 5. dhcp trafiği
            ['iptables', '-A', 'INPUT', '-i', self.arayuz,
             '-p', 'udp', '--dport', '67', '-j', 'ACCEPT'],
            ['iptables', '-A', 'OUTPUT', '-o', self.arayuz,
             '-p', 'udp', '--sport', '67', '-j', 'ACCEPT'],
            ['iptables', '-A', 'OUTPUT', '-o', self.arayuz,
             '-p', 'udp', '--dport', '68', '-j', 'ACCEPT'],

            # 6. dns trafiği
            ['iptables', '-A', 'INPUT', '-i', self.arayuz,
             '-p', 'udp', '--dport', '53', '-j', 'ACCEPT'],
            ['iptables', '-A', 'INPUT', '-i', self.arayuz,
             '-p', 'tcp', '--dport', '53', '-j', 'ACCEPT'],
            ['iptables', '-A', 'OUTPUT', '-o', self.arayuz,
             '-p', 'udp', '--sport', '53', '-j', 'ACCEPT'],
            ['iptables', '-A', 'OUTPUT', '-o', self.arayuz,
             '-p', 'tcp', '--sport', '53', '-j', 'ACCEPT'],

            # 7. http trafiği
            ['iptables', '-A', 'INPUT', '-i', self.arayuz,
             '-p', 'tcp', '--dport', '80', '-j', 'ACCEPT'],
            ['iptables', '-A', 'OUTPUT', '-o', self.arayuz,
             '-p', 'tcp', '--sport', '80', '-j', 'ACCEPT'],

            # 8. icmp trafiği
            ['iptables', '-A', 'INPUT', '-i', self.arayuz,
             '-p', 'icmp', '-j', 'ACCEPT'],
            ['iptables', '-A', 'OUTPUT', '-o', self.arayuz,
             '-p', 'icmp', '-j', 'ACCEPT'],

            # 9. nat yönlendirmeleri
            # dns trafiği yönlendirmesi
            ['iptables', '-t', 'nat', '-A', 'PREROUTING', '-i', self.arayuz,
             '-p', 'udp', '--dport', '53', '-j', 'DNAT',
             '--to-destination', '{}:53'.format(VARSAYILAN_AG_GECIDI)],
            # http trafiği yönlendirmesi
            ['iptables', '-t', 'nat', '-A', 'PREROUTING', '-i', self.arayuz,
             '-p', 'tcp', '--dport', '80', '-j', 'DNAT',
             '--to-destination', '{}:80'.format(VARSAYILAN_AG_GECIDI)],
            # https trafiği yönlendirmesi
            ['iptables', '-t', 'nat', '-A', 'PREROUTING', '-i', self.arayuz,
             '-p', 'tcp', '--dport', '443', '-j', 'DNAT',
             '--to-destination', '{}:80'.format(VARSAYILAN_AG_GECIDI)],
        ]

        for komut in komutlar:
            try:
                subprocess.run(komut, check=True, capture_output=True)
            except subprocess.CalledProcessError as hata:
                print("{}[!] iptables hatası: {} - {}{}".format(
                    Renkler.KIRMIZI, ' '.join(komut), hata, Renkler.SIFIRLA
                ))
                return False

        print("{}[*] iptables kuralları ayarlandı (tam izolasyon — internet erişimi kapalı){}".format(
            Renkler.YESIL, Renkler.SIFIRLA
        ))
        return True

    def baslat(self, internet_arayuzu='eth0'):
        """sahte erişim noktasını başlatır."""
        if self.aktif:
            print("{}[!] sahte erişim noktası zaten çalışıyor{}".format(
                Renkler.SARI, Renkler.SIFIRLA
            ))
            return False

        print("{}[*] sahte erişim noktası başlatılıyor...{}".format(
            Renkler.MAVI, Renkler.SIFIRLA
        ))

        # yapılandırma dosyalarını oluştur
        self.yapilandirma_olustur()

        # arayüzü yapılandır
        if not self._arayuz_yapilandir():
            return False

        # iptables kurallarını ayarla
        if not self._iptables_ayarla(internet_arayuzu):
            return False

        # hostapd sürecini başlat
        try:
            self.hostapd_surec = subprocess.Popen(
                ['hostapd', HOSTAPD_YAPILANDIRMA_YOLU],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            time.sleep(2)

            if self.hostapd_surec.poll() is not None:
                hata_cikti = self.hostapd_surec.stderr.read() if self.hostapd_surec.stderr else ""
                print("{}[!] hostapd başlatılamadı: {}{}".format(
                    Renkler.KIRMIZI, hata_cikti.strip(), Renkler.SIFIRLA
                ))
                return False

            print("{}[+] hostapd başlatıldı (pid: {}){}".format(
                Renkler.YESIL, self.hostapd_surec.pid, Renkler.SIFIRLA
            ))
        except FileNotFoundError:
            print("{}[!] hostapd bulunamadı. lütfen kurun: apt install hostapd{}".format(
                Renkler.KIRMIZI, Renkler.SIFIRLA
            ))
            return False

        # dnsmasq servisini durdur
        try:
            subprocess.run(['systemctl', 'stop', 'dnsmasq'], capture_output=True)
        except Exception:
            pass

        # dnsmasq sürecini başlat
        try:
            self.dnsmasq_surec = subprocess.Popen(
                ['dnsmasq', '-C', DNSMASQ_YAPILANDIRMA_YOLU, '-d'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            time.sleep(1)

            if self.dnsmasq_surec.poll() is not None:
                hata_cikti = self.dnsmasq_surec.stderr.read() if self.dnsmasq_surec.stderr else ""
                print("{}[!] dnsmasq başlatılamadı: {}{}".format(
                    Renkler.KIRMIZI, hata_cikti.strip(), Renkler.SIFIRLA
                ))
                self.durdur()
                return False

            print("{}[+] dnsmasq başlatıldı (pid: {}){}".format(
                Renkler.YESIL, self.dnsmasq_surec.pid, Renkler.SIFIRLA
            ))
        except FileNotFoundError:
            print("{}[!] dnsmasq bulunamadı. lütfen kurun: apt install dnsmasq{}".format(
                Renkler.KIRMIZI, Renkler.SIFIRLA
            ))
            self.durdur()
            return False

        self.aktif = True
        print("{}[+] sahte erişim noktası aktif: '{}' (kanal: {}){}".format(
            Renkler.YESIL, self.ssid, self.kanal, Renkler.SIFIRLA
        ))
        return True

    def durdur(self):
        """sahte erişim noktasını durdurur."""
        print("{}[*] sahte erişim noktası durduruluyor...{}".format(
            Renkler.SARI, Renkler.SIFIRLA
        ))

        # hostapd sürecini durdur
        if self.hostapd_surec is not None:
            try:
                os.kill(self.hostapd_surec.pid, signal.SIGTERM)
                self.hostapd_surec.wait(timeout=5)
                print("{}[*] hostapd durduruldu{}".format(
                    Renkler.MAVI, Renkler.SIFIRLA
                ))
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.kill(self.hostapd_surec.pid, signal.SIGKILL)
                    self.hostapd_surec.wait(timeout=1)
                except Exception:
                    pass
            self.hostapd_surec = None

        # dnsmasq sürecini durdur
        if self.dnsmasq_surec is not None:
            try:
                os.kill(self.dnsmasq_surec.pid, signal.SIGTERM)
                self.dnsmasq_surec.wait(timeout=5)
                print("{}[*] dnsmasq durduruldu{}".format(
                    Renkler.MAVI, Renkler.SIFIRLA
                ))
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.kill(self.dnsmasq_surec.pid, signal.SIGKILL)
                    self.dnsmasq_surec.wait(timeout=1)
                except Exception:
                    pass
            self.dnsmasq_surec = None

        # iptables kurallarını temizle
        temizleme_komutlari = [
            ['iptables', '-P', 'INPUT', 'ACCEPT'],
            ['iptables', '-P', 'OUTPUT', 'ACCEPT'],
            ['iptables', '-P', 'FORWARD', 'ACCEPT'],
            ['iptables', '--flush'],
            ['iptables', '--table', 'nat', '--flush'],
            ['iptables', '--delete-chain'],
            ['iptables', '--table', 'nat', '--delete-chain'],
        ]

        for komut in temizleme_komutlari:
            try:
                subprocess.run(komut, capture_output=True)
            except Exception:
                pass

        # ip yönlendirmeyi kapat
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as dosya:
                dosya.write('0')
            print("{}[*] ip yönlendirme devre dışı bırakıldı{}".format(
                Renkler.MAVI, Renkler.SIFIRLA
            ))
        except IOError:
            pass

        # geçici dosyaları sil
        for gecici_dosya in [HOSTAPD_YAPILANDIRMA_YOLU, DNSMASQ_YAPILANDIRMA_YOLU]:
            if os.path.exists(gecici_dosya):
                try:
                    os.remove(gecici_dosya)
                    print("{}[*] geçici dosya silindi: {}{}".format(
                        Renkler.MAVI, gecici_dosya, Renkler.SIFIRLA
                    ))
                except OSError:
                    pass

        self.aktif = False
        print("{}[+] sahte erişim noktası durduruldu{}".format(
            Renkler.YESIL, Renkler.SIFIRLA
        ))

    def durum_kontrol(self):
        """süreçlerin durumunu kontrol eder."""
        durum = {
            'hostapd': False,
            'dnsmasq': False,
            'aktif': self.aktif
        }

        if self.hostapd_surec is not None:
            durum['hostapd'] = self.hostapd_surec.poll() is None

        if self.dnsmasq_surec is not None:
            durum['dnsmasq'] = self.dnsmasq_surec.poll() is None

        # durum bilgisini yazdır
        hostapd_durum = "{}çalışıyor{}".format(Renkler.YESIL, Renkler.SIFIRLA) \
            if durum['hostapd'] else "{}durdu{}".format(Renkler.KIRMIZI, Renkler.SIFIRLA)
        dnsmasq_durum = "{}çalışıyor{}".format(Renkler.YESIL, Renkler.SIFIRLA) \
            if durum['dnsmasq'] else "{}durdu{}".format(Renkler.KIRMIZI, Renkler.SIFIRLA)

        print("{}[*] sahte ap durumu:{}".format(Renkler.MAVI, Renkler.SIFIRLA))
        print("    ssid     : {}".format(self.ssid))
        print("    kanal    : {}".format(self.kanal))
        print("    arayüz   : {}".format(self.arayuz))
        print("    hostapd  : {}".format(hostapd_durum))
        print("    dnsmasq  : {}".format(dnsmasq_durum))

        return durum
