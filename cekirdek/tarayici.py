#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""kablosuz ağ tarayıcı modülü."""

import subprocess
import threading
import time

# pyrefly: ignore [missing-import]
from scapy.all import (
    sniff,
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    RadioTap
)


class AgTarayici:
    """kablosuz ağ tarayıcı sınıfı."""

    # renkler
    SIFIRLA = "\033[0m"
    YESIL = "\033[92m"
    MAVI = "\033[94m"
    SARI = "\033[93m"
    KIRMIZI = "\033[91m"
    KALIN = "\033[1m"
    CYAN = "\033[96m"

    def __init__(self, arayuz):
        """tarayıcıyı başlatır."""
        self.arayuz = arayuz
        self.erisim_noktalari = []
        self.istemciler = []
        self.tarama_aktif = False
        self._tarama_ipligi = None
        self._kilit = threading.Lock()
        self._paket_sayaci = 0

    def _paket_isle(self, paket):
        """yakalanan paketleri işler."""
        if not self.tarama_aktif:
            return

        # beacon frame kontrolü
        if paket.haslayer(Dot11Beacon):
            self._ap_bilgisi_cikar(paket)

        # probe request ve data frame kontrolü
        elif paket.haslayer(Dot11):
            dot11_katmani = paket.getlayer(Dot11)
            tip = dot11_katmani.type
            alt_tip = dot11_katmani.subtype

            # probe request
            if tip == 0 and alt_tip == 4:
                self._istemci_bilgisi_cikar(paket)

            # data frame
            elif tip == 2:
                self._istemci_bilgisi_cikar(paket)

    def _ap_bilgisi_cikar(self, paket):
        """beacon paketinden ap bilgilerini çıkarır."""
        try:
            bssid = paket[Dot11].addr2
            if bssid is None:
                return

            bssid = bssid.upper()

            # ssid bilgisini al
            ssid = ""
            elt_katmani = paket.getlayer(Dot11Elt)
            while elt_katmani:
                if elt_katmani.ID == 0:
                    try:
                        raw_info = elt_katmani.info
                        if raw_info is None:
                            ssid = "<gizli>"
                        elif isinstance(raw_info, bytes):
                            ssid = raw_info.decode("utf-8", errors="replace").replace("\x00", "").strip()
                        else:
                            ssid = str(raw_info).replace("\x00", "").strip()
                    except Exception:
                        ssid = "<gizli>"
                    break
                elt_katmani = elt_katmani.payload.getlayer(Dot11Elt) if hasattr(elt_katmani, 'payload') and elt_katmani.payload else None

            if not ssid:
                ssid = "<gizli>"

            # kanal bilgisini al
            kanal = self._kanal_bilgisi_al(paket)

            # sinyal gücünü al
            sinyal = self._sinyal_gucu_al(paket)

            # şifreleme türünü belirle
            sifreleme = self._sifreleme_belirle(paket)

            ap_bilgisi = {
                "ssid": ssid,
                "bssid": bssid,
                "kanal": kanal,
                "sinyal": sinyal,
                "sifreleme": sifreleme
            }

            # ap listesini güncelle
            with self._kilit:
                mevcut = False
                for i, ap in enumerate(self.erisim_noktalari):
                    if ap["bssid"] == bssid:
                        self.erisim_noktalari[i] = ap_bilgisi
                        mevcut = True
                        break

                if not mevcut:
                    self.erisim_noktalari.append(ap_bilgisi)

        except Exception:
            pass

    def _istemci_bilgisi_cikar(self, paket):
        """istemci bilgilerini çıkarır."""
        try:
            dot11_katmani = paket.getlayer(Dot11)
            if not dot11_katmani:
                return

            # kaynak mac adresi
            istemci_mac = dot11_katmani.addr2
            if istemci_mac is None:
                return

            istemci_mac = istemci_mac.upper()

            # broadcast ve multicast adreslerini atla
            if istemci_mac == "FF:FF:FF:FF:FF:FF":
                return
            if istemci_mac.startswith("01:") or istemci_mac.startswith("33:33:"):
                return

            # bağlı bssid tespiti
            bssid = dot11_katmani.addr1
            if bssid is not None:
                bssid = bssid.upper()

                # data frame kontrolü
                if dot11_katmani.type == 2:
                    fc = getattr(dot11_katmani, 'FCfield', 0)
                    if fc is not None:
                        ds_durumu = int(fc) & 0x3
                        if ds_durumu == 0x1:  # to-ds
                            bssid = dot11_katmani.addr1.upper() if dot11_katmani.addr1 else None
                        elif ds_durumu == 0x2:  # from-ds
                            bssid = dot11_katmani.addr2.upper() if dot11_katmani.addr2 else None
                            if dot11_katmani.addr1:
                                istemci_mac = dot11_katmani.addr1.upper()
            else:
                bssid = "bilinmiyor"

            # sinyal gücünü al
            sinyal = self._sinyal_gucu_al(paket)

            istemci_bilgisi = {
                "mac": istemci_mac,
                "bssid": bssid if bssid else "bilinmiyor",
                "sinyal": sinyal
            }

            # istemci listesini güncelle
            with self._kilit:
                mevcut = False
                for i, istemci in enumerate(self.istemciler):
                    if istemci["mac"] == istemci_mac:
                        self.istemciler[i] = istemci_bilgisi
                        mevcut = True
                        break

                if not mevcut:
                    self.istemciler.append(istemci_bilgisi)

        except Exception:
            pass

    def _kanal_bilgisi_al(self, paket):
        """paketten kanal bilgisini çıkarır."""
        try:
            elt_katmani = paket.getlayer(Dot11Elt)
            while elt_katmani:
                if elt_katmani.ID == 3:
                    info = elt_katmani.info
                    if isinstance(info, bytes) and len(info) >= 1:
                        return info[0]
                    elif isinstance(info, int):
                        return info
                elt_katmani = elt_katmani.payload.getlayer(Dot11Elt) if hasattr(elt_katmani, 'payload') and elt_katmani.payload else None
        except Exception:
            pass

        return 0

    def _sinyal_gucu_al(self, paket):
        """paketten sinyal gücünü çıkarır."""
        try:
            if paket.haslayer(RadioTap):
                radyo_katmani = paket.getlayer(RadioTap)
                if hasattr(radyo_katmani, "dBm_AntSignal"):
                    val = radyo_katmani.dBm_AntSignal
                    if val is not None and isinstance(val, (int, float)):
                        return int(val)
        except Exception:
            pass

        return -100

    def _sifreleme_belirle(self, paket):
        """şifreleme türünü belirler."""
        try:
            # gizlilik kontrolü
            yetenek = paket[Dot11Beacon].cap
            gizlilik = bool(yetenek & 0x10)

            if not gizlilik:
                return "AÇIK"

            # rsn ve wpa kontrolü
            rsn_bulundu = False
            wpa_bulundu = False

            elt_katmani = paket.getlayer(Dot11Elt)
            while elt_katmani:
                if elt_katmani.ID == 48:
                    rsn_bulundu = True
                    break

                if elt_katmani.ID == 221:
                    oui = elt_katmani.info[:4] if len(elt_katmani.info) >= 4 else b""
                    if oui == b"\x00\x50\xf2\x01":
                        wpa_bulundu = True

                elt_katmani = elt_katmani.payload.getlayer(Dot11Elt)

            if rsn_bulundu:
                return "WPA2"
            elif wpa_bulundu:
                return "WPA"
            else:
                return "WEP"

        except Exception:
            return "bilinmiyor"

    def tarama_baslat(self, sure=30):
        """ağ taramasını başlatır."""
        self.tarama_aktif = True
        self._paket_sayaci = 0

        print(
            f"\n{self.YESIL}[*]{self.SIFIRLA} tarama başlatılıyor... "
            f"(arayüz: {self.CYAN}{self.arayuz}{self.SIFIRLA}, "
            f"süre: {self.CYAN}{sure}s{self.SIFIRLA})"
        )

        def tarama_gorevi():
            """tarama iş parçacığı görevi."""
            try:
                sniff(
                    iface=self.arayuz,
                    prn=self._paket_sayaci_isle,
                    timeout=sure,
                    store=False,
                    stop_filter=lambda p: not self.tarama_aktif
                )
            except Exception as hata:
                print(f"\n{self.KIRMIZI}[!] tarama hatası: {hata}{self.SIFIRLA}")
            finally:
                self.tarama_aktif = False

        self._tarama_ipligi = threading.Thread(
            target=tarama_gorevi,
            daemon=True,
            name="ag_tarama"
        )
        self._tarama_ipligi.start()

        # taramanın bitmesini bekle
        self._tarama_ipligi.join(timeout=sure + 5)

    def tarama_durdur(self):
        """taramayı durdurur."""
        self.tarama_aktif = False

        if self._tarama_ipligi and self._tarama_ipligi.is_alive():
            self._tarama_ipligi.join(timeout=3)

        print(f"\n{self.SARI}[*] tarama durduruldu.{self.SIFIRLA}")

    def erisim_noktalarini_goster(self):
        """bulunan erişim noktalarını gösterir."""
        with self._kilit:
            # sinyal gücüne göre sırala
            self.erisim_noktalari.sort(key=lambda ap: ap["sinyal"], reverse=True)
            ap_listesi = list(self.erisim_noktalari)

        if not ap_listesi:
            print(f"\n{self.SARI}[!] henüz erişim noktası bulunamadı.{self.SIFIRLA}")
            return []

        # tablo başlığı
        print(f"\n{self.KALIN}{self.MAVI}{'=' * 78}{self.SIFIRLA}")
        print(f"{self.KALIN}{self.MAVI}  bulunan erişim noktaları ({len(ap_listesi)} adet){self.SIFIRLA}")
        print(f"{self.KALIN}{self.MAVI}{'=' * 78}{self.SIFIRLA}")

        # sütun başlıkları
        baslik = (
            f"  {self.KALIN}{'No':<5}"
            f"{'SSID':<25}"
            f"{'BSSID':<20}"
            f"{'Kanal':<8}"
            f"{'Sinyal':<10}"
            f"{'Şifreleme':<12}{self.SIFIRLA}"
        )
        print(baslik)
        print(f"  {'-' * 75}")

        # satırları yazdır
        for sira, ap in enumerate(ap_listesi, 1):
            sinyal = ap["sinyal"]
            if sinyal >= -50:
                sinyal_renk = self.YESIL
            elif sinyal >= -70:
                sinyal_renk = self.SARI
            else:
                sinyal_renk = self.KIRMIZI

            sifreleme = ap["sifreleme"]
            if sifreleme == "AÇIK":
                sifreleme_renk = self.YESIL
            elif sifreleme == "WEP":
                sifreleme_renk = self.SARI
            else:
                sifreleme_renk = self.KIRMIZI

            ssid_gosterim = ap["ssid"][:23] if len(ap["ssid"]) > 23 else ap["ssid"]

            satir = (
                f"  {self.CYAN}{sira:<5}{self.SIFIRLA}"
                f"{ssid_gosterim:<25}"
                f"{ap['bssid']:<20}"
                f"{ap['kanal']:<8}"
                f"{sinyal_renk}{sinyal} dBm{self.SIFIRLA}{'':>3}"
                f"{sifreleme_renk}{sifreleme:<12}{self.SIFIRLA}"
            )
            print(satir)

        print(f"  {'-' * 75}\n")
        return ap_listesi

    def istemcileri_goster(self, hedef_bssid):
        """bağlı istemcileri gösterir."""
        hedef_bssid = hedef_bssid.upper()

        with self._kilit:
            bagli_istemciler = [
                istemci for istemci in self.istemciler
                if istemci["bssid"] == hedef_bssid
            ]

        if not bagli_istemciler:
            print(
                f"\n{self.SARI}[!] {hedef_bssid} adresine bağlı istemci bulunamadı.{self.SIFIRLA}"
            )
            return

        # sinyal gücüne göre sırala
        bagli_istemciler.sort(key=lambda i: i["sinyal"], reverse=True)

        # tablo başlığı
        print(f"\n{self.KALIN}{self.MAVI}{'=' * 55}{self.SIFIRLA}")
        print(
            f"{self.KALIN}{self.MAVI}  bağlı istemciler - "
            f"{hedef_bssid} ({len(bagli_istemciler)} adet){self.SIFIRLA}"
        )
        print(f"{self.KALIN}{self.MAVI}{'=' * 55}{self.SIFIRLA}")

        # sütun başlıkları
        baslik = (
            f"  {self.KALIN}{'No':<5}"
            f"{'İstemci MAC':<22}"
            f"{'Sinyal':<12}{self.SIFIRLA}"
        )
        print(baslik)
        print(f"  {'-' * 50}")

        # satırları yazdır
        for sira, istemci in enumerate(bagli_istemciler, 1):
            sinyal = istemci["sinyal"]
            if sinyal >= -50:
                sinyal_renk = self.YESIL
            elif sinyal >= -70:
                sinyal_renk = self.SARI
            else:
                sinyal_renk = self.KIRMIZI

            satir = (
                f"  {self.CYAN}{sira:<5}{self.SIFIRLA}"
                f"{istemci['mac']:<22}"
                f"{sinyal_renk}{sinyal} dBm{self.SIFIRLA}"
            )
            print(satir)

        print(f"  {'-' * 50}\n")

    def kanal_degistir(self, kanal):
        """kablosuz arayüzün kanalını değiştirir."""
        try:
            subprocess.run(
                ["iwconfig", self.arayuz, "channel", str(kanal)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError:
            pass

    def tum_kanallari_tara(self, sure=30):
        """tüm kanalları sırayla tarar."""
        self.tarama_aktif = True
        self._paket_sayaci = 0

        print(
            f"\n{self.YESIL}[*]{self.SIFIRLA} tüm kanallar taranıyor... "
            f"(süre: {self.CYAN}{sure}s{self.SIFIRLA})"
        )

        def kanal_degistirme_gorevi():
            """kanallar arası geçiş yapar."""
            kanal = 1
            while self.tarama_aktif:
                self.kanal_degistir(kanal)
                kanal = (kanal % 14) + 1
                time.sleep(0.5)

        def paket_yakalama_gorevi():
            """paketleri yakalar."""
            try:
                sniff(
                    iface=self.arayuz,
                    prn=self._paket_sayaci_isle,
                    timeout=sure,
                    store=False,
                    stop_filter=lambda p: not self.tarama_aktif
                )
            except PermissionError as hata:
                print(f"\n{self.KIRMIZI}[!] izin hatası: {hata}{self.SIFIRLA}")
                print(f"{self.SARI}[*] root yetkisiyle çalıştırdığınızdan emin olun.{self.SIFIRLA}")
            except OSError as hata:
                print(f"\n{self.KIRMIZI}[!] arayüz hatası: {hata}{self.SIFIRLA}")
                print(f"{self.SARI}[*] arayüzün monitor modda olduğundan emin olun.{self.SIFIRLA}")
            except Exception as hata:
                print(f"\n{self.KIRMIZI}[!] tarama hatası: {hata}{self.SIFIRLA}")
            finally:
                self.tarama_aktif = False

        def durum_gorevi():
            """tarama durumunu gösterir."""
            while self.tarama_aktif:
                time.sleep(5)
                if self.tarama_aktif:
                    with self._kilit:
                        ap_sayisi = len(self.erisim_noktalari)
                    print(
                        f"  {self.SARI}[~] yakalanan paket: {self._paket_sayaci} | "
                        f"bulunan ap: {ap_sayisi}{self.SIFIRLA}"
                    )

        # kanal değiştirme iş parçacığı
        kanal_ipligi = threading.Thread(
            target=kanal_degistirme_gorevi,
            daemon=True,
            name="kanal_degistir"
        )

        # paket yakalama iş parçacığı
        self._tarama_ipligi = threading.Thread(
            target=paket_yakalama_gorevi,
            daemon=True,
            name="paket_yakala"
        )

        # durum iş parçacığı
        durum_ipligi = threading.Thread(
            target=durum_gorevi,
            daemon=True,
            name="durum_goster"
        )

        kanal_ipligi.start()
        self._tarama_ipligi.start()
        durum_ipligi.start()

    def _paket_sayaci_isle(self, paket):
        """paket sayacını artırır ve paketi işler."""
        with self._kilit:
            self._paket_sayaci += 1
        self._paket_isle(paket)
