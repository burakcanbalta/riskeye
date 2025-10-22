# 🛡️ Riskeye – Network Risk & Port Scanner

Riskeye, GitHub için özel hazırlanmış profesyonel bir siber güvenlik aracıdır. Ağ üzerinde hızlı port taraması yapar, açık servisleri tanımlar ve bu servislerin risk seviyesini belirler. Gelişmiş özellikleri sayesinde CVE açıklamaları, MAC vendor bilgileri, HTML/JSON raporları ve Docker desteğiyle kolay dağıtımı bir araya getirir.

Bu araç, hem terminal hem de web arayüz üzerinden çalıştırılabilir. Eğitim, CTF ortamları, iç ağ analizleri ve port güvenliği değerlendirmeleri için idealdir.

---

## 🚀 Özellikler
- 🔍 IP veya CIDR üzerinden Nmap hızlı port taraması
- 📊 Port bazlı risk skorlama (LOW, MEDIUM, HIGH)
- 🔐 CVE uyarıları ve açıklamaları
- 🌐 Flask tabanlı modern web arayüz
- 🖥️ MAC adresinden cihaz vendor tespiti (ARP üzerinden)
- 📁 HTML ve JSON formatında otomatik raporlama
- 🐳 Docker ve bash script ile hızlı çalıştırma desteği

---

## 📦 Kurulum

### Python ile Çalıştırmak İçin:
```bash
pip install flask python-nmap
python riskeye.py
```

### Docker ile Çalıştırmak İçin:
```bash
# Normal başlatma
./run_docker.sh

# Sadece durum kontrolü
./run_docker.sh status

# Logları görüntüle
./run_docker.sh logs

# Durdur
./run_docker.sh stop

# Yeniden başlat
./run_docker.sh restart

docker-compose up -d
docker-compose logs -f

```
veya:
```bash
chmod +x run.sh
./run.sh
```

Tarayıcıdan erişim:
http://localhost:5000

---

## 📤 Örnek Raporlar
- exports/nmap_report_YYYYMMDD_HHMMSS.json
- exports/nmap_report_YYYYMMDD_HHMMSS.html

Demo raporlar için samples/ klasörünü inceleyin.

---

## 📁 Proje Yapısı
riskeye/
├── riskeye.py           # Ana Python uygulaması
├── Dockerfile           # Docker yapılandırması
├── run.sh               # Hızlı başlatma scripti
├── exports/             # JSON & HTML çıktı dosyaları
├── samples/             # Örnek demo raporlar
└── README.md            # Proje açıklaması

---

## 📜 Lisans
MIT Lisansı © 2025 Burak BALTA – Tüm hakları saklıdır.
