# CyberSecAudit 🔒

![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)

Kapsamlı Siber Güvenlik Denetim Aracı | Comprehensive Cybersecurity Audit Tool

## 🚀 Özellikler | Features

- 🔍 Gelişmiş Port Tarama |Advanced Port Scanning
- 🛡️ Güvenlik Açığı Analizi | Vulnerability Analysis
- 🔐 Şifre Güvenlik Kontrolü |  Password Security Check
- 📊 Detaylı Raporlama | Detailed Reporting
- 🐳 Docker Desteği | Docker Support

## ⚙️ Kurulum | Installation

### 1. Repository'i Klonlayın | Clone the repository
```bash
git clone https://github.com/warth1/cybersecaudit.git
cd cybersecaudit
```

### 2. Python Sanal Ortam Oluşturun | Create a Python virtual environment
```bash
# Linux/macOS
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

### 3. Gereksinimleri Yükleyin | Install the requirements
```bash
pip install -r requirements_file.txt
```

### 4. Aracı Çalıştırılabilir Yapın | Make the tool executable
```bash
# Linux/macOS
chmod +x cybersec_audit.py
```

### Docker ile Kurulum | Installation via Docker is also supported
```bash
# Image oluştur
docker build -t cybersecaudit .

# Docker Compose ile başlat
docker-compose up -d
```

## 💻 Kullanım | Usage

### Temel Kullanım | Basic Usage
```bash
python cybersec_audit.py [target]
```

### Parametreler | Parameters
```
-h, --help            Yardım menüsünü göster
-p, --ports PORTS     Taranacak portlar (örn: 80,443,22)
-t, --threads THREADS Thread sayısı (varsayılan: 100)
-o, --output OUTPUT   Çıktı dosyası (varsayılan: security_report.json)
--password-check      Şifre güvenlik analizi
```

### Örnek Komutlar | Example Commands
```bash
# Belirli portları tara
python cybersec_audit.py 192.168.1.1 -p 80,443,22,21

# Thread sayısını ayarla
python cybersec_audit.py 192.168.1.1 -t 200

# Özel rapor dosyası oluştur
python cybersec_audit.py 192.168.1.1 -o my_scan_report.json

# Şifre analizi yap
python cybersec_audit.py 192.168.1.1 --password-check "TestPassword123!"
```

## 📋 Örnek Çıktı | Sample Output

```json
{
  "scan_time": "2025-07-13T12:46:31",
  "port_scan": {
    "192.168.1.1": [80, 443, 22]
  },
  "vulnerability_scan": [
    {
      "severity": "MEDIUM",
      "port": 80,
      "description": "HTTP trafiği şifrelenmemiş",
      "recommendation": "HTTP trafiğini HTTPS'e yönlendirin"
    }
  ]
}
```

## 🔧 Gereksinimler | Requirements

### Minimum Sistem Gereksinimleri | Minimum System Requirements
- Python 3.6 veya üzeri
- 2GB RAM
- 1GB boş disk alanı

### Desteklenen İşletim Sistemleri | Supported Operating Systems
- Linux (Ubuntu, Debian, CentOS)
- macOS
- Windows 10/11

## 🤝 Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/YeniOzellik`)
3. Değişikliklerinizi commit edin (`git commit -am 'Yeni özellik: XYZ'`)
4. Branch'inizi push edin (`git push origin feature/YeniOzellik`)
5. Pull Request oluşturun

## 🔒 Güvenlik

Güvenlik açığı bulduysanız, lütfen "" adresine e-posta gönderin.
Detaylı bilgi için [SECURITY.md](SECURITY.md) dosyasına bakın.

## 📝 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

## 📞 İletişim

Warth - [@warth1](https://github.com/warth1)

Proje Linki: [https://github.com/warth1/cybersecaudit](https://github.com/warth1/cybersecaudit)

---

⭐️ Bu projeyi beğendiyseniz yıldız vermeyi unutmayın!
