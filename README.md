# OmniCleaner

OmniCleaner, Windows için kapsamlı bir güvenlik ve temizlik aracıdır. USB kısayol virüsleri başta olmak üzere yaygın kötü amaçlı yazılım kalıntılarını temizlemeye, gizlenen dosyaları geri getirmeye ve gelişmiş taramalar ile riskleri görselleştirmeye odaklanır. GUI üzerinden kolay kullanım sağlar, komut satırından da çalıştırılabilir.

## Özellikler

- **Temizlik**: Kısayol virüsleri, gizli dosyalar, autorun kalıntıları
- **Karantina**: Bulunan tehditleri güvenli karantina alanına taşıma/geri yükleme
- **Gerçek zamanlı log**: Clean ve Advanced sekmelerinde satır içi log (word wrap açık)
- **Gelişmiş taramalar (Advanced)**:
  - Startup klasörleri inceleme
  - Hosts dosyası kontrolü
  - Tarayıcı eklentilerini listeleme
  - PowerShell profillerini kontrol etme
  - Açık port taraması (netstat)
  - Şüpheli süreç analizi
- **Gelişmiş aksiyonlar (isteğe bağlı ve riskli)**:
  - Riskli açık portları kapatma (seçili portlar kırmızı vurgulanır)
- **Tema**: Aydınlık/Karanlık tema, Advanced sayfası dahil tutarlı görünüm
- **Log rotasyonu**: Eski `omnicleaner.log` otomatik `scripts/logs/` klasörüne arşivlenir
- **Ayarlar**: `gui_settings.json` ile kalıcı kullanıcı ayarları
- **Modüler mimari**: GUI bölümleri ayrı dosyalarda (dot-source)

## Hızlı Başlangıç

### 1) GitHub’dan klonlayarak

```powershell
git clone https://github.com/SoulzHem/OmniCleaner.git
cd OmniCleaner
Get-ChildItem -Recurse -Filter *.ps1 | Unblock-File
./RunCleanerGUI.bat
```

### 2) Tek satırla (indirip çalıştıran bootstrap)

GUI’yi geçici klasöre indirip başlatır:

```powershell
irm 'https://raw.githubusercontent.com/SoulzHem/OmniCleaner/main/bootstrap.ps1' | iex
```

Çalıştırma sonrası geçici klasörü temizlemek için:

```powershell
iwr -useb 'https://raw.githubusercontent.com/SoulzHem/OmniCleaner/main/bootstrap.ps1' | iex; bootstrap -Cleanup
```

## Komut Satırı Kullanımı

Temel kullanım örnekleri:

```powershell
./scripts/OmniCleaner.ps1 -AllRemovable -WhatIf
./scripts/OmniCleaner.ps1 -DoOpenPorts -LogPath "./scripts/omnicleaner.log"
./scripts/OmniCleaner.ps1 -DoProcessAnomalies -LogPath "./scripts/omnicleaner.log"
./scripts/OmniCleaner.ps1 -DoHosts -DoStartup -LogPath "./scripts/omnicleaner.log"
./scripts/OmniCleaner.ps1 -CloseOpenPorts -PortTargets 135,139,445,3389 -LogPath "./scripts/omnicleaner.log"
```

Notlar:
- `-WhatIf` ile güvenli önizleme yapılır (değişiklik yapmadan).
- `-LogPath` verilmezse varsayılan `scripts/omnicleaner.log` kullanılır.

## Dosya Yapısı

```
OmniCleaner/
├── RunCleanerGUI.bat                 # GUI başlatıcı (PowerShell GUI’yi çağırır)
├── Setup.ps1                         # İlk kurulum kolaylıkları (klasörler, unblock)
├── bootstrap.ps1                     # Tek satırdan indirme/çalıştırma betiği
├── README.md                         # Bu dosya
├── LICENSE                           # MIT lisansı
├── .gitignore
├── .github/
│   └── workflows/
│       └── release.yml               # Tag ile otomatik zip release
└── scripts/
    ├── OmniCleaner.ps1               # Ana temizlik/scan betiği
    ├── OmniCleaner.GUI.ps1           # GUI ana betiği (gui/*.ps1 dot-source)
    ├── exclusions.txt                # Hariç tutulacak yollar/kalıplar
    ├── logs/                         # Arşiv loglar (otomatik oluşturulur)
    ├── reports/                      # CSV/HTML dışa aktarımlar
    ├── quarantine/                   # Karantinaya alınanlar
    └── gui/
        ├── CleanTab.ps1              # Clean sekmesi UI/işlevler
        ├── AdvancedTab.ps1           # Advanced sekmesi UI/işlevler
        ├── Quarantine.ps1            # Karantina yöneticisi penceresi
        ├── Logging.ps1               # Write-Log / renkli log yardımcıları
        ├── Theme.ps1                 # Tema ve stil fonksiyonları
        ├── Settings.ps1              # Ayarları yükle/kaydet
        └── gui_settings.json         # Varsayılan kullanıcı ayarları
```

## Release ve Dağıtım

- GitHub Actions ile tag atıldığında (`v1.0.0` vb.) `OmniCleaner.zip` otomatik oluşturulur ve release’e eklenir.
- Release veya `main.zip` bootstrap tarafından indirilebilir ve GUI otomatik başlatılır.

## Güvenlik ve Antivirüs Notu

Bu araç meşru bir güvenlik/temizlik aracıdır. Kaynak kodu açık ve denetlenebilirdir. Antivirüsler komut dosyalarını yanlış pozitif olarak işaretleyebilir; gerekiyorsa proje klasörünü istisnalara ekleyin.

## Lisans

Bu proje **MIT Lisansı** ile lisanslanmıştır. Ayrıntılar için `LICENSE` dosyasına bakın.