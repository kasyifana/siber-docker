# Laporan Sementara Proyek: MCP Security Audit

## 1. Judul Proyek

MCP Security Audit: Sebuah server audit keamanan berbasis Micro-service Communication Protocol (MCP) yang menyediakan berbagai perkakas keamanan untuk melakukan pengujian penetrasi secara otomatis.

## 2. Deskripsi Proyek

Proyek ini bertujuan untuk membangun sebuah server yang dapat diintegrasikan dengan platform lain melalui MCP. Server ini menyediakan serangkaian perkakas audit keamanan yang dapat dipanggil secara terprogram. Setiap perkakas dirancang untuk melakukan tugas spesifik, seperti pemindaian port, pengujian kerentanan web, analisis SSL, dan lain-lain.

Aplikasi ini dibangun dengan Python dan memanfaatkan berbagai perkakas keamanan open-source yang populer. Hasil dari setiap pemindaian dapat diformat menjadi laporan yang mudah dibaca.

## 3. Arsitektur & Komponen Utama

Proyek ini memiliki arsitektur modular yang terdiri dari beberapa komponen utama:

### a. Server MCP (`server.py`, `stdio_server.py`)

- **Fungsi:** Bertindak sebagai titik masuk utama aplikasi. Server ini bertanggung jawab untuk menerima permintaan melalui protokol MCP, memanggil perkakas yang sesuai, dan mengembalikan hasilnya.
- **Implementasi:** Menggunakan pustaka `mcp` untuk membuat server. Terdapat dua mode: server standar dan `stdio_server` yang dirancang untuk kompatibilitas dengan Docker MCP Gateway.

### b. Modul Perkakas Keamanan (Direktori `src/tools/`)

Setiap perkakas keamanan dibungkus dalam modulnya sendiri, yang membuatnya mudah untuk dikelola dan diperluas.

- **`nmap_scanner.py`:** Melakukan pemindaian port menggunakan **Nmap**.
- **`sqlmap_tool.py`:** Menguji kerentanan SQL Injection menggunakan **SQLMap**.
- **`nikto_scanner.py`:** Memindai kerentanan web umum menggunakan **Nikto**.
- **`zap_tool.py`:** Melakukan pemindaian aplikasi web secara mendalam menggunakan **OWASP ZAP**.
- **`xss_tester.py`:** Menguji kerentanan Cross-Site Scripting (XSS).
- **`subdomain_enum.py`:** Melakukan enumerasi subdomain target.
- **`ssl_checker.py`:** Menganalisis konfigurasi SSL/TLS pada server.
- **`header_analyzer.py`:** Memeriksa keberadaan dan konfigurasi header keamanan HTTP.

### c. Modul Utilitas (Direktori `src/utils/`)

- **`logger.py`:** Mengkonfigurasi dan menyediakan *logger* aplikasi menggunakan `loguru` untuk pencatatan yang terstruktur.
- **`reporter.py`:** Menghasilkan laporan hasil audit dalam format Markdown.
- **`validator.py`:** Melakukan validasi dan sanitasi input target (URL, IP, domain) untuk memastikan keamanan dan mencegah pemindaian terhadap jaringan internal atau target yang tidak valid.

### d. Konfigurasi (`src/config/settings.py`)

- Menggunakan `pydantic-settings` untuk mengelola semua konfigurasi aplikasi, seperti host server, port, path perkakas, dan pengaturan pemindaian. Konfigurasi dapat diatur melalui *environment variables* atau file `.env`.

## 4. Fungsionalitas Utama

Server ini menyediakan fungsionalitas berikut yang diekspos sebagai "tools" melalui MCP:

- **Pemindaian Port:** Mendeteksi port yang terbuka pada target.
- **Pengujian SQL Injection:** Mencari celah keamanan SQL Injection pada aplikasi web.
- **Pemindaian Kerentanan Web:** Mengidentifikasi kerentanan umum pada server web.
- **Pengujian XSS:** Mencari kemungkinan serangan Cross-Site Scripting.
- **Enumerasi Subdomain:** Menemukan subdomain yang terkait dengan domain target.
- **Analisis SSL/TLS:** Memeriksa kekuatan konfigurasi enkripsi.
- **Analisis Header Keamanan:** Memvalidasi implementasi header keamanan.
- **Audit Keamanan Penuh:** Menjalankan beberapa pemindaian secara bersamaan untuk memberikan gambaran keamanan yang komprehensif.
- **Pembuatan Laporan:** Menghasilkan laporan dari hasil pemindaian.

## 5. Alur Kerja

1.  **Inisialisasi:** Server dimulai dan mendaftarkan semua perkakas keamanan yang tersedia.
2.  **Permintaan:** Klien (misalnya, melalui MCP Gateway) mengirimkan permintaan untuk memanggil perkakas tertentu dengan argumen yang sesuai (misalnya, `port_scan` dengan target `example.com`).
3.  **Validasi:** Input dari klien divalidasi oleh `TargetValidator` untuk memastikan target aman untuk dipindai.
4.  **Eksekusi:** Server memanggil modul perkakas yang relevan. Modul ini kemudian menjalankan perkakas baris perintah yang sesuai (misalnya, `nmap`) sebagai *subprocess*.
5.  **Pengolahan Hasil:** Output dari perkakas baris perintah di-parse dan diformat menjadi struktur data Python yang bersih.
6.  **Respons:** Hasil yang telah diformat dikirim kembali ke klien sebagai respons MCP.
7.  **Pelaporan:** Jika diminta, `ReportGenerator` dapat digunakan untuk membuat laporan lengkap dari satu atau lebih hasil pemindaian.

## 6. Status Saat Ini & Langkah Selanjutnya

### Status Saat Ini:

- Kerangka dasar server MCP telah selesai.
- Integrasi dengan perkakas keamanan utama (Nmap, SQLMap, Nikto, dll.) telah diimplementasikan.
- Fungsionalitas untuk validasi input, logging, dan pembuatan laporan dasar sudah ada.
- Proyek ini tampaknya sudah fungsional pada level prototipe.

### Langkah Selanjutnya yang Mungkin:

- **Pengujian Menyeluruh:** Melakukan pengujian pada setiap perkakas untuk memastikan akurasi dan keandalan hasil.
- **Peningkatan Pelaporan:** Menambahkan lebih banyak format laporan (misalnya, HTML, PDF) dan memperkaya konten laporan dengan grafik atau ringkasan yang lebih baik.
- **Manajemen Sesi & Hasil:** Mengimplementasikan penyimpanan hasil pemindaian ke database (seperti yang diindikasikan oleh konfigurasi PostgreSQL) sehingga laporan dapat dibuat kapan saja untuk pemindaian sebelumnya.
- **Peningkatan Performa:** Mengoptimalkan eksekusi pemindaian, mungkin dengan antrian tugas (seperti Redis yang ada di konfigurasi) untuk mengelola pemindaian yang berjalan secara bersamaan.
- **Dokumentasi API:** Membuat dokumentasi yang jelas untuk setiap perkakas yang tersedia melalui MCP.
