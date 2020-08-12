# Skripsi Deteksi DGA

Perangkat lunak dibangun sebagai implementasi pada skripsi berjudul *Deteksi Serangan Malware dengan Domain Generation Algorithm Berdasarkan Analisis Traffic DNS*. Perangkat lunak dibangun menggunakan bahasa Python ver. 2.7 dan *library* Pyshark (v0.3.8)

## Development

Perangkat lunak dibangun menggunakan komputer dengan spesifikasi sebagai berikut:

1. Sistem operasi: Ubuntu (v20.04 LTS)
2. Bahasa pemrograman: Python 2.7, HTML, JavaScript
3. Basis Data: MySQL ver. 8.0.20-0ubuntu0.20.04.1 for Linux on x86_64
4. IDE: PyCharm 2020.1.1 Professional Edition
5. Library: Pyshark v0.3.8, Flask v1.1.2, Flask-SocketIO v4.2.1

Untuk melakukan ubahan, menjalankan, dan membangun perangkat lunak ini dibutuhkan hal sebagai berikut:

1. Perangkat lunak sebaiknya diubah, dijalankan, dan dibangun menggunakan OS Ubuntu (tested pada v19.10 dan v20.04 LTS)
2. Pastikan anda telah menginstall dan melakukan set-up Apache, MySQL, dan Python (v2.7) pada Ubuntu anda
3. Install [TShark](https://www.wireshark.org/docs/man-pages/tshark.html). Pastikan TShark memiliki permission agar bisa dijalankan tanpa menggunakan `sudo`.
4. Install *library* yang dibutuhkan. Disarankan anda menggunakan Virtual Environment Python (venv).
   1. Pyshark v0.3.8
   ``` 
   $ pip install pyshark==0.3.8 
   ```
   2. Flask
   ``` 
   $ pip install Flask 
   ```
   3. Flask-SocketIO
   ``` 
   $ pip install flask-socketio 
   ```
5. Ubah nilai `MAIN_INTERFACE` pada baris **15** dengan nama *Network Interface Card* (NIC) yang akan digunakan sebagai NIC untuk melakukan proses penangkapan *traffic* DNS. Anda dapat memeriksanya dengan menjalankan *command* `$ ifconfig` pada terminal untuk mengetahui nama NIC yang akan digunakan.
6. Lakukan ubahan *credentials* basis data MySQL pada file `app.py` baris **188-190**. Ubah parameter `user`, `passwd`, dan `database` sesuai dengan *credentials* yang anda gunakan.
7. Jalankan program menggunakan *command* `$ python app.py`. Secara default, program dapat diakses melalui *browser* anda pada URL `http://localhost:5000`.

## Petunjuk Pemakaian Penggunaan Program
### Live Capture
1. Akses halaman `Live Capture`
2. Tekan tombol `Start Capture`. Program akan melakukan penangkapan *traffic* DNS selama waktu yang diinginkan.
3. Tekan tombol `Stop Capture` untuk menghentikan penangkapan *traffic* DNS. Program akan melakukan penyimpanan ke basis data dan melakukan analisis terhadap *traffic* DNS yang telah ditangkap.
4. Hasil penangkapan dan analisis akan ditampilkan pada tabel di halaman yang sama.

### Analyze PCAP
1. Akses halaman `Analyze PCAP`
2. Pilih file PCAP yang akan dianalisis dengan menekan tombol `Browse`
3. Program akan melakukan analisis terhadap file PCAP yang dipilih.
4. Hasil penangkapan dan analisis akan ditampilkan pada tabel di halaman yang sama.

### Melihat histori Live Capture atau Analyze PCAP
1. Akses halaman `Live Capture` atau `Analyze PCAP`
2. Pilih *tab* `History`
3. Pilih histori penangkapan dari *dropdown* yang disediakan.
4. Hasil penangkapan dan analisis akan ditampilkan pada tabel di halaman yang sama.

### Melihat keseluruhan histori Live Capture atau Analyze PCAP
1. Akses halaman `Live Capture` atau `Analyze PCAP`
2. Pilih *tab* `Show All History`
3. Tekan tombol `Refresh`.
4. Hasil penangkapan dan analisis akan ditampilkan pada tabel di halaman yang sama.

### Melihat detail informasi dari tiap domain yang telah dianalisis
1. Pada tabel berisi hasil analisis, tekan tombol `Details`
2. Anda akan diarahkan ke halaman `Details` untuk domain yang dipilih.
