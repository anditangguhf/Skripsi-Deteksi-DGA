## Petunjuk Pemakaian Penggunaan Program
Jalankan *command* `$ python app.py` terlebih dahulu, kemudian akses `http://localhost:5000` pada *browser* anda.

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
