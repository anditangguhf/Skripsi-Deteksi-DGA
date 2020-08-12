## Instalasi

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
