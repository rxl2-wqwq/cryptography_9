# CipherForge — Web Kriptosistem Klasik

Aplikasi web berbasis Flask untuk mempelajari enkripsi dan dekripsi tujuh cipher klasik. Pengguna dapat memasukkan teks atau mengunggah file, memilih cipher dan kunci, lalu melihat hasil atau mengunduh berkas hasil proses.

> **Catatan keamanan:** cipher klasik dalam proyek ini dibuat untuk pembelajaran dan demonstrasi, bukan untuk melindungi data sensitif.

## Repository & Collaborators

- Repository: https://github.com/rxl2-wqwq/cryptography_9
- Collaborators:
  - [rafiisetianto](https://github.com/rafiisetianto)
  - [Latief342](https://github.com/Latief342)

## Informasi Teknis

- Bahasa pemrograman: Python 3
- Framework web: Flask
- Template HTML: Jinja2 (termasuk dalam Flask)
- Operasi matriks Hill: SymPy
- Pengujian: pytest

## Fitur

- Enkripsi dan dekripsi teks melalui antarmuka web.
- Implementasi tujuh cipher: Shift, Substitution, Affine, Vigenère, Hill, Permutation, dan One-Time Pad (OTP).
- Enkripsi dan dekripsi file biner, termasuk file gambar, audio, video, dan database.
- Hasil cipherteks teks dapat ditampilkan tanpa spasi atau dikelompokkan setiap lima huruf.
- File hasil enkripsi menggunakan ekstensi `.dat`; nama file asli disimpan sebagai metadata terenkripsi dan dipulihkan saat dekripsi.
- Validasi kunci dan pesan kesalahan ditampilkan pada halaman, bukan dibiarkan menyebabkan aplikasi berhenti.

## Struktur Proyek

```text
kripto_9/
├─ app.py                   # Aplikasi Flask: form, routing, dan pemanggilan cipher
├─ ciphers/                 # Implementasi cipher teks
│  ├─ __init__.py           # Ekspor fungsi cipher
│  ├─ utils.py              # Helper alfabet, konversi huruf, dan format kelompok-5
│  ├─ shift.py
│  ├─ substitution.py
│  ├─ affine.py
│  ├─ vigenere.py
│  ├─ hill.py
│  ├─ permutation.py
│  └─ otp.py
├─ filemode.py              # Transformasi byte dan metadata file
├─ templates/
│  └─ index.html            # Antarmuka HTML/Jinja2
├─ static/
│  └─ style.css             # Tampilan aplikasi
├─ tests/                   # Tes otomatis cipher dan file mode
├─ requirements.txt         # Dependensi Python
├─ .gitignore
└─ README.md
```

## Persyaratan

- Python 3.8 atau lebih baru.
- Dependensi yang tercantum di `requirements.txt`: Flask, SymPy, dan pytest.

### Instalasi dengan pip (direkomendasikan)

Jalankan dari direktori proyek:

```bash
python -m venv venv
source venv/bin/activate       # Linux/macOS
# venv\Scripts\activate       # Windows PowerShell
python -m pip install -r requirements.txt
```

Pada terminal Arch Linux, `pip install` ke Python sistem dapat ditolak oleh PEP 668. Gunakan virtual environment seperti langkah di atas, bukan `--break-system-packages`.

## Menjalankan Aplikasi

Dari direktori proyek, aktifkan virtual environment bila digunakan, lalu jalankan:

```bash
python app.py
```

Buka alamat berikut di browser:

```text
http://127.0.0.1:5000
```

Hentikan server dengan `Ctrl+C` pada terminal.

## Menggunakan Aplikasi

### Enkripsi atau dekripsi teks

1. Pilih operasi **Enkripsi** atau **Dekripsi**.
2. Pilih jenis input **Teks**.
3. Pilih salah satu cipher.
4. Masukkan teks dan kunci dengan format yang sesuai.
5. Pilih format tampilan cipherteks jika tersedia, lalu tekan **Proses cipher**.

Format kunci yang diterima:

| Cipher | Format kunci teks | Contoh |
|---|---|---|
| Shift | Angka pergeseran | `3` |
| Substitution | Permutasi 26 huruf A–Z | `QWERTYUIOPASDFGHJKLZXCVBNM` |
| Affine | `m,b`; `m` harus relatif prima dengan 26 | `7,10` |
| Vigenère | Kata atau rangkaian huruf | `CIPHER` |
| Hill | Matriks persegi yang invertibel modulo 26 | `[[17,17,5],[21,18,21],[2,2,19]]` |
| Permutation | Urutan angka kolom tanpa duplikat | `3,1,2` |
| OTP | Kunci huruf sekurang-kurangnya sepanjang pesan | `XMCKL` |

### Enkripsi atau dekripsi file

1. Pilih jenis input **File**.
2. Pilih cipher dan masukkan kuncinya.
3. Untuk OTP, unggah file kunci OTP yang cukup panjang.
4. Unggah file yang akan diproses, lalu tekan **Proses cipher**.
5. Enkripsi menghasilkan unduhan `.dat`. Untuk dekripsi, unggah `.dat` tersebut, pilih cipher dan kunci yang sama, lalu unduh file hasil.

File diproses sebagai bytes, sehingga aplikasi tidak bergantung pada ekstensi atau format internalnya. Berkas gambar, audio, video, dokumen, dan database dapat diproses sebagai data biner. Metadata nama file asli turut dilindungi dalam ciphertext dan digunakan untuk memberi nama file hasil dekripsi.

> **Peringatan OTP:** kunci OTP harus memadai panjangnya untuk seluruh data yang diproses, termasuk metadata file. Gunakan kunci baru yang acak untuk setiap enkripsi dan jangan pernah menggunakan ulang kunci.

## Menjalankan Tes

Dari direktori proyek, dengan dependensi terpasang:

```bash
python -m pytest -q
```

Tes mencakup vektor uji cipher teks, round-trip enkripsi/dekripsi, validasi kunci, dan round-trip file biner. Untuk menjalankan tes file mode saja:

```bash
python -m pytest -q tests/test_filemode.py
```

## Cara Kerja Singkat

Browser mengirim nilai form ke route Flask pada `app.py`. Untuk teks, Flask memilih fungsi enkripsi atau dekripsi dari paket `ciphers/`, lalu mengirim hasil kembali ke template. Untuk file, Flask meneruskan bytes ke `filemode.py`, yang menambahkan metadata, menjalankan transformasi byte, dan mengembalikan hasil sebagai unduhan. `tests/` menguji fungsi cipher dan alur file secara terpisah dari antarmuka.

## Batasan dan Catatan Implementasi

- Cipher ini bersifat edukatif dan tidak aman untuk penggunaan produksi.
- Mode teks bekerja pada alfabet A–Z; karakter non-alfabet diproses sesuai aturan masing-masing cipher dan dapat dibuang.
- Enkripsi Hill menambahkan padding `X` saat plaintext tidak memenuhi ukuran blok. Implementasi dekripsi menghapus `X` di akhir; akibatnya, teks asli yang memang berakhir dengan `X` dapat menjadi ambigu.
- Mode file menggunakan transformasi byte modulo 256. Karena domainnya berbeda dari mode teks, kunci file Affine dan Hill harus memenuhi syarat kebalikan modulo 256.
- File OTP harus menyediakan jumlah byte kunci yang cukup untuk data dan metadata; kunci pendek ditolak.
- Tombol **Generate key OTP** pada antarmuka belum tersambung ke fungsi backend. Untuk pemrosesan file OTP, unggah file kunci yang telah disiapkan secara terpisah.
- Batas ukuran unggahan mengikuti konfigurasi server dan sumber daya komputer; file besar membutuhkan memori dan waktu pemrosesan lebih banyak.
- Dukungan satu file diuji sebagai round-trip bytes. Uji aplikasi dengan berkas penting milik pengguna tetap disarankan menggunakan salinan, bukan satu-satunya file asli.

## Status Pengujian

Tes otomatis terakhir yang dijalankan pada lingkungan pengembangan menghasilkan **17 passed** dengan `python -m pytest -q`. Hasil tersebut mencakup tes cipher dan file mode yang ada di repositori pada saat tes dijalankan; angka ini perlu diperbarui jika jumlah tes berubah.

## Contributors

- [rafiisetianto](https://github.com/rafiisetianto)
- [Latief342](https://github.com/Latief342)
