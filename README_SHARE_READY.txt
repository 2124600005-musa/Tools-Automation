# Oushh Telegram Deep Bot - Share Ready

```text
 ██████╗ ██╗   ██╗███████╗██╗  ██╗██╗  ██╗██╗  ██╗
██╔═══██╗██║   ██║██╔════╝██║  ██║██║  ██║██║  ██║
██║   ██║██║   ██║███████╗███████║███████║███████║
██║   ██║██║   ██║╚════██║██╔══██║██╔══██║██╔══██║
╚██████╔╝╚██████╔╝███████║██║  ██║██║  ██║██║  ██║
 ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
```

## Official Social

- Instagram: @ouashxy
- LinkedIn: musa-hamonangan-lubis-a719b9282
- GitHub: 2124600005-musa

## Git Clone

`at
git clone https://github.com/2124600005-musa/Tools-Automation.git
cd Tools-Automation
`

## Cara Setup Windows

1. Extract ZIP ini.
2. Jalankan:

```bat
setup.bat
```

3. Edit `config.py`:

```python
BOT_TOKEN = "TOKEN_BOTFATHER_KAMU"
CHAT_ID = "TELEGRAM_USER_ID_KAMU"
```

4. Jalankan bot:

```bat
run_deep_bot.bat
```

Atau:

```bat
python telegram_deep_bot.py
```

## Cara Setup Linux/macOS

1. Clone/extract project.
2. Jalankan:

```bash
chmod +x setup.sh run_deep_bot.sh
./setup.sh
```

3. Edit `config.py`:

```python
BOT_TOKEN = "TOKEN_BOTFATHER_KAMU"
CHAT_ID = "TELEGRAM_USER_ID_KAMU"
```

4. Jalankan bot:

```bash
./run_deep_bot.sh
```

Atau:

```bash
python3 telegram_deep_bot.py
```

## Catatan

- Bot ini untuk target yang kamu miliki/diizinkan saja.
- Jangan scan target tanpa izin.
- Output scan bisa besar. Gunakan tombol `Clean Output` di bot untuk membersihkan hasil lama.
- Jika tools Go belum terbaca setelah setup, tutup terminal lalu buka lagi.

## Fitur

- Deep Scan via Telegram.
- Status mengikuti tahapan asli Oushh.
- Nuclei findings tampil di Telegram.
- ZIP report otomatis.
- Cleaning output/cache.
- Windows-safe tool resolver untuk httpx/waybackurls/gau/katana/nuclei.
