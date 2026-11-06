# FileTrace — Direct File QR Tracking

Upload a file, embed a QR code that identifies it, download the processed file, and share that file directly using WhatsApp, Gmail, Telegram, or another channel. When a recipient scans the QR code, the scan page records the event and requests device location through the browser's native permission prompt.

## Features

- SHA-256 digest and unique Tracking ID for each upload.
- QR embedded in PDF as an additional identification page.
- QR embedded in DOCX footer.
- QR embedded in common image files as a visible panel.
- For other file formats, keep the original bytes and provide a separate QR PNG.
- Download processed file without creating a separate share link.
- QR scan event history.
- Optional visitor name submission; a name is not automatically knowable from a file scan.
- Device-reported location is saved only after browser permission is granted, with accuracy and timestamp.
- If permission is denied or unavailable, the scan event is still recorded.

## Important technical facts

- Opening an ordinary local file cannot automatically send an event to a server. This design uses an embedded QR code; the recipient must scan it.
- The QR opens a tracking page. It is not a viewer link for the file itself.
- The browser/device controls location permission. The app cannot bypass it or silently collect GPS.
- A name must be voluntarily entered or supplied by an authenticated account. It cannot reliably be inferred from a QR scan.
- A QR scan indicates that the QR was scanned, not proof that the person scanned is the recipient, that they opened the file, or that they physically possess it.
- This starter stores event IP fingerprints (one-way SHA-256), user agent, visitor-submitted name, and permission-granted coordinates. Add an appropriate privacy notice, retention controls, access controls, and legal review before real-world use.
- Use HTTPS for deployed tracking pages. Browser geolocation is generally restricted to secure contexts (HTTPS or localhost).

## Install on Windows

```powershell
cd path	o\FileTrace
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000

## Local testing

1. Upload a PDF, DOCX, or image.
2. Download the processed file.
3. Open the QR code from the added PDF page, DOCX footer, or image panel using a phone.
4. Alternatively, download the separate QR PNG from the dashboard.
5. The QR URL must be reachable from the phone. `127.0.0.1` on your PC will not work from another device.
6. Review the file's event history on the dashboard.

## Make QR work for recipients outside your computer

Deploy this app to a public HTTPS host first, then set `PUBLIC_BASE_URL` to the deployed URL **before uploading files**. QR codes already generated with localhost must be regenerated after changing the base URL. Do not expose this demo publicly without adding authentication and owner authorization.

## Production work still required

This is a development starter, not production-ready. Add user login, per-owner file authorization, CSRF protection, rate limiting, malware scanning, file-type validation, secure private object storage, managed database migrations, audit logs, deletion/retention controls, backups, token revocation/rotation, and automated tests. Protect the dashboard before deployment.
