# Scanner Emailuri Suspecte  - ScanEmail.py

Acest program analizează emailurile din contul tău Gmail pentru a detecta potențiale amenințări de securitate, inclusiv phishing, malware și alte tipuri de atacuri transmise prin email.

## Funcționalități

- **Analiza headerelor emailului**: Verifică SPF, DKIM, DMARC pentru a identifica emailuri falsificate
- **Analiza conținutului**: Detectează cuvinte și fraze suspicious, precum și texte cu formatare suspectă
- **Scanare linkuri**: Identifică URL-uri scurtate, domenii periculoase și link-uri de phishing
- **Verificare atașamente**: Detectează tipuri de fișiere periculoase și potențiale amenințări în atașamente
- **Evaluare risc**: Calculează un scor de pericol (0-10) pentru fiecare email

## Cerințe

- Python 3.6+
- Acces la un cont Gmail
- Credențiale OAuth2 pentru Google API

## Instalare

1. Instalează dependențele necesare:

```bash
pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib dnspython
```

2. Creează credențialele OAuth2 pentru Gmail API:
   - Accesează [Google Cloud Console](https://console.cloud.google.com/)
   - Creează un proiect nou
   - Activează Gmail API pentru proiect
   - Creează credențiale OAuth2 (tip "Desktop app")
   - Descarcă fișierul JSON cu credențiale și salvează-l ca `credentials.json` în directorul cu scriptul

## Utilizare

1. Rulează scriptul:

```bash
python ScanareEmailuri.py
```

2. La prima rulare, se va deschide un browser pentru autentificare și acordarea permisiunilor necesare
3. Introdu numărul de emailuri pe care dorești să le scanezi
4. Scriptul va analiza emailurile și va genera un raport cu rezultatele scanării

## Rezultate

Programul va afișa:
- Numărul total de emailuri scanate
- Numărul de emailuri potențial periculoase
- Detalii pentru fiecare email suspect: 
  - Scorul de pericol
  - Probleme identificate în headere
  - Conținut suspect
  - Linkuri periculoase 
  - Atașamente suspecte

Rezultatele sunt salvate și în fișierul `rezultate_scanare_email.json` pentru analiză ulterioară.

## Note de securitate

- Scriptul rulează local și nu trimite datele tale nicăieri
- Accesul OAuth este doar pentru citirea emailurilor, nu și pentru modificarea lor
- Analizele sunt simple și pot avea atât rezultate fals pozitive cât și fals negative
- Acest instrument este menit să completeze, nu să înlocuiască, soluțiile de securitate existente







  Scanare.java && # Scanner de Malware && Scan.java

## Descriere
Această aplicație Java oferă o soluție simplă dar eficientă pentru scanarea sistemului în căutarea potențialelor fișiere malware. Programul utilizează o bază de semnături predefinite și verifică extensiile fișierelor pentru a identifica potențiale amenințări.

## Funcționalități
- Scanare recursivă a directoarelor
- Detectare fișiere suspecte bazată pe semnături
- Verificare extensii periculoase
- Raportare în timp real a progresului scanării
- Sumar final cu statistici

## Semnături Detectate
Programul poate detecta următoarele tipuri de fișiere potențial periculoase:
- Executabile PE (Windows)
- Executabile ELF (Linux)
- Arhive ZIP suspecte
- Fișiere Java Class
- Scripturi (Bash, PHP)
- Documente Office cu macro-uri
- Fișiere PDF cu JavaScript
- Și multe altele

## Cum să Utilizați
1. Compilați fișierul `scan.java`
2. Rulați programul
3. Introduceți calea completă a directorului pe care doriți să-l scanați
4. Așteptați finalizarea scanării
5. Verificați rezultatele afișate

## Limitări
- Scanează doar fișiere mai mici de 10MB
- Verifică doar primii 4 bytes ai fișierelor pentru semnături
- Nu oferă opțiuni de carantină sau remediere

## Cerințe Sistem
- Java Runtime Environment (JRE)
- Drepturi de acces pentru citirea directoarelor țintă

## Note de Securitate
- Programul este destinat doar pentru scopuri educaționale
- Nu este un înlocuitor pentru soluțiile antivirus profesionale
- Poate genera false pozitive

## Extensii Monitorizate
Următoarele extensii sunt considerate potențial periculoase:
- .exe
- .dll
- .bat
- .cmd
- .scr
- .vbs
- .js
- .jar 

