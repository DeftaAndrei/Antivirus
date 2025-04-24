#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import base64
import re
import hashlib
import json
import pickle
import tempfile
import mimetypes
import dns.resolver
from email.parser import BytesParser
from email.policy import default
from urllib.parse import urlparse

from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Setările pentru API Gmail
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CREDENTIALS_FILE = 'credentials.json'
TOKEN_FILE = 'token.pickle'

# Domenii suspecte 
DOMENII_SUSPECTE = ['.ru', '.tk', '.cn', '.top', '.xyz', '.club', '.online', '.info']

# Extensii periculoase
EXTENSII_PERICULOASE = [
    '.exe', '.js', '.vbs', '.bat', '.cmd', '.scr', '.dll', '.jar', 
    '.pif', '.reg', '.msi', '.ps1', '.hta', '.com', '.msc'
]

# Cuvinte și fraze suspecte
CUVINTE_SUSPECTE = [
    'urgent', 'verify your account', 'click here', 'password reset', 
    'suspended', 'limited', 'unusual activity', 'verify now', 
    'update your information', 'confirm identity', 'winner',
    'congratulations', 'ofertă', 'câștigat', 'account compromised',
    'security alert', 'authenticate', 'expires', 'validate', 'lottery'
]

def autentificare_google():
    """Autentificare la API-ul Gmail folosind OAuth2"""
    creds = None

    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'rb') as token:
            creds = pickle.load(token)
    
    # Verificare dacă credențialele sunt valide
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        
        # Salvare credențiale pentru utilizare viitoare
        with open(TOKEN_FILE, 'wb') as token:
            pickle.dump(creds, token)
    
    return build('gmail', 'v1', credentials=creds)

def verificare_spf_dkim_dmarc(headers):
    """Verifică dacă există probleme cu SPF, DKIM sau DMARC"""
    probleme = []
    header_dict = {h['name'].lower(): h['value'] for h in headers}
    
    # Verificare if From și Return-Path se potrivesc
    from_email = re.search(r'<([^>]+)>', header_dict.get('from', '')).group(1) if re.search(r'<([^>]+)>', header_dict.get('from', '')) else header_dict.get('from', '')
    return_path = re.search(r'<([^>]+)>', header_dict.get('return-path', '')).group(1) if re.search(r'<([^>]+)>', header_dict.get('return-path', '')) else header_dict.get('return-path', '')
    
    if from_email and return_path and from_email.lower() != return_path.lower():
        probleme.append(f"Diferență între From ({from_email}) și Return-Path ({return_path})")
    
    # Verificare Authentication-Results pentru SPF/DKIM/DMARC
    auth_results = header_dict.get('authentication-results', '')
    
    if 'spf=fail' in auth_results or 'spf=softfail' in auth_results:
        probleme.append("SPF fail - expeditor neautorizat")
    
    if 'dkim=fail' in auth_results or 'dkim=none' in auth_results:
        probleme.append("DKIM fail - posibil email falsificat")
    
    if 'dmarc=fail' in auth_results or 'dmarc=none' in auth_results:
        probleme.append("DMARC fail - posibil email falsificat")
    
    return probleme

def verificare_domeniu(domeniu):
    """Verifică dacă domeniul este suspect"""
    for sufix in DOMENII_SUSPECTE:
        if domeniu.endswith(sufix):
            return True
    
    # Verificare domeniu nou (mai puțin de 1 an)
    try:
        # Această parte necesită instalarea bibliotecii dnspython
        answers = dns.resolver.resolve(domeniu, 'SOA')
        for rdata in answers:
            # Verificare potențială a vârstei domeniului
            pass
    except:
        # Eroare la rezolvarea DNS - poate fi un semn de domeniu suspect
        return True
    
    return False

def verificare_continut_text(text):
    """Verifică conținutul textului pentru cuvinte și fraze suspecte"""
    text_lower = text.lower()
    suspecte_gasite = []
    
    for cuvant in CUVINTE_SUSPECTE:
        if cuvant.lower() in text_lower:
            suspecte_gasite.append(cuvant)
    
    # Verificare erori gramaticale sau text generat automat
    # (Implementare simplificată - în realitate ar folosi NLP)
    if len(text) > 100:
        # Verificăm densitatea de erori sau inconsistențe
        erori_evidente = re.search(r'\b[A-Z]{5,}\b', text) # Cuvinte ALL CAPS
        if erori_evidente:
            suspecte_gasite.append("Text cu formatare suspectă (CAPS excesiv)")
    
    return suspecte_gasite

def extrage_linkuri(text):
    """Extrage toate linkurile din text"""
    # Regex pentru URL-uri simple
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+|bit\.ly/[^\s<>"]+'
    linkuri = re.findall(url_pattern, text)
    
    # Regex pentru linkuri HTML
    html_pattern = r'href=["\'](https?://[^\s<>"\']+|www\.[^\s<>"\']+)["\']'
    html_linkuri = re.findall(html_pattern, text)
    
    return list(set(linkuri + html_linkuri))

def verificare_linkuri(linkuri):
    """Verifică linkurile suspecte"""
    suspecte = []
    
    for link in linkuri:
        # Verificare URL-uri scurtate
        if 'bit.ly' in link or 'tinyurl' in link or 'goo.gl' in link:
            suspecte.append(f"URL scurtat: {link}")
            continue
        
        # Verificare domenii suspecte
        try:
            parsed = urlparse(link)
            domain = parsed.netloc
            
            if verificare_domeniu(domain):
                suspecte.append(f"Domeniu suspect: {domain}")
            
            # Verificare URL-uri care imită site-uri legitime
            for site in ['paypal', 'google', 'microsoft', 'facebook', 'apple', 'amazon']:
                if site in domain and site not in domain.split('.')[0]:
                    suspecte.append(f"Posibil phishing care imită {site}: {domain}")
        except:
            pass
    
    return suspecte

def verificare_atasamente(parts):
    """Verifică atașamentele pentru tipuri de fișiere periculoase"""
    atasamente_suspecte = []
    
    for part in parts:
        if part.get('filename'):
            nume_fisier = part.get('filename', '')
            
            # Verificare extensie periculoasă
            for ext in EXTENSII_PERICULOASE:
                if nume_fisier.lower().endswith(ext):
                    atasamente_suspecte.append(f"Atașament periculos: {nume_fisier}")
                    break
            
            # Verificare atașamente ZIP (pot conține malware)
            if nume_fisier.lower().endswith('.zip'):
                atasamente_suspecte.append(f"Arhivă ZIP (verificați conținutul): {nume_fisier}")
            
            # Verificare documente Office (potențiale macro-uri)
            if nume_fisier.lower().endswith(('.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm')):
                atasamente_suspecte.append(f"Document Office (posibil cu macro-uri): {nume_fisier}")
                
            # Verificare PDF (pot conține JavaScript)
            if nume_fisier.lower().endswith('.pdf'):
                atasamente_suspecte.append(f"Document PDF (verificați conținutul): {nume_fisier}")
    
    return atasamente_suspecte

def analiza_email(service, email_id):
    """Analizează un email individual"""
    rezultat = {
        'probleme_header': [],
        'continut_suspect': [],
        'linkuri_suspecte': [],
        'atasamente_suspecte': [],
        'scor_pericol': 0
    }
    
    # Obține emailul complet cu toate părțile și headerele
    email = service.users().messages().get(userId='me', id=email_id, format='full').execute()
    
    # Analiza header-elor
    headers = email['payload']['headers']
    rezultat['probleme_header'] = verificare_spf_dkim_dmarc(headers)
    
    # Extrage expeditorul
    expeditor = next((h['value'] for h in headers if h['name'].lower() == 'from'), '')
    domain_expeditor = re.search(r'@([^>]+)', expeditor)
    
    if domain_expeditor:
        domain = domain_expeditor.group(1)
        if verificare_domeniu(domain):
            rezultat['probleme_header'].append(f"Domeniu expeditor suspect: {domain}")
    
    # Analiza subiectului
    subiect = next((h['value'] for h in headers if h['name'].lower() == 'subject'), '')
    cuvinte_suspecte_subiect = verificare_continut_text(subiect)
    if cuvinte_suspecte_subiect:
        rezultat['continut_suspect'].append(f"Subiect suspect: {', '.join(cuvinte_suspecte_subiect)}")
    
    # Funcție auxiliară pentru a extrage text din payload
    def get_text_from_part(part):
        if 'body' in part and 'data' in part['body']:
            data = part['body']['data']
            text = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
            return text
        return ""
    
    # Funcție auxiliară pentru a procesa recursiv părțile emailului
    def process_parts(part, parts_list):
        if 'parts' in part:
            for subpart in part['parts']:
                process_parts(subpart, parts_list)
        else:
            parts_list.append(part)
    
    # Colectăm toate părțile emailului
    all_parts = []
    if 'parts' in email['payload']:
        for part in email['payload']['parts']:
            process_parts(part, all_parts)
    else:
        all_parts.append(email['payload'])
    
    # Extrage textul din părțile emailului
    text_content = ""
    html_content = ""
    attachment_parts = []
    
    for part in all_parts:
        mime_type = part.get('mimeType', '')
        
        if mime_type == 'text/plain':
            text_content += get_text_from_part(part)
        elif mime_type == 'text/html':
            html_content += get_text_from_part(part)
        elif 'filename' in part and part.get('filename'):
            attachment_parts.append(part)
    
    # Analizează conținutul text
    if text_content:
        cuvinte_suspecte = verificare_continut_text(text_content)
        if cuvinte_suspecte:
            rezultat['continut_suspect'].append(f"Text suspect: {', '.join(cuvinte_suspecte)}")
    
    # Analizează conținutul HTML
    if html_content:
        cuvinte_suspecte_html = verificare_continut_text(html_content)
        if cuvinte_suspecte_html:
            rezultat['continut_suspect'].extend([c for c in cuvinte_suspecte_html if c not in rezultat['continut_suspect']])
    
    # Analizează linkurile
    linkuri = []
    if text_content:
        linkuri.extend(extrage_linkuri(text_content))
    if html_content:
        linkuri.extend(extrage_linkuri(html_content))
    
    rezultat['linkuri_suspecte'] = verificare_linkuri(linkuri)
    
    # Analizează atașamentele
    rezultat['atasamente_suspecte'] = verificare_atasamente(attachment_parts)
    
    # Calculează scorul de pericol (0-10)
    scor = 0
    scor += len(rezultat['probleme_header']) * 2  # Probleme de header sunt foarte importante
    scor += len(rezultat['continut_suspect'])
    scor += len(rezultat['linkuri_suspecte']) * 1.5
    scor += len(rezultat['atasamente_suspecte']) * 2  # Atașamentele sunt foarte periculoase
    
    rezultat['scor_pericol'] = min(10, scor)  # Limitează scorul la 10
    
    return rezultat

def scanare_emailuri(numar_emailuri=50):
    """Scanează emailurile și identifică potențiale amenințări"""
    try:
        service = autentificare_google()
        
        # Obține lista de emailuri
        results = service.users().messages().list(userId='me', maxResults=numar_emailuri).execute()
        messages = results.get('messages', [])
        
        if not messages:
            print("Nu s-au găsit emailuri.")
            return
        
        emailuri_suspecte = []
        
        print(f"Scanare {len(messages)} emailuri...")
        
        for i, message in enumerate(messages):
            msg_id = message['id']
            print(f"Scanarea emailului {i+1}/{len(messages)}...")
            
            # Obține și analizează emailul
            email_data = service.users().messages().get(userId='me', id=msg_id, format='metadata').execute()
            headers = email_data['payload']['headers']
            
            subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), '(Fără subiect)')
            from_email = next((h['value'] for h in headers if h['name'].lower() == 'from'), '(Expeditor necunoscut)')
            
            # Analizează emailul complet
            rezultate = analiza_email(service, msg_id)
            
            # Dacă emailul are probleme, îl adaugă la lista de emailuri suspecte
            if rezultate['scor_pericol'] > 3:  # Pragul de 3 poate fi ajustat
                emailuri_suspecte.append({
                    'id': msg_id,
                    'subiect': subject,
                    'expeditor': from_email,
                    'rezultate': rezultate
                })
        
        # Sortează emailurile după scorul de pericol
        emailuri_suspecte.sort(key=lambda x: x['rezultate']['scor_pericol'], reverse=True)
        
        # Afișează raportul
        print("\n=== RAPORT SCANARE EMAILURI ===")
        print(f"Emailuri scanate: {len(messages)}")
        print(f"Emailuri potențial periculoase detectate: {len(emailuri_suspecte)}")
        
        if emailuri_suspecte:
            print("\nEmailuri suspecte (ordonate după risc):")
            for i, email in enumerate(emailuri_suspecte):
                print(f"\n{i+1}. Scor de pericol: {email['rezultate']['scor_pericol']}/10")
                print(f"   Subiect: {email['subiect']}")
                print(f"   Expeditor: {email['expeditor']}")
                
                if email['rezultate']['probleme_header']:
                    print("   Probleme header:")
                    for problema in email['rezultate']['probleme_header']:
                        print(f"     - {problema}")
                
                if email['rezultate']['continut_suspect']:
                    print("   Conținut suspect:")
                    for problema in email['rezultate']['continut_suspect']:
                        print(f"     - {problema}")
                
                if email['rezultate']['linkuri_suspecte']:
                    print("   Linkuri suspecte:")
                    for problema in email['rezultate']['linkuri_suspecte']:
                        print(f"     - {problema}")
                
                if email['rezultate']['atasamente_suspecte']:
                    print("   Atașamente suspecte:")
                    for problema in email['rezultate']['atasamente_suspecte']:
                        print(f"     - {problema}")
        
        # Salvează rezultatele într-un fișier JSON
        with open('rezultate_scanare_email.json', 'w', encoding='utf-8') as f:
            json.dump({
                'total_emailuri': len(messages),
                'emailuri_suspecte': len(emailuri_suspecte),
                'detalii': emailuri_suspecte
            }, f, ensure_ascii=False, indent=4)
        
        print("\nRezultatele au fost salvate în fișierul 'rezultate_scanare_email.json'")
        
    except Exception as e:
        print(f"Eroare: {str(e)}")

if __name__ == "__main__":
    print("=== SCANNER EMAILURI SUSPECTE ===")
    print("Acest program va analiza emailurile din contul tău Gmail pentru a detecta potențiale amenințări.")
    print("Va trebui să autorizezi accesul la contul tău Gmail prin browser.")
    
    print("\nAlege o opțiune de scanare:")
    print("1. Scanează primele 50 de emailuri")
    print("2. Scanează primele 100 de emailuri")
    print("3. Scanează primele 200 de emailuri")
    print("4. Scanează primele 400 de emailuri")
    print("5. Scanează primele 500 de emailuri")
    print("6. Specificați manual numărul de emailuri")
    
    optiuni_scanare = {
        "1": 50,
        "2": 100,
        "3": 200,
        "4": 400,
        "5": 500
    }
    
    while True:
        optiune = input("\nIntroduceți numărul opțiunii (1-6): ")
        
        if optiune in optiuni_scanare:
            numar = optiuni_scanare[optiune]
            print(f"\nSe vor scana primele {numar} emailuri...")
            break
        elif optiune == "6":
            try:
                numar = int(input("Introduceți numărul de emailuri de scanat: "))
                if numar <= 0:
                    print("Numărul trebuie să fie pozitiv. Se va folosi valoarea implicită de 50.")
                    numar = 50
                print(f"\nSe vor scana primele {numar} emailuri...")
                break
            except ValueError:
                print("Valoare invalidă. Se va folosi valoarea implicită de 50.")
                numar = 50
                break
        else:
            print("Opțiune invalidă. Alegeți o opțiune între 1 și 6.")
    
    print("\nInițierea procesului de autentificare...")
    scanare_emailuri(numar) 
