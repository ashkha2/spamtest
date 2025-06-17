#!/usr/bin/env python3
"""
Robuste E-Mail Security Test Script
Für das Testen von Spam-Filtern und SPF-Validierung
Nur für autorisierte Penetrationstests verwenden!
"""

import smtplib
import paramiko
import tempfile
import os
import socket
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate, make_msgid
from email.header import Header
import random
import string
import logging

# Logging konfigurieren
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EmailSecurityTester:
    def __init__(self):
        self.spam_subjects = [
            "URGENT: Ihr Konto wurde gesperrt!",
            "Bestätigen Sie Ihre Identität - Sofort erforderlich",
            "Sicherheitswarnung: Verdächtige Anmeldung erkannt",
            "Ihr E-Mail-Speicher ist voll - Jetzt erweitern",
            "Wichtige Mitteilung von der IT-Abteilung"
        ]

    def test_smtp_connection(self, smtp_server, port, username, password):
        """
        Testet die SMTP-Verbindung
        """
        try:
            logger.info(f"Teste SMTP-Verbindung zu {smtp_server}:{port}")
            server = smtplib.SMTP(smtp_server, port, timeout=30)
            server.set_debuglevel(1)  # Debug-Modus aktivieren
            
            logger.info("Starte STARTTLS...")
            server.starttls()
            
            logger.info("Authentifiziere...")
            server.login(username, password)
            
            logger.info("✓ SMTP-Verbindung erfolgreich!")
            server.quit()
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"✗ Authentifizierungsfehler: {e}")
            return False
        except smtplib.SMTPConnectError as e:
            logger.error(f"✗ Verbindungsfehler: {e}")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"✗ SMTP-Fehler: {e}")
            return False
        except Exception as e:
            logger.error(f"✗ Unbekannter Fehler: {e}")
            return False

    def create_spoofed_email(self, to_email, manipulation_type="same_address", custom_from=None):
        """
        Erstellt eine E-Mail mit Header-Spoofing
        """
        msg = MIMEMultipart('alternative')
        
        # Basis-Konfiguration
        username = to_email.split('@')[0]
        domain = to_email.split('@')[1]
        
        # Header-Manipulation basierend auf Typ
        if manipulation_type == "custom_sender" and custom_from:
            # Benutzerdefinierte Absender-Adresse
            from_addr = custom_from
            sender_addr = custom_from
            reply_to = custom_from
            logger.info(f"Manipulation: Benutzerdefiniert ({custom_from})")
            
        elif manipulation_type == "same_address":
            # Sender = Empfänger
            from_addr = to_email
            sender_addr = to_email
            reply_to = to_email
            logger.info(f"Manipulation: Sender = Empfänger ({to_email})")
            
        elif manipulation_type == "domain_spoofing":
            # Gleiche Domain, anderer Benutzer
            fake_users = ['admin', 'security', 'noreply', 'support', 'postmaster', 'info']
            fake_user = random.choice(fake_users)
            from_addr = f"{fake_user}@{domain}"
            sender_addr = from_addr
            reply_to = from_addr
            logger.info(f"Manipulation: Domain-Spoofing ({from_addr})")
            
        elif manipulation_type == "external_spoof":
            # Externe Domain vortäuschen
            fake_domains = ['gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com']
            fake_domain = random.choice(fake_domains)
            from_addr = f"security@{fake_domain}"
            sender_addr = from_addr
            reply_to = from_addr
            logger.info(f"Manipulation: Externe Domain ({from_addr})")
        
        # Standard-Header setzen
        msg['From'] = from_addr
        msg['To'] = to_email
        msg['Subject'] = Header(random.choice(self.spam_subjects), 'utf-8')
        msg['Date'] = formatdate(localtime=True)
        msg['Message-ID'] = make_msgid(domain=domain.split('@')[-1] if '@' in from_addr else domain)
        
        # Erweiterte Header für Spoofing
        msg['Sender'] = sender_addr
        msg['Reply-To'] = reply_to
        msg['Return-Path'] = f"<{sender_addr}>"
        
        # Verdächtige Header hinzufügen
        suspicious_headers = {
            'X-Mailer': 'Microsoft Outlook 16.0',  # Vortäuschen legitimer Software
            'X-Priority': '1',
            'X-MSMail-Priority': 'High',
            'Importance': 'High',
            'X-MimeOLE': 'Produced By Microsoft MimeOLE V16.0',
            'X-Originating-IP': f"[{self.generate_random_private_ip()}]",
            'X-Source-IP': self.generate_random_private_ip(),
            'Thread-Topic': random.choice(self.spam_subjects),
            'Thread-Index': self.generate_random_string(32),
        }
        
        # Gefälschte Authentication-Results
        auth_results = f"spf=fail (sender IP is {self.generate_random_ip()}) smtp.mailfrom={from_addr}; dkim=fail; dmarc=fail"
        msg['Authentication-Results'] = auth_results
        
        # Zufällige Header hinzufügen
        for header, value in random.sample(list(suspicious_headers.items()), k=random.randint(3, 6)):
            msg[header] = value
            
        # Personalized body content
        body_html = self.create_html_phishing_body(username, domain, from_addr)
        body_text = self.create_text_phishing_body(username, domain, from_addr)
        
        # Text und HTML Teile hinzufügen
        msg.attach(MIMEText(body_text, 'plain', 'utf-8'))
        msg.attach(MIMEText(body_html, 'html', 'utf-8'))
        
        return msg

    def create_text_phishing_body(self, username, domain, from_addr):
        """Erstellt Text-Version der Phishing-E-Mail"""
        templates = [
            f"""
Hallo {username},

wir haben verdächtige Aktivitäten in Ihrem {domain}-Konto festgestellt.

Jemand hat versucht, sich von folgender IP-Adresse anzumelden:
IP: {self.generate_random_ip()}
Standort: Unbekannt
Zeit: {formatdate(localtime=True)}

Um Ihr Konto zu schützen, wurde es temporär gesperrt.

Bestätigen Sie Ihre Identität hier:
https://security-{domain.replace('.', '-')}.verify-account.com/login

Falls Sie diese Anmeldung nicht versucht haben, ignorieren Sie diese E-Mail.

Mit freundlichen Grüßen,
Sicherheitsteam {domain}

Diese E-Mail wurde von {from_addr} gesendet.
            """,
            f"""
Sehr geehrte/r {username},

Ihr E-Mail-Postfach bei {domain} ist zu 95% voll.

Aktuelle Speichernutzung: 14.3 GB von 15 GB

Ohne sofortige Maßnahmen werden neue E-Mails abgewiesen!

Erweitern Sie Ihren Speicher kostenfrei:
https://storage-{domain.replace('.', '-')}.upgrade-now.com/expand

Diese Aktion muss binnen 24 Stunden erfolgen.

Support-Team {domain}
{from_addr}
            """
        ]
        return random.choice(templates)

    def create_html_phishing_body(self, username, domain, from_addr):
        """Erstellt HTML-Version der Phishing-E-Mail"""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Sicherheitswarnung</title>
</head>
<body style="font-family: Arial, sans-serif; background-color: #f5f5f5; padding: 20px;">
    <div style="max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
        <div style="text-align: center; margin-bottom: 30px;">
            <h1 style="color: #d73502; font-size: 24px;">⚠️ SICHERHEITSWARNUNG</h1>
        </div>
        
        <p>Hallo <strong>{username}</strong>,</p>
        
        <p>Wir haben <span style="color: red; font-weight: bold;">verdächtige Aktivitäten</span> 
        in Ihrem <strong>{domain}</strong>-Konto festgestellt.</p>
        
        <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 20px 0; border-radius: 4px;">
            <strong>Verdächtige Anmeldung:</strong><br>
            IP-Adresse: {self.generate_random_ip()}<br>
            Standort: Unbekannt<br>
            Zeit: {formatdate(localtime=True)}
        </div>
        
        <p>Zur Sicherheit wurde Ihr Konto temporär gesperrt.</p>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://security-{domain.replace('.', '-')}.verify-account.com/login" 
               style="background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold;">
                Konto entsperren
            </a>
        </div>
        
        <p style="font-size: 12px; color: #666; margin-top: 30px;">
            Falls Sie diese Anmeldung nicht versucht haben, ignorieren Sie diese E-Mail.<br>
            Diese Nachricht wurde von {from_addr} gesendet.
        </p>
        
        <hr style="margin: 20px 0; border: none; border-top: 1px solid #eee;">
        <p style="font-size: 10px; color: #999;">
            Sicherheitsteam {domain} | Automatisch generierte E-Mail
        </p>
    </div>
</body>
</html>
        """

    def generate_random_ip(self):
        """Generiert eine zufällige öffentliche IP"""
        return f"{random.randint(1,223)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)}"
    
    def generate_random_private_ip(self):
        """Generiert eine zufällige private IP"""
        ranges = ['192.168', '10.0', '172.16']
        base = random.choice(ranges)
        return f"{base}.{random.randint(1,255)}.{random.randint(1,254)}"
    
    def generate_random_string(self, length):
        """Generiert einen zufälligen String"""
        chars = string.ascii_uppercase + string.digits
        return ''.join(random.choices(chars, k=length))

    def send_test_emails(self, smtp_server, port, username, password, to_email, count=1, manipulation_type="same_address", custom_from=None):
        """
        Sendet Test-E-Mails mit verbesserter Fehlerbehandlung
        """
        try:
            logger.info(f"Verbinde zu SMTP-Server {smtp_server}:{port}")
            server = smtplib.SMTP(smtp_server, port, timeout=60)
            server.set_debuglevel(0)  # Debug nur bei Bedarf
            
            # TLS starten
            if port != 25:  # Nur wenn nicht Port 25 (unverschlüsselt)
                server.starttls()
            
            # Authentifizierung
            server.login(username, password)
            logger.info("✓ SMTP-Authentifizierung erfolgreich")
            
            successful_sends = 0
            
            for i in range(count):
                try:
                    # E-Mail erstellen
                    msg = self.create_spoofed_email(to_email, manipulation_type, custom_from)
                    
                    logger.info(f"\n--- E-Mail {i+1}/{count} ---")
                    logger.info(f"Von: {msg['From']}")
                    logger.info(f"An: {msg['To']}")
                    logger.info(f"Betreff: {msg['Subject']}")
                    logger.info(f"Manipulation: {manipulation_type}")
                    
                    # E-Mail senden
                    refused = server.send_message(msg)
                    
                    if refused:
                        logger.warning(f"Einige Empfänger abgelehnt: {refused}")
                    else:
                        logger.info(f"✓ E-Mail {i+1} erfolgreich gesendet")
                        successful_sends += 1
                    
                    # Kurze Pause zwischen E-Mails
                    if i < count - 1:
                        time.sleep(2)
                        
                except Exception as e:
                    logger.error(f"✗ Fehler bei E-Mail {i+1}: {e}")
                    continue
            
            server.quit()
            logger.info(f"\n=== Zusammenfassung ===")
            logger.info(f"Erfolgreich gesendet: {successful_sends}/{count}")
            
            return successful_sends > 0
            
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"✗ Authentifizierungsfehler: {e}")
            logger.error("Prüfen Sie Benutzername und Passwort")
            return False
        except smtplib.SMTPConnectError as e:
            logger.error(f"✗ Verbindungsfehler: {e}")
            logger.error("Prüfen Sie Server und Port")
            return False
        except Exception as e:
            logger.error(f"✗ Unerwarteter Fehler: {e}")
            return False

def get_smtp_config():
    """
    Hilft bei der SMTP-Konfiguration
    """
    print("\n=== SMTP-Konfiguration ===")
    print("Häufige SMTP-Einstellungen:")
    print("Gmail: smtp.gmail.com:587 (App-Passwort erforderlich)")
    print("Outlook: smtp-mail.outlook.com:587")
    print("Yahoo: smtp.mail.yahoo.com:587")
    print("Eigener Server: Ihre SMTP-Einstellungen")
    
    smtp_server = input("\nSMTP-Server: ").strip()
    smtp_port = int(input("SMTP-Port (587): ").strip() or "587")
    
    print("\nAuthentifizierung:")
    smtp_user = input("Benutzername/E-Mail: ").strip()
    smtp_pass = input("Passwort: ").strip()
    
    return smtp_server, smtp_port, smtp_user, smtp_pass

def main():
    print("=== Erweiterte E-Mail Security Tester ===")
    print("WARNUNG: Nur für autorisierte Penetrationstests verwenden!")
    print("Stellen Sie sicher, dass Sie die Berechtigung haben!\n")
    
    tester = EmailSecurityTester()
    
    # Ziel-E-Mail
    to_email = input("Ziel-E-Mail-Adresse (Ihre Test-Adresse): ").strip()
    if not to_email or '@' not in to_email:
        print("✗ Ungültige E-Mail-Adresse")
        return
    
    # SMTP-Konfiguration
    smtp_server, smtp_port, smtp_user, smtp_pass = get_smtp_config()
    
    # Verbindung testen
    print(f"\nTeste Verbindung zu {smtp_server}:{smtp_port}...")
    if not tester.test_smtp_connection(smtp_server, smtp_port, smtp_user, smtp_pass):
        print("✗ SMTP-Verbindung fehlgeschlagen. Prüfen Sie die Einstellungen.")
        return
    
    # Manipulation wählen
    print("\n=== Header-Manipulation wählen ===")
    print("1 = Sender = Empfänger (Sie senden an sich selbst)")
    print("2 = Domain-Spoofing (admin@ihredomain.com)")  
    print("3 = Externe Domain (security@gmail.com)")
    print("4 = Benutzerdefinierte Absender-Adresse")
    
    manipulation_choice = input("Manipulation (1-4): ").strip()
    manipulation_map = {
        "1": "same_address",
        "2": "domain_spoofing", 
        "3": "external_spoof",
        "4": "custom_sender"
    }
    manipulation_type = manipulation_map.get(manipulation_choice, "same_address")
    
    # Benutzerdefinierte Absender-Adresse
    custom_from = None
    if manipulation_type == "custom_sender":
        print("\n=== Benutzerdefinierte Absender-Adresse ===")
        print("Beispiele für interessante Tests:")
        print("• CEO@ihrefirma.com (Vortäuschen des Chefs)")
        print("• noreply@microsoft.com (Bekannte Marke)")
        print("• security@paypal.com (Sicherheitswarnung)")
        print("• admin@bank.de (Finanzinstitut)")
        print("• support@amazon.com (Online-Shop)")
        
        while True:
            custom_from = input("\nAbsender-E-Mail eingeben: ").strip()
            if '@' in custom_from and '.' in custom_from.split('@')[1]:
                break
            else:
                print("✗ Ungültige E-Mail-Adresse, bitte erneut eingeben")
        
        print(f"✓ Verwende Absender: {custom_from}")
    
    # Anzahl E-Mails
    count = int(input("\nAnzahl Test-E-Mails (1-5): ").strip() or "1")
    count = min(count, 5)  # Maximum 5 für Tests
    
    # E-Mails senden
    print(f"\nSende {count} Test-E-Mail(s) mit {manipulation_type}...")
    if custom_from:
        print(f"Absender: {custom_from}")
    
    success = tester.send_test_emails(smtp_server, smtp_port, smtp_user, smtp_pass, 
                                    to_email, count, manipulation_type, custom_from)
    
    if success:
        print("\n=== Test abgeschlossen ===")
        print("Überprüfen Sie nun Ihr E-Mail-Postfach:")
        print("✓ Sind die E-Mails angekommen?")
        print("✓ Wurden sie als Spam/Phishing erkannt?")
        print("✓ Sind sie im Junk-Ordner?")
        print("✓ Zeigen die Header SPF/DKIM/DMARC-Fehler?")
        print("\nTipp: Analysieren Sie die vollständigen Header der E-Mails!")
    else:
        print("\n✗ Test fehlgeschlagen. Prüfen Sie die Konfiguration.")

if __name__ == "__main__":
    main()