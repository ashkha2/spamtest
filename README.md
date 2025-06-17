# Mail Server Pentesting Tool

Ein Python-basiertes Tool zum Testen der Sicherheit von Mailservern durch Überprüfung von Authentifizierungsmethoden wie SPF, DMARC und DKIM sowie der Möglichkeit zur Durchführung von Header-Manipulationen. Mit diesem Tool können Sicherheitslücken in der E-Mail-Infrastruktur aufgedeckt werden, die das Risiko von Phishing-Angriffen und anderen Bedrohungen minimieren.

### Funktionen

Das Tool bietet die Möglichkeit, verschiedene Tests auf E-Mail-Server durchzuführen:

1. **Sender = Empfänger (Self-Testing)**  
   - Sendet eine E-Mail an die eigene Adresse, um die Konfiguration der E-Mail-Authentifizierung zu testen. Dies hilft dabei, potenzielle Fehler in der SPF-, DKIM- und DMARC-Implementierung zu erkennen.

2. **Domain-Spoofing (z. B. admin@ihredomain.com)**  
   - Simuliert das Spoofen einer E-Mail-Adresse innerhalb deiner eigenen Domain. Dies hilft zu überprüfen, ob der Mailserver korrekt gegen Domain-Spoofing geschützt ist.

3. **Externe Domain (z. B. security@knowndomains-xyz.com)**  
   - Testet die E-Mail-Sicherheit mit externen Domains und stellt sicher, dass die E-Mail-Authentifizierung auch für eingehende E-Mails von externen Absendern funktioniert.

4. **Benutzerdefinierte Absender-Adresse**  
   - Ermöglicht es dir, eine beliebige Absenderadresse anzugeben, um gezielt zu testen, wie der Mailserver auf E-Mails von nicht autorisierten Absendern reagiert.

---

### Funktionen und Anwendungsmöglichkeiten

- **SPF, DKIM, DMARC Validierung:** Überprüft die korrekte Implementierung und Funktionsweise der gängigen E-Mail-Authentifizierungsmechanismen, um Phishing und Spam zu verhindern.
- **Schutz vor E-Mail-Spoofing:** Testet, ob dein Mailserver richtig konfiguriert ist, um Spoofing-Angriffe abzuwehren.
- **Header-Manipulation:** Ermöglicht das Testen der Handhabung und Validierung von E-Mails, die manipulierte Header oder Absenderadressen enthalten.
- **Erhöhung der Sicherheit:** Hilft dabei, Sicherheitslücken in der E-Mail-Kommunikation zu finden und zu schließen.

---

### **Disclaimer**

**Wichtiger rechtlicher Hinweis:**

- **Verwendung nur auf autorisierten Domains!**  
  Dieses Tool darf **nur auf Domains verwendet werden, für die du explizite Erlaubnis hast**, Tests durchzuführen. Die Durchführung von Tests ohne ausdrückliche Genehmigung des Domaininhabers ist **illegal** und kann strafrechtliche Konsequenzen nach sich ziehen.
  
- **Ethical Hacking:**  
  Das Tool ist ausschließlich für **ethische Hacking-Zwecke** gedacht, um die Sicherheit von E-Mail-Servern zu verbessern. Verwende es nur auf Servern, bei denen du die ausdrückliche Genehmigung hast.

- **Haftungsausschluss:**  
  Der Entwickler dieses Tools übernimmt keinerlei Verantwortung für die Verwendung des Tools außerhalb der erlaubten, ethischen Rahmenbedingungen. Die **Verantwortung für die Nutzung** liegt ausschließlich beim Benutzer.

- **Rechtliche Verantwortung:**  
  Unbefugte Tests, die gegen Gesetze und Vorschriften verstoßen, sind **illegal** und können zu rechtlichen Konsequenzen führen.

---

### Installation

1. **Repository klonen**  
   Klone das Repository mit Git:
   ```bash
   git clone https://github.com/dein-benutzername/mail-server-pentest-tool.git


2. **Abhängigkeiten installieren**  
   ```bash
    pip install -r requirements.txt

3. **Ausführen**
   ```bash
   python SPFreak.py
