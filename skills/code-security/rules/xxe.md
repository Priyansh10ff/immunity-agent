---
title: Prevent XML External Entity (XXE) Injection
impact: CRITICAL
impactDescription: Attackers can access local files, perform SSRF, or cause denial of service via malicious XML
tags: security, xxe, xml, cwe-611, owasp-a05
attribution: Adapted from https://github.com/semgrep/skills (Apache-2.0)
---

## Prevent XML External Entity (XXE) Injection

XXE occurs when XML input containing a reference to an external entity is processed by a weakly configured XML parser. Attackers can access local files (e.g., `/etc/passwd`), perform SSRF against internal services, or cause denial of service via recursive entity expansion (billion laughs attack).

---

### Java (DocumentBuilderFactory)

**Incorrect (vulnerable to XXE):**
```java
class BadDocumentBuilderFactory {
    public void parseXml() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.newDocumentBuilder();  // Default config allows external entities
    }
}
```

**Correct (XXE disabled):**
```java
class GoodDocumentBuilderFactory {
    public void parseXml() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.newDocumentBuilder();
    }
}
```

**References:**
- CWE-611: Improper Restriction of XML External Entity Reference
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [Semgrep Java XXE Cheat Sheet](https://semgrep.dev/docs/cheat-sheets/java-xxe/)

---

### Python

**Incorrect (native xml library vulnerable to XXE):**
```python
def parse_xml():
    from xml.etree import ElementTree
    tree = ElementTree.parse('data.xml')  # Vulnerable to XXE
    root = tree.getroot()
```

**Correct (use defusedxml):**
```python
def parse_xml():
    from defusedxml.etree import ElementTree
    tree = ElementTree.parse('data.xml')  # Safe: defusedxml disables XXE
    root = tree.getroot()
```

**References:**
- [defusedxml on GitHub](https://github.com/tiran/defusedxml)
- [Python xml Documentation — Security Warning](https://docs.python.org/3/library/xml.html)

---

### JavaScript (libxmljs)

**Incorrect (noent enabled):**
```javascript
var libxmljs = require("libxmljs");

module.exports.parseXml = function(req, res) {
    libxmljs.parseXml(req.body, { noent: true, noblanks: true });  // VULNERABLE
}
```

**Correct (noent disabled):**
```javascript
var libxmljs = require("libxmljs");

module.exports.parseXml = function(req, res) {
    libxmljs.parseXml(req.body, { noent: false, noblanks: true });  // Safe
}
```

---

### C# (XmlReaderSettings)

**Incorrect (DtdProcessing.Parse allows external entities):**
```csharp
public void ParseXml(string input) {
    XmlReaderSettings rs = new XmlReaderSettings();
    rs.DtdProcessing = DtdProcessing.Parse;  // VULNERABLE
    XmlReader myReader = XmlReader.Create(new StringReader(input), rs);
    while (myReader.Read()) { Console.WriteLine(myReader.Value); }
}
```

**Correct (DtdProcessing.Prohibit):**
```csharp
public void ParseXml(string input) {
    XmlReaderSettings rs = new XmlReaderSettings();
    rs.DtdProcessing = DtdProcessing.Prohibit;  // Safe
    XmlReader myReader = XmlReader.Create(new StringReader(input), rs);
    while (myReader.Read()) { Console.WriteLine(myReader.Value); }
}
```

---

### Go (lestrrat-go/libxml2)

**Incorrect (XMLParseNoEnt enables external entities):**
```go
func parseXml() {
    const s = `<!DOCTYPE d [<!ENTITY e SYSTEM "file:///etc/passwd">]><t>&e;</t>`
    p := parser.New(parser.XMLParseNoEnt)  // VULNERABLE
    doc, _ := p.ParseString(s)
    fmt.Println(doc)
}
```

**Correct (no XMLParseNoEnt):**
```go
func parseXml() {
    const s = `<!DOCTYPE d [<!ENTITY e SYSTEM "file:///etc/passwd">]><t>&e;</t>`
    p := parser.New()  // Safe: external entities disabled by default
    doc, _ := p.ParseString(s)
    fmt.Println(doc)
}
```

---

## Key Prevention Rules

1. **Disable DOCTYPE declarations** — block DTD processing entirely if possible
2. **Disable external entity resolution** — never allow `SYSTEM` or `PUBLIC` entity references from untrusted input
3. **Use safe XML libraries** — `defusedxml` (Python), `DtdProcessing.Prohibit` (C#)
4. **Validate XML schema** — use schema validation to restrict XML structure
5. **Reject unexpected content types** — if your API doesn't need XML, reject `application/xml` content types

**References:**
- [CWE-611: XXE](https://cwe.mitre.org/data/definitions/611.html)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [OWASP A05:2021 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [Semgrep Skills](https://github.com/semgrep/skills)
