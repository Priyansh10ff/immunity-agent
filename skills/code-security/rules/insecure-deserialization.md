---
title: Prevent Insecure Deserialization
impact: CRITICAL
impactDescription: Remote code execution — deserializing untrusted data can trigger arbitrary code execution
tags: security, deserialization, rce, cwe-502, owasp-a08
attribution: Curated and enhanced for Prismor
---

## Prevent Insecure Deserialization

Insecure deserialization occurs when untrusted data is deserialized without proper validation. Attackers craft malicious serialized payloads that execute arbitrary code, cause denial of service, or abuse application logic upon deserialization. Never deserialize data from untrusted sources using native serialization formats.

**Vulnerable formats:** Python `pickle`, Ruby `Marshal`, Java `ObjectInputStream`, C# `BinaryFormatter`, PHP `unserialize()`, JavaScript `node-serialize`.

---

### Python (pickle)

**Incorrect (deserializing user-supplied pickle data):**
```python
import pickle
from base64 import b64decode
from flask import Flask, request

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    user_obj = request.cookies.get('uuid')
    return "Hey there! {}!".format(pickle.loads(b64decode(user_obj)))  # VULNERABLE: RCE
```

**Correct (use JSON or load from trusted file only):**
```python
import json
from flask import Flask, request

app = Flask(__name__)

@app.route("/data")
def get_data():
    # Safe: JSON only returns primitive types
    user_data = json.loads(request.data)
    return str(user_data)
```

**References:**
- [Python pickle — Security Warning](https://docs.python.org/3/library/pickle.html)

---

### JavaScript / TypeScript (node-serialize)

**Incorrect (using insecure deserialization libraries):**
```typescript
var node_serialize = require("node-serialize")

module.exports.handler = function (req, res) {
    var data = req.files.products.data.toString('utf8')
    node_serialize.unserialize(data)  // VULNERABLE: allows code execution via IIFE
}
```

**Correct (use JSON.parse for untrusted data):**
```javascript
module.exports.handler = function (req, res) {
    var data = req.body.toString('utf8')
    var parsed = JSON.parse(data)  // Safe: JSON is data-only
    return parsed
}
```

---

### Java (ObjectInputStream)

**Incorrect (deserializing from untrusted stream):**
```java
import java.io.InputStream;
import java.io.ObjectInputStream;

public class Deserializer {
    public Object deserializeObject(InputStream receivedData) throws Exception {
        ObjectInputStream in = new ObjectInputStream(receivedData);
        return in.readObject();  // VULNERABLE: executes gadget chains
    }
}
```

**Correct (use Jackson JSON):**
```java
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;

public class SafeDeserializer {
    public MyClass deserialize(InputStream data) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(data, MyClass.class);  // Safe: type-bound JSON
    }
}
```

---

### Ruby (Marshal / YAML)

**Incorrect (Marshal.load or YAML.load with user input):**
```ruby
def bad_deserialization
    data = params['data']
    obj = Marshal.load(data)  # VULNERABLE: RCE

    yaml_data = params['yaml']
    config = YAML.load(yaml_data)  # VULNERABLE: allows arbitrary object instantiation
end
```

**Correct (use YAML.safe_load or JSON):**
```ruby
def ok_deserialization
    # YAML.safe_load restricts to primitive types
    config = YAML.safe_load(params['yaml'])

    # Or use JSON for untrusted data
    data = JSON.parse(params['data'])
end
```

---

### C# (BinaryFormatter)

**Incorrect (BinaryFormatter is inherently insecure):**
```csharp
using System.Runtime.Serialization.Formatters.Binary;

public class InsecureDeserialization {
    public void Deserialize(string data) {
        BinaryFormatter formatter = new BinaryFormatter();
        MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(data));
        object obj = formatter.Deserialize(stream);  // VULNERABLE
    }
}
```

**Correct (use System.Text.Json):**
```csharp
using System.Text.Json;

public class SafeDeserialization {
    public MyClass Deserialize(string json) {
        return JsonSerializer.Deserialize<MyClass>(json);  // Safe: type-bound JSON
    }
}
```

---

### PHP (unserialize)

**Incorrect (unserializing user-controlled data):**
```php
<?php
$data = $_GET["data"];
$object = unserialize($data);  // VULNERABLE: object injection / RCE
```

**Correct (use json_decode for untrusted input):**
```php
<?php
$object = json_decode($_GET["data"], true);  // Safe: returns associative array
```

---

## General Prevention Guidelines

1. **Never deserialize untrusted data** — treat all external data as potentially malicious
2. **Use JSON for data interchange** — JSON only returns primitive types (strings, arrays, numbers, null)
3. **Implement integrity checks** — sign serialized data with HMACs to detect tampering before deserialization
4. **Use allowlists for deserialization** — if you must deserialize, restrict to specific known-safe classes
5. **Avoid native serialization formats** — pickle, Marshal, ObjectInputStream, BinaryFormatter are all dangerous with untrusted data
6. **Use safe YAML loaders** — always use `YAML.safe_load` / `SafeLoader`, never bare `YAML.load`
7. **Monitor and log** — alert on unexpected deserialization attempts

**References:**
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [OWASP A08:2021 Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
- [Prismor](https://github.com/PrismorSec/prismor)
