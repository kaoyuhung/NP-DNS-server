# Network Programming Project
* A simple DNS server
* Can load zone files and respond DNS queries.

## Test

```
> g++ dnscpp -o dns.out
> ./dns.out <port #> </path/to/config_file>
```

## EX:
* Terminal 1:
```
> ./dns.out 10003 config.txt
```

* Terminal 2:
```
> dig @localhost -p 10003 example1.org ns
;; Warning: query response not set

; <<>> DiG 9.18.18-0ubuntu0.22.04.1-Ubuntu <<>> @localhost -p 10003 example1.org ns
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: FORMERR, id: 27882
;; flags: rd ad; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 5
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: 3b99e1adf90a544c (echoed)
;; QUESTION SECTION:
;example1.org.                  IN      NS

;; ANSWER SECTION:
example1.org.           3600    IN      NS      dns.example1.org.
example1.org.           3600    IN      NS      dns2.example1.org.
example1.org.           3600    IN      NS      dns3.example1.org.

;; ADDITIONAL SECTION:
dns.example1.org.       3600    IN      A       140.113.123.1
dns2.example1.org.      3600    IN      A       140.113.123.2
dns3.example1.org.      3600    IN      A       140.113.123.3
dns3.example1.org.      3600    IN      A       140.113.123.4

;; Query time: 0 msec
;; SERVER: 127.0.0.1#10003(localhost) (UDP)
;; WHEN: Fri Jan 19 02:35:36 CST 2024
;; MSG SIZE  rcvd: 312
```
