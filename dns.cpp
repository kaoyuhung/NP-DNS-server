#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <netinet/in.h>
#include <regex.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cctype>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>
#define MAXLINE 2048
using namespace std;
typedef struct sockaddr SA;
typedef struct {
    uint16_t ID;
    uint8_t QR : 1;
    uint8_t OPCODE : 4;
    uint8_t AA : 1;
    uint8_t TC : 1;
    uint8_t RD : 1;
    uint8_t RA : 1;
    uint8_t Z : 3;
    uint8_t RCODE : 4;
    uint16_t QDCNT;
    uint16_t ANCNT;
    uint16_t NSCNT;
    uint16_t ARCNT;
} __attribute((packed)) header_t;
typedef struct {
    uint16_t type;
    uint16_t Class;
    uint32_t ttl;
    uint16_t rd_length;
} __attribute((packed)) RR_data;
typedef struct {
    uint32_t serial_n;
    uint32_t refreash_n;
    uint32_t retry_n;
    uint32_t expire_n;
    uint32_t minimum_n;
} __attribute((packed)) SOA_data;
string foreign_srv;
set<string> domains;
unordered_map<string, vector<string>> NS_names;
unordered_map<string, vector<string>> MX_names;
unordered_map<string, string> subDOMAIN_DOMAIN;
unordered_map<string, vector<pair<int, char *>>> A_mp, AAAA_mp, NS_mp, MX_mp, TXT_mp, CNAME_mp;
unordered_map<string, pair<int, char *>> SOA_mp;
unordered_map<string, uint16_t> QTYPE_num;
char *Fgets(char *buf, int n, FILE *fp) {
    char *re = fgets(buf, n, fp);
    if (!re)
        return re;
    for (int i = (int)strlen(buf) - 1; i >= 0; i--) {
        if (isprint(buf[i])) {
            buf[i + 1] = '\0';
            break;
        }
    }
    return re;
}
int name_formatting(char *host) {
    char host_cp[50] = {0};
    memcpy(host_cp, host, (int)strlen(host));
    memset(host, 0, 50);
    char *tmp = strtok(host_cp, ".");
    int idx = 0, len;
    while (tmp != NULL) {
        len = (int)strlen(tmp);
        host[idx] = len;
        strncat(host + idx + 1, tmp, len);
        idx += (len + 1);
        tmp = strtok(NULL, ".");
    }
    return idx + 1;
}
void init(char *config_file) {
    QTYPE_num["A"] = 1;
    QTYPE_num["AAAA"] = 28;
    QTYPE_num["NS"] = 2;
    QTYPE_num["CNAME"] = 5;
    QTYPE_num["SOA"] = 6;
    QTYPE_num["MX"] = 15;
    QTYPE_num["TXT"] = 16;
    int n;
    char buf[500], *zone_txt, buff[200];
    FILE *fp = fopen(config_file, "r");
    Fgets(buff, sizeof(buff), fp);
    // sprintf(buf, "sudo sh -c 'echo nameserver %s > /etc/resolv.conf'", buff);
    // system(buf);
    // foreign_srv = string(buff);
    while (Fgets(buf, 500, fp)) {
        for (int i = 0; i < (int)strlen(buf); i++) {
            if (buf[i] == ',') {
                buf[i] = '\0';
                zone_txt = buf + i + 1;
                break;
            }
        }
        string domain(buf);
        domains.insert(domain);
        subDOMAIN_DOMAIN["www." + domain] = domain;
        subDOMAIN_DOMAIN["dns." + domain] = domain;
        subDOMAIN_DOMAIN["mail." + domain] = domain;
        FILE *fp2 = fopen(zone_txt, "r");
        Fgets(buf, sizeof(buf), fp2);
        RR_data rr_data;
        puts("Infomation in the zone file:");
        while (Fgets(buf, sizeof(buf), fp2)) {
            char *name, *TTL, *CLASS, *TYPE, *RDATA;
            name = strtok(buf, ",");
            TTL = strtok(NULL, ",");
            CLASS = strtok(NULL, ",");
            TYPE = strtok(NULL, ",");
            RDATA = strtok(NULL, ",");
            printf("%s %s %s %s %s\n", name, TTL, CLASS, TYPE, RDATA);
            rr_data.type = htons(QTYPE_num[string(TYPE)]);
            rr_data.Class = htons(1);
            rr_data.ttl = htonl(atoi(TTL));
            char *buf;
            if (!strcmp(TYPE, "A")) {
                uint32_t ipv4;
                rr_data.rd_length = htons(4);
                inet_pton(AF_INET, RDATA, &ipv4);
                string sub_domain = string(name) + "." + domain;
                subDOMAIN_DOMAIN[sub_domain] = domain;
                buf = (char *)malloc(10 + rr_data.rd_length);
                memcpy(buf, &rr_data, sizeof(RR_data));
                memcpy(buf + sizeof(RR_data), &ipv4, sizeof(uint32_t));
                A_mp[sub_domain].push_back(make_pair((int)sizeof(RR_data) + 4, buf));
            } else if (!strcmp(TYPE, "AAAA")) {
                char ipv6[16];
                rr_data.rd_length = htons(16);
                inet_pton(AF_INET6, RDATA, ipv6);
                string sub_domain = string(name) + "." + domain;
                subDOMAIN_DOMAIN[sub_domain] = domain;
                buf = (char *)malloc(10 + ntohs(rr_data.rd_length));
                memcpy(buf, &rr_data, sizeof(RR_data));
                memcpy(buf + sizeof(RR_data), ipv6, 16);
                AAAA_mp[sub_domain].push_back(make_pair((int)sizeof(RR_data) + 16, buf));
            } else if (!strcmp(TYPE, "NS")) {
                NS_names[domain].push_back(string(RDATA));
                char autho_name_srv[50];
                strcpy(autho_name_srv, RDATA);
                int len1 = name_formatting(autho_name_srv);
                rr_data.rd_length = htons(len1);
                buf = (char *)malloc(10 + ntohs(rr_data.rd_length));
                memcpy(buf, &rr_data, sizeof(RR_data));
                memcpy(buf + sizeof(RR_data), autho_name_srv, len1);
                NS_mp[domain].push_back(make_pair((int)sizeof(RR_data) + len1, buf));
            } else if (!strcmp(TYPE, "SOA")) {
                SOA_data soa_d;
                char host[50], admin[50];
                char serial[20], refresh[20], retry[20], expire[20], minimum[20];
                sscanf(RDATA, "%s %s %s %s %s %s %s", host, admin, serial, refresh, retry, expire, minimum);
                int len1 = name_formatting(host), len2 = name_formatting(admin);
                rr_data.rd_length = htons(len1 + len2 + 20);
                soa_d.serial_n = htonl(atoi(serial));
                soa_d.refreash_n = htonl(atoi(refresh));
                soa_d.retry_n = htonl(atoi(retry));
                soa_d.expire_n = htonl(atoi(expire));
                soa_d.minimum_n = htonl(atoi(minimum));
                buf = (char *)malloc(10 + ntohs(rr_data.rd_length));
                memcpy(buf, &rr_data, sizeof(RR_data));
                memcpy(buf + sizeof(RR_data), host, len1);
                memcpy(buf + sizeof(RR_data) + len1, admin, len2);
                memcpy(buf + sizeof(RR_data) + len1 + len2, &soa_d, sizeof(SOA_data));
                SOA_mp[domain] = make_pair((int)sizeof(RR_data) + len1 + len2 + (int)sizeof(SOA_data), buf);
            } else if (!strcmp(TYPE, "MX")) {
                uint16_t preference;
                char mail_ex[50];
                sscanf(RDATA, "%hu %s", &preference, mail_ex);
                MX_names[domain].push_back(string(mail_ex));
                preference = htons(preference);
                int len = name_formatting(mail_ex);
                rr_data.rd_length = htons(2 + len);
                buf = (char *)malloc(10 + ntohs(rr_data.rd_length));
                memcpy(buf, &rr_data, sizeof(RR_data));
                memcpy(buf + sizeof(RR_data), &preference, 2);
                memcpy(buf + sizeof(RR_data) + 2, mail_ex, len);
                MX_mp[domain].push_back(make_pair((int)sizeof(RR_data) + 2 + len, buf));
            } else if (!strcmp(TYPE, "TXT")) {
                uint8_t len = (uint8_t)strlen(RDATA);
                rr_data.rd_length = htons(len + 1);
                buf = (char *)malloc(10 + ntohs(rr_data.rd_length));
                memcpy(buf, &rr_data, sizeof(RR_data));
                memcpy(buf + sizeof(RR_data), &len, 1);
                memcpy(buf + sizeof(RR_data) + 1, RDATA, len);
                TXT_mp[domain].push_back(make_pair((int)sizeof(RR_data) + 1 + len, buf));
            } else if (!strcmp(TYPE, "CNAME")) {
                string sub_domain = string(name) + "." + domain;
                subDOMAIN_DOMAIN[sub_domain] = domain;
                char *CNAME = RDATA;
                int tmp_len = (uint16_t)name_formatting(CNAME);
                rr_data.rd_length = htons(tmp_len);
                buf = (char *)malloc(10 + tmp_len);
                memcpy(buf, &rr_data, sizeof(RR_data));
                memcpy(buf + sizeof(RR_data), CNAME, tmp_len);
                CNAME_mp[sub_domain].push_back(make_pair(10 + tmp_len, buf));
            }
        }
        fclose(fp2);
    }
    fclose(fp);
    puts("");
    return;
}
void show_header(header_t *header) {
    printf("ID: %02x\n", header->ID);
    printf("QR: %d\n", header->QR);
    printf("OPCODE: %d\n", header->OPCODE);
    printf("RD: %01x\n", header->RD);
    printf("RA: %01x\n", header->RA);
    printf("RCODE: %d\n", header->RCODE);
    printf("QDCOUNT(ntohs): %d\n", ntohs(header->QDCNT));
    printf("ANCOUNT(ntohs): %d\n", ntohs(header->ANCNT));
    printf("NSCOUNT(ntohs): %d\n", ntohs(header->NSCNT));
    printf("ARCOUNT(ntohs): %d\n", ntohs(header->ARCNT));
    return;
}
int main(int argc, char **argv) {
    if (argc != 3) {
        printf("./dns <port-number> <path/to/the/config/file>\n");
        exit(1);
    }
    init(argv[2]);
    int sockfd, n;
    socklen_t clilen;
    char recvline[MAXLINE], sendbuf[MAXLINE];
    char *QNAME = recvline + sizeof(header_t) + 1;
    header_t *r_header = (header_t *)recvline;
    header_t *s_header = (header_t *)sendbuf;
    struct sockaddr_in servaddr, cliaddr;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    clilen = sizeof(cliaddr);
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(atoi(argv[1]));
    bind(sockfd, (SA *)&servaddr, sizeof(servaddr));
    while ((n = recvfrom(sockfd, recvline, MAXLINE, 0, (SA *)&cliaddr, &clilen)) > 0) {
        recvline[n] = '\0';
        puts("received header info:");
        show_header(r_header);
        int len = (int)strlen(QNAME);
        int total = (int)sizeof(header_t) + len + 2 + 4;
        char *st = QNAME;
        char *answer_st = sendbuf + total;
        char *domain_name = new char[len];
        memset(domain_name, 0, len);
        memcpy(sendbuf, recvline, total);
        uint16_t QTYPE = ntohs(*(uint16_t *)(QNAME + len + 1));
        uint16_t QCLASS = ntohs(*(uint16_t *)(QNAME + len + 3));
        uint8_t *idx = (uint8_t *)(st - 1);
        while (*idx) {
            strncat(domain_name, st, *idx);
            st += (*idx + 1);
            idx = (uint8_t *)(st - 1);
            strcat(domain_name, ".");
        }
        printf("\nDomain: <%s> , %d\n", domain_name, (int)strlen(domain_name));
        printf("QTYPE: %d\n", QTYPE);
        printf("QCLASS: %d\n", QCLASS);
        printf("\nResponse:\n");
        string domain(domain_name);
        s_header->RA = 1;
        s_header->QR = 1;
        s_header->ARCNT = 0;
        int find = 0, match = 0;
        regex_t preg;
        char prefix_pattern[] = "^([0-9]{1,3}[.]){4}([0-9a-zA-Z]{1,61}[.])*";
        if (QTYPE == 1) {
            for (auto itr = domains.begin(); itr != domains.end(); itr++) {
                char pattern[100];
                sprintf(pattern, "%s%s%c", prefix_pattern, (*itr).c_str(), '\0');
                regcomp(&preg, pattern, REG_EXTENDED);
                regmatch_t matchptr[1];
                match = !regexec(&preg, domain_name, 1, matchptr, 0);
                if (match) {
                    printf("Match: %s\n", domain_name);
                    uint32_t ipv4;
                    char ip[30];
                    int cnt = 0;
                    for (int i = 0; i < (int)strlen(domain_name); i++) {
                        if (domain_name[i] == '.') {
                            cnt++;
                            if (cnt == 4) {
                                strncpy(ip, domain_name, i);
                                ip[i] = '\0';
                                break;
                            }
                        }
                    }
                    s_header->ANCNT = htons(1);
                    RR_data rr_data;
                    rr_data.type = htons(QTYPE_num["A"]);
                    rr_data.Class = htons(1);
                    rr_data.ttl = htonl(1);
                    rr_data.rd_length = htons(4);
                    inet_pton(AF_INET, ip, &ipv4);
                    char *buf = (char *)malloc(14);
                    memcpy(buf, &rr_data, sizeof(RR_data));
                    memcpy(buf + sizeof(RR_data), &ipv4, sizeof(uint32_t));
                    domain_name[(int)strlen(domain_name) - 1] = '\0';
                    int tmp_len = name_formatting(domain_name);
                    memcpy(answer_st, domain_name, tmp_len);
                    answer_st += tmp_len;
                    total += tmp_len;
                    memcpy(answer_st, buf, 14);
                    answer_st += 14;
                    total += 14;
                    break;
                }
            }
        }
        if (!match) {
            for (auto itr = domains.begin(); itr != domains.end(); itr++) {
                if (domain.find(*itr) != string::npos) {
                    find = 1;
                    string rootdomain = *itr;
                    if (QTYPE == 1) {
                        auto itr = A_mp.find(domain);
                        if (itr != A_mp.end()) {
                            s_header->ANCNT = htons(itr->second.size());
                            for (int i = 0; i < itr->second.size(); i++) {
                                memcpy(answer_st, QNAME - 1, len + 2);
                                answer_st += len + 2;
                                total += len + 2;
                                memcpy(answer_st, itr->second[i].second, itr->second[i].first);
                                answer_st += itr->second[i].first;
                                total += itr->second[i].first;
                            }
                            auto itr2 = subDOMAIN_DOMAIN.find(domain);
                            if (itr2 != subDOMAIN_DOMAIN.end() && NS_mp.find(itr2->second) != NS_mp.end()) {
                                auto itr3 = NS_mp.find(itr2->second);
                                s_header->NSCNT = htons(itr3->second.size());
                                for (int i = 0; i < itr3->second.size(); i++) {
                                    char tmp[50];
                                    strcpy(tmp, itr2->second.c_str());
                                    int tmp_len = name_formatting(tmp);
                                    memcpy(answer_st, tmp, tmp_len);
                                    answer_st += tmp_len;
                                    total += tmp_len;
                                    memcpy(answer_st, itr3->second[i].second, itr3->second[i].first);
                                    answer_st += itr3->second[i].first;
                                    total += itr3->second[i].first;
                                }
                            }
                        } else {
                            auto itr2 = SOA_mp.find(rootdomain);
                            if (itr2 != SOA_mp.end()) {
                                s_header->NSCNT = htons(1);
                                char tmp[50];
                                strcpy(tmp, rootdomain.c_str());
                                int tmp_len = name_formatting(tmp);
                                memcpy(answer_st, tmp, tmp_len);
                                answer_st += tmp_len;
                                total += tmp_len;
                                memcpy(answer_st, itr2->second.second, itr2->second.first);
                                answer_st += itr2->second.first;
                                total += itr2->second.first;
                            }
                        }
                    } else if (QTYPE == 2) {
                        auto itr = NS_mp.find(domain);
                        if (itr != NS_mp.end()) {
                            s_header->ANCNT = htons(itr->second.size());
                            for (int i = 0; i < itr->second.size(); i++) {
                                memcpy(answer_st, QNAME - 1, len + 2);
                                answer_st += len + 2;
                                total += len + 2;
                                memcpy(answer_st, itr->second[i].second, itr->second[i].first);
                                answer_st += itr->second[i].first;
                                total += itr->second[i].first;
                            }
                            int cnt = 0;
                            for (int i = 0; i < NS_names[domain].size(); i++) {
                                auto itr2 = A_mp.find(NS_names[domain][i]);
                                if (itr2 != A_mp.end()) {
                                    cnt += itr2->second.size();
                                    for (int j = 0; j < itr2->second.size(); j++) {
                                        char tmp[50];
                                        strcpy(tmp, NS_names[domain][i].c_str());
                                        int len1 = name_formatting(tmp);
                                        memcpy(answer_st, tmp, len1);
                                        answer_st += len1;
                                        total += len1;
                                        memcpy(answer_st, itr2->second[j].second, itr2->second[j].first);
                                        answer_st += itr2->second[j].first;
                                        total += itr2->second[j].first;
                                    }
                                }
                            }
                            s_header->ARCNT = htons(cnt);
                            /*string dns_domain = "dns." + domain;
                            auto itr2 = A_mp.find(dns_domain);
                            if (itr2 != A_mp.end()) {
                                s_header->ARCNT = htons(itr2->second.size());
                                for (int i = 0; i < itr2->second.size(); i++) {
                                    char tmp[50];
                                    strcpy(tmp, dns_domain.c_str());
                                    int len1 = name_formatting(tmp);
                                    memcpy(answer_st, tmp, len1);
                                    answer_st += len1;
                                    total += len1;
                                    memcpy(answer_st, itr2->second[i].second, itr2->second[i].first);
                                    answer_st += itr2->second[i].first;
                                    total += itr2->second[i].first;
                                }
                            }*/
                        } else {
                            auto itr2 = SOA_mp.find(rootdomain);
                            if (itr2 != SOA_mp.end()) {
                                s_header->NSCNT = htons(1);
                                char tmp[50];
                                strcpy(tmp, rootdomain.c_str());
                                int tmp_len = name_formatting(tmp);
                                memcpy(answer_st, tmp, tmp_len);
                                answer_st += tmp_len;
                                total += tmp_len;
                                memcpy(answer_st, itr2->second.second, itr2->second.first);
                                answer_st += itr2->second.first;
                                total += itr2->second.first;
                            }
                        }
                    } else if (QTYPE == 5) {
                        auto itr = CNAME_mp.find(domain);
                        if (itr != CNAME_mp.end()) {
                            s_header->ANCNT = htons(itr->second.size());
                            for (int i = 0; i < itr->second.size(); i++) {
                                memcpy(answer_st, QNAME - 1, len + 2);
                                answer_st += len + 2;
                                total += len + 2;
                                memcpy(answer_st, itr->second[i].second, itr->second[i].first);
                                answer_st += itr->second[i].first;
                                total += itr->second[i].first;
                            }
                            auto itr2 = NS_mp.find(rootdomain);
                            if (itr2 != NS_mp.end()) {
                                s_header->NSCNT = htons(itr2->second.size());
                                for (int i = 0; i < itr2->second.size(); i++) {
                                    char tmp[50];
                                    strcpy(tmp, rootdomain.c_str());
                                    int tmp_len = name_formatting(tmp);
                                    memcpy(answer_st, tmp, tmp_len);
                                    answer_st += tmp_len;
                                    total += tmp_len;
                                    memcpy(answer_st, itr2->second[i].second, itr2->second[i].first);
                                    answer_st += itr2->second[i].first;
                                    total += itr2->second[i].first;
                                }
                            }
                        } else {
                            auto itr2 = SOA_mp.find(rootdomain);
                            if (itr2 != SOA_mp.end()) {
                                s_header->NSCNT = htons(1);
                                char tmp[50];
                                strcpy(tmp, rootdomain.c_str());
                                int tmp_len = name_formatting(tmp);
                                memcpy(answer_st, tmp, tmp_len);
                                answer_st += tmp_len;
                                total += tmp_len;
                                memcpy(answer_st, itr2->second.second, itr2->second.first);
                                answer_st += itr2->second.first;
                                total += itr2->second.first;
                            }
                        }
                    } else if (QTYPE == 6) {
                        auto itr = SOA_mp.find(domain);
                        if (itr != SOA_mp.end()) {
                            s_header->ANCNT = htons(1);
                            memcpy(answer_st, QNAME - 1, len + 2);
                            answer_st += len + 2;
                            total += len + 2;
                            memcpy(answer_st, itr->second.second, itr->second.first);
                            answer_st += itr->second.first;
                            total += itr->second.first;
                            auto itr2 = NS_mp.find(domain);
                            if (itr2 != NS_mp.end()) {
                                s_header->NSCNT = htons(itr2->second.size());
                                for (int i = 0; i < itr2->second.size(); i++) {
                                    memcpy(answer_st, QNAME - 1, len + 2);
                                    answer_st += len + 2;
                                    total += len + 2;
                                    memcpy(answer_st, itr2->second[i].second, itr2->second[i].first);
                                    answer_st += itr2->second[i].first;
                                    total += itr2->second[i].first;
                                }
                            }
                        } else {
                            auto itr2 = SOA_mp.find(rootdomain);
                            if (itr2 != SOA_mp.end()) {
                                s_header->NSCNT = htons(1);
                                char tmp[50];
                                strcpy(tmp, rootdomain.c_str());
                                int tmp_len = name_formatting(tmp);
                                memcpy(answer_st, tmp, tmp_len);
                                answer_st += tmp_len;
                                total += tmp_len;
                                memcpy(answer_st, itr2->second.second, itr2->second.first);
                                answer_st += itr2->second.first;
                                total += itr2->second.first;
                            }
                        }
                    } else if (QTYPE == 15) {
                        auto itr = MX_mp.find(domain);
                        if (itr != MX_mp.end()) {
                            s_header->ANCNT = htons(itr->second.size());
                            for (int i = 0; i < itr->second.size(); i++) {
                                memcpy(answer_st, QNAME - 1, len + 2);
                                answer_st += len + 2;
                                total += len + 2;
                                memcpy(answer_st, itr->second[i].second, itr->second[i].first);
                                answer_st += itr->second[i].first;
                                total += itr->second[i].first;
                            }
                            auto itr2 = NS_mp.find(domain);
                            if (itr2 != NS_mp.end()) {
                                s_header->NSCNT = htons(itr2->second.size());
                                for (int i = 0; i < itr2->second.size(); i++) {
                                    memcpy(answer_st, QNAME - 1, len + 2);
                                    answer_st += len + 2;
                                    total += len + 2;
                                    memcpy(answer_st, itr2->second[i].second, itr2->second[i].first);
                                    answer_st += itr2->second[i].first;
                                    total += itr2->second[i].first;
                                }
                            }
                            int cnt = 0;
                            for (int i = 0; i < MX_names[domain].size(); i++) {
                                printf("%s\n", MX_names[domain][i].c_str());
                                auto itr2 = A_mp.find(MX_names[domain][i]);
                                if (itr2 != A_mp.end()) {
                                    cnt += itr2->second.size();
                                    for (int j = 0; j < itr2->second.size(); j++) {
                                        char tmp[50];
                                        strcpy(tmp, MX_names[domain][i].c_str());
                                        int len1 = name_formatting(tmp);
                                        memcpy(answer_st, tmp, len1);
                                        answer_st += len1;
                                        total += len1;
                                        memcpy(answer_st, itr2->second[j].second, itr2->second[j].first);
                                        answer_st += itr2->second[j].first;
                                        total += itr2->second[j].first;
                                    }
                                }
                            }
                            s_header->ARCNT = htons(cnt);
                            // string mx_domain = "mail." + domain;
                            // auto itr3 = A_mp.find(mx_domain);
                            // if (itr3 != A_mp.end()) {
                            //     s_header->ARCNT = htons(itr3->second.size());
                            //     for (int i = 0; i < itr3->second.size(); i++) {
                            //         char tmp[50];
                            //         strcpy(tmp, mx_domain.c_str());
                            //         int len1 = name_formatting(tmp);
                            //         memcpy(answer_st, tmp, len1);
                            //         answer_st += len1;
                            //         total += len1;
                            //         memcpy(answer_st, itr3->second[i].second, itr3->second[i].first);
                            //         answer_st += itr3->second[i].first;
                            //         total += itr3->second[i].first;
                            //     }
                            // }
                        } else {
                            auto itr2 = SOA_mp.find(rootdomain);
                            if (itr2 != SOA_mp.end()) {
                                s_header->NSCNT = htons(1);
                                char tmp[50];
                                strcpy(tmp, rootdomain.c_str());
                                int tmp_len = name_formatting(tmp);
                                memcpy(answer_st, tmp, tmp_len);
                                answer_st += tmp_len;
                                total += tmp_len;
                                memcpy(answer_st, itr2->second.second, itr2->second.first);
                                answer_st += itr2->second.first;
                                total += itr2->second.first;
                            }
                        }
                    } else if (QTYPE == 16) {
                        auto itr = TXT_mp.find(domain);
                        if (itr != TXT_mp.end()) {
                            s_header->ANCNT = htons(itr->second.size());
                            for (int i = 0; i < itr->second.size(); i++) {
                                memcpy(answer_st, QNAME - 1, len + 2);
                                answer_st += len + 2;
                                total += len + 2;
                                memcpy(answer_st, itr->second[i].second, itr->second[i].first);
                                answer_st += itr->second[i].first;
                                total += itr->second[i].first;
                            }
                            auto itr2 = NS_mp.find(rootdomain);
                            if (itr2 != NS_mp.end()) {
                                s_header->NSCNT = htons(itr2->second.size());
                                for (int i = 0; i < itr2->second.size(); i++) {
                                    char tmp[50];
                                    strcpy(tmp, rootdomain.c_str());
                                    int tmp_len = name_formatting(tmp);
                                    memcpy(answer_st, tmp, tmp_len);
                                    answer_st += tmp_len;
                                    total += tmp_len;
                                    memcpy(answer_st, itr2->second[i].second, itr2->second[i].first);
                                    answer_st += itr2->second[i].first;
                                    total += itr2->second[i].first;
                                }
                            }
                        } else {
                            auto itr2 = SOA_mp.find(rootdomain);
                            if (itr2 != SOA_mp.end()) {
                                s_header->NSCNT = htons(1);
                                char tmp[50];
                                strcpy(tmp, rootdomain.c_str());
                                int tmp_len = name_formatting(tmp);
                                memcpy(answer_st, tmp, tmp_len);
                                answer_st += tmp_len;
                                total += tmp_len;
                                memcpy(answer_st, itr2->second.second, itr2->second.first);
                                answer_st += itr2->second.first;
                                total += itr2->second.first;
                            }
                        }
                    } else if (QTYPE == 28) {
                        auto itr = AAAA_mp.find(domain);
                        if (itr != AAAA_mp.end()) {
                            s_header->ANCNT = htons(itr->second.size());
                            for (int i = 0; i < itr->second.size(); i++) {
                                memcpy(answer_st, QNAME - 1, len + 2);
                                answer_st += len + 2;
                                total += len + 2;
                                memcpy(answer_st, itr->second[i].second, itr->second[i].first);
                                answer_st += itr->second[i].first;
                                total += itr->second[i].first;
                            }
                            auto itr2 = NS_mp.find(rootdomain);
                            if (itr2 != NS_mp.end()) {
                                s_header->NSCNT = htons(itr2->second.size());
                                for (int i = 0; i < itr2->second.size(); i++) {
                                    char tmp[50];
                                    strcpy(tmp, rootdomain.c_str());
                                    int tmp_len = name_formatting(tmp);
                                    memcpy(answer_st, tmp, tmp_len);
                                    answer_st += tmp_len;
                                    total += tmp_len;
                                    memcpy(answer_st, itr2->second[i].second, itr2->second[i].first);
                                    answer_st += itr2->second[i].first;
                                    total += itr2->second[i].first;
                                }
                            }
                        } else {
                            auto itr2 = SOA_mp.find(rootdomain);
                            if (itr2 != SOA_mp.end()) {
                                s_header->NSCNT = htons(1);
                                char tmp[50];
                                strcpy(tmp, rootdomain.c_str());
                                int tmp_len = name_formatting(tmp);
                                memcpy(answer_st, tmp, tmp_len);
                                answer_st += tmp_len;
                                total += tmp_len;
                                memcpy(answer_st, itr2->second.second, itr2->second.first);
                                answer_st += itr2->second.first;
                                total += itr2->second.first;
                            }
                        }
                    }
                    break;
                }
            }
        }
        if (!find && !match) {
            domain_name[(int)strlen(domain_name) - 1] = '\0';
            printf("%s\n", domain_name);
            if (QTYPE == 1) {
                total = res_search(domain_name, C_IN, T_A, (u_char *)sendbuf, MAXLINE);
            } else if (QTYPE == 2) {
                total = res_search(domain_name, C_IN, T_NS, (u_char *)sendbuf, MAXLINE);
            } else if (QTYPE == 5) {
                total = res_search(domain_name, C_IN, T_CNAME, (u_char *)sendbuf, MAXLINE);
            } else if (QTYPE == 6) {
                total = res_search(domain_name, C_IN, T_SOA, (u_char *)sendbuf, MAXLINE);
            } else if (QTYPE == 15) {
                total = res_search(domain_name, C_IN, T_MX, (u_char *)sendbuf, MAXLINE);
            } else if (QTYPE == 16) {
                total = res_search(domain_name, C_IN, T_TXT, (u_char *)sendbuf, MAXLINE);
            } else if (QTYPE == 28) {
                total = res_search(domain_name, C_IN, T_AAAA, (u_char *)sendbuf, MAXLINE);
            }
            printf("total: %d\n", total);
            if (total == -1) {
                total = (int)sizeof(header_t) + len + 2 + 4;
                memcpy(sendbuf, recvline, total);
                s_header->RA = 1;
                s_header->ARCNT = 0;
            } else {
                memcpy(&s_header->ID, &r_header->ID, sizeof(r_header->ID));
                answer_st = sendbuf + total;
            }
        }
        if (r_header->ARCNT) {
            s_header->ARCNT = htons(ntohs(s_header->ARCNT) + 1);
            int add_rr_idx = (int)sizeof(header_t) + len + 2 + 4;
            char *add_RR_st = recvline + add_rr_idx;
            memcpy(answer_st, add_RR_st, n - add_rr_idx);
            answer_st += n - add_rr_idx;
            total += n - add_rr_idx;
        }
        puts("sended header info:");
        show_header(s_header);
        n = sendto(sockfd, sendbuf, total, 0, (SA *)&cliaddr, clilen);
    }
    return 0;
}