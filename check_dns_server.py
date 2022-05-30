import dns.resolver, dns.reversename
import socket

#send query type PTR to dns server with server ip itself (reverse lookup)
#just as nmap does --script=dns-service-discovery  https://github.com/nmap/nmap/blob/master/nselib/dnssd.lua
def check_dns_available(ip: str, port: int = 53, timeout: float = 3.0) -> bool:
    result = False
    try:
        reversed_ip = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [ip]
        resolver.timeout = resolver.lifetime = timeout
        resolver.port=port
        
        resp = resolver.resolve(reversed_ip, 'PTR')
        
        if resp:
            result = True
    except (dns.resolver.NXDOMAIN):
        #skip DNS response error: DNS server is running, but the response is incorrect
        result = True
    except (dns.resolver.NoAnswer, dns.exception.Timeout) as e:
        pass
    return result
#send query with flags: 0x1000 Server status request
#it's more faster method to check dns server available on udp port 
'''
https://nmap.org/book/man-port-scanning-techniques.html 
"For some common ports such as 53 and 161, a protocol-specific payload is sent to increase response rate"
'''
def check_dns_available_fast(ip: str, port: int = 53, timeout: int = 3) -> bool:
    result = False
    
    #TODO: random Transaction ID
    dns_query = b'\x77\x77\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x76\x65\x72\x73\x69\x6f\x6e\x04\x62\x69\x6e\x64\x00\x00\x10\x00\x03'
    #Transaction ID [00 00] Flags [10 00] (Server status request) Questions [00 01] AnswerRRs [00 00] Authority RRs [00 00] Additional RRs [00 00]
    #Queries: version.bind: type TXT, class CH
    server_address = (ip, port)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(dns_query, server_address)
        data = sock.recv(512) #512b not for EDNS
        if (len(data)>=12): #20b - (8b udp header) = 12b minimal dns packet
            if (data[0:2]==b'\x77\x77'): #check Transaction ID
                result=True
            #data[2:4] = \x90\x04 Reply code: Not implemented, it's normally
    except socket.timeout:    
        pass
    finally:
        sock.close()
    return result

#Checking the availability of A record for a certain hostname on dns server
def resolve_dns_available(hostname: str, ip: str, port: int = 53, timeout: float = 3.0) -> bool:
    result = False
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [ip]
        resolver.timeout = resolver.lifetime = timeout
        resolver.port=port
        
        resp = resolver.resolve(hostname, 'A')
        #TODO: parse answer
        if len(resp):
            result = True
    except (dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NXDOMAIN) as e:
        pass
    return result

if __name__ == "__main__":
    #TODO: check IPv6 2001:4860:4860::8888

    response2 = check_dns_available('8.8.8.8')
    print(response2) 
    
    response = check_dns_available_fast("8.8.8.8")
    print(response) 
    
    response3 = resolve_dns_available("ya.ru", "8.8.8.8")
    print(response3) 