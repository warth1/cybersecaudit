#!/usr/bin/env python3
"""
CyberSecAudit - Comprehensive Cybersecurity Audit Tool
Kapsamlı Siber Güvenlik Denetim Aracı

Bu araç network güvenliği, port tarama, güvenlik açığı tespiti ve 
güvenlik raporlama işlevlerini bir arada sunar.

Author: Warth
License: MIT
"""

import socket
import subprocess
import sys
import threading
import time
import json
import hashlib
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import argparse

class Colors:
    """Terminal renk kodları"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class SecurityAuditor:
    def __init__(self):
        self.results = {
            'scan_time': datetime.now().isoformat(),
            'port_scan': {},
            'vulnerability_scan': [],
            'password_analysis': {},
            'network_info': {},
            'recommendations': []
        }
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3389, 5432, 5900]
        
    def print_banner(self):
        """Araç başlığını yazdır"""
        banner = f"""
{Colors.CYAN}
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗ 
██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝ 
██║     ██║   ██║██████╔╝█████╗  ██████╔╝███████╗█████╗  ██║      
██║     ██║   ██║██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║      
╚██████╗╚██████╔╝██████╔╝███████╗██║  ██║███████║███████╗╚██████╗ 
 ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ 
                                                                   
    ██╗   ██╗██████╗ ██╗████████╗                                  
    ██║   ██║██╔══██╗██║╚══██╔══╝                                  
    ███████║██████╔╝██║   ██║                                     
    ██╔══██║██╔══██╗██║   ██║                                     
    ██║  ██║██║  ██║██║   ██║                                     
    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝                                     
{Colors.ENDC}
{Colors.YELLOW}    Kapsamlı Siber Güvenlik Denetim Aracı v1.0{Colors.ENDC}
{Colors.GREEN}    GitHub: github.com/warth1/cybersecaudit{Colors.ENDC}
        """
        print(banner)

    def scan_port(self, host, port, timeout=3):
        """Tek bir portu tara"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return port if result == 0 else None
        except:
            return None

    def port_scanner(self, host, ports=None, threads=100):
        """Çoklu thread ile port taraması"""
        if ports is None:
            ports = self.common_ports
            
        print(f"{Colors.BLUE}[INFO]{Colors.ENDC} Port taraması başlatılıyor: {host}")
        print(f"{Colors.BLUE}[INFO]{Colors.ENDC} Taranan portlar: {len(ports)}")
        
        open_ports = []
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(self.scan_port, host, port) for port in ports]
            
            for future in futures:
                result = future.result()
                if result:
                    open_ports.append(result)
                    service = self.get_service_name(result)
                    print(f"{Colors.GREEN}[AÇIK]{Colors.ENDC} Port {result}/tcp - {service}")
        
        self.results['port_scan'][host] = open_ports
        return open_ports

    def get_service_name(self, port):
        """Port numarasından servis adını al"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5900: 'VNC'
        }
        return services.get(port, 'Unknown')

    def vulnerability_check(self, host, open_ports):
        """Temel güvenlik açığı kontrolü"""
        print(f"{Colors.YELLOW}[SCAN]{Colors.ENDC} Güvenlik açığı taraması başlatılıyor...")
        
        vulnerabilities = []
        
        # Güvensiz servisler kontrolü
        risky_ports = {21: 'FTP - Şifrelenmemiş veri transferi',
                      23: 'Telnet - Şifrelenmemiş bağlantı',
                      25: 'SMTP - Potansiyel spam relay',
                      53: 'DNS - DNS amplification saldırı riski'}
        
        for port in open_ports:
            if port in risky_ports:
                vuln = {
                    'severity': 'HIGH' if port in [21, 23] else 'MEDIUM',
                    'port': port,
                    'description': risky_ports[port],
                    'recommendation': f'Port {port} güvenli alternatifi ile değiştirilmeli'
                }
                vulnerabilities.append(vuln)
                print(f"{Colors.RED}[RISK]{Colors.ENDC} {vuln['severity']} - Port {port}: {vuln['description']}")

        # SSH brute force koruması kontrolü
        if 22 in open_ports:
            ssh_check = self.check_ssh_security(host)
            if ssh_check:
                vulnerabilities.append(ssh_check)

        self.results['vulnerability_scan'] = vulnerabilities
        return vulnerabilities

    def check_ssh_security(self, host):
        """SSH güvenlik kontrolü"""
        try:
            # SSH banner bilgisi al
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, 22))
            banner = sock.recv(1024).decode().strip()
            sock.close()
            
            # Eski SSH versiyonu kontrolü
            if 'SSH-1' in banner:
                return {
                    'severity': 'HIGH',
                    'port': 22,
                    'description': 'Eski SSH protokol versiyonu tespit edildi',
                    'recommendation': 'SSH versiyonunu güncelleyin'
                }
        except:
            pass
        return None

    def password_strength_analyzer(self, password):
        """Şifre güvenlik analizi"""
        analysis = {
            'length': len(password),
            'has_upper': bool(re.search(r'[A-Z]', password)),
            'has_lower': bool(re.search(r'[a-z]', password)),
            'has_digit': bool(re.search(r'\d', password)),
            'has_special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
            'score': 0,
            'strength': 'WEAK'
        }
        
        # Puanlama sistemi
        if analysis['length'] >= 8:
            analysis['score'] += 2
        if analysis['length'] >= 12:
            analysis['score'] += 1
        if analysis['has_upper']:
            analysis['score'] += 1
        if analysis['has_lower']:
            analysis['score'] += 1
        if analysis['has_digit']:
            analysis['score'] += 1
        if analysis['has_special']:
            analysis['score'] += 2
        
        # Güç seviyesi belirleme
        if analysis['score'] >= 7:
            analysis['strength'] = 'STRONG'
        elif analysis['score'] >= 4:
            analysis['strength'] = 'MEDIUM'
        
        return analysis

    def network_info_gather(self, host):
        """Network bilgi toplama"""
        print(f"{Colors.BLUE}[INFO]{Colors.ENDC} Network bilgileri toplanıyor...")
        
        info = {}
        
        # Ping testi
        try:
            ping_result = subprocess.run(['ping', '-c', '4', host], 
                                       capture_output=True, text=True, timeout=10)
            info['ping_success'] = ping_result.returncode == 0
            if info['ping_success']:
                # Ping süresini çıkar
                ping_times = re.findall(r'time=(\d+\.?\d*)', ping_result.stdout)
                if ping_times:
                    info['avg_ping'] = sum(float(t) for t in ping_times) / len(ping_times)
        except:
            info['ping_success'] = False

        # DNS çözümleme
        try:
            info['ip_address'] = socket.gethostbyname(host)
            info['hostname'] = socket.gethostbyaddr(info['ip_address'])[0]
        except:
            info['ip_address'] = host
            info['hostname'] = 'Unknown'

        self.results['network_info'] = info
        return info

    def generate_recommendations(self):
        """Güvenlik önerileri oluştur"""
        recommendations = []
        
        # Port tabanlı öneriler
        for host, ports in self.results['port_scan'].items():
            if 21 in ports:
                recommendations.append("FTP yerine SFTP kullanın")
            if 23 in ports:
                recommendations.append("Telnet yerine SSH kullanın")
            if 80 in ports and 443 not in ports:
                recommendations.append("HTTP trafiğini HTTPS'e yönlendirin")
        
        # Güvenlik açığı tabanlı öneriler
        high_risk_count = sum(1 for vuln in self.results['vulnerability_scan'] 
                             if vuln['severity'] == 'HIGH')
        if high_risk_count > 0:
            recommendations.append(f"{high_risk_count} yüksek risk güvenlik açığı tespit edildi - derhal müdahale edin")
        
        # Genel güvenlik önerileri
        recommendations.extend([
            "Düzenli güvenlik taraması yapın",
            "Güvenlik yamalarını güncel tutun",
            "Güçlü şifre politikası uygulayın",
            "İki faktörlü kimlik doğrulama kullanın",
            "Firewall kurallarını gözden geçirin"
        ])
        
        self.results['recommendations'] = recommendations
        return recommendations

    def generate_report(self, output_file='security_report.json'):
        """Detaylı rapor oluştur"""
        print(f"{Colors.BLUE}[INFO]{Colors.ENDC} Rapor oluşturuluyor...")
        
        # Önerileri oluştur
        self.generate_recommendations()
        
        # JSON raporu kaydet
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        # Konsol raporu yazdır
        self.print_console_report()
        
        print(f"{Colors.GREEN}[SUCCESS]{Colors.ENDC} Detaylı rapor kaydedildi: {output_file}")

    def print_console_report(self):
        """Konsol raporu yazdır"""
        print(f"\n{Colors.BOLD}=== GÜVENLİK DEĞERLENDİRME RAPORU ==={Colors.ENDC}")
        print(f"{Colors.CYAN}Tarama Zamanı:{Colors.ENDC} {self.results['scan_time']}")
        
        print(f"\n{Colors.BOLD}AÇIK PORTLAR:{Colors.ENDC}")
        for host, ports in self.results['port_scan'].items():
            print(f"Host: {host}")
            for port in ports:
                service = self.get_service_name(port)
                print(f"  - {port}/tcp ({service})")
        
        print(f"\n{Colors.BOLD}GÜVENLİK AÇIKLARI:{Colors.ENDC}")
        for vuln in self.results['vulnerability_scan']:
            color = Colors.RED if vuln['severity'] == 'HIGH' else Colors.YELLOW
            print(f"{color}[{vuln['severity']}]{Colors.ENDC} Port {vuln['port']}: {vuln['description']}")
            print(f"  Öneri: {vuln['recommendation']}")
        
        print(f"\n{Colors.BOLD}ÖNERİLER:{Colors.ENDC}")
        for i, rec in enumerate(self.results['recommendations'], 1):
            print(f"{i}. {rec}")

def main():
    parser = argparse.ArgumentParser(description='CyberSecAudit - Siber Güvenlik Denetim Aracı')
    parser.add_argument('target', help='Hedef IP adresi veya hostname')
    parser.add_argument('-p', '--ports', help='Taranacak portlar (virgülle ayrılmış)')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Thread sayısı')
    parser.add_argument('-o', '--output', default='security_report.json', help='Çıktı dosyası')
    parser.add_argument('--password-check', help='Şifre güvenlik analizi')
    
    args = parser.parse_args()
    
    # Güvenlik denetçisi oluştur
    auditor = SecurityAuditor()
    auditor.print_banner()
    
    # Hedef doğrulama
    try:
        target_ip = socket.gethostbyname(args.target)
        print(f"{Colors.GREEN}[SUCCESS]{Colors.ENDC} Hedef çözümlendi: {args.target} -> {target_ip}")
    except:
        print(f"{Colors.RED}[ERROR]{Colors.ENDC} Hedef çözümlenemedi: {args.target}")
        return
    
    # Port listesi hazırla
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(',')]
    else:
        ports = auditor.common_ports
    
    try:
        # Network bilgi toplama
        auditor.network_info_gather(args.target)
        
        # Port taraması
        open_ports = auditor.port_scanner(args.target, ports, args.threads)
        
        # Güvenlik açığı taraması
        if open_ports:
            auditor.vulnerability_check(args.target, open_ports)
        
        # Şifre analizi (eğer belirtilmişse)
        if args.password_check:
            analysis = auditor.password_strength_analyzer(args.password_check)
            auditor.results['password_analysis'] = analysis
            color = Colors.GREEN if analysis['strength'] == 'STRONG' else Colors.YELLOW if analysis['strength'] == 'MEDIUM' else Colors.RED
            print(f"{Colors.BLUE}[PASSWORD]{Colors.ENDC} Şifre gücü: {color}{analysis['strength']}{Colors.ENDC} (Skor: {analysis['score']}/8)")
        
        # Rapor oluştur
        auditor.generate_report(args.output)
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[WARNING]{Colors.ENDC} Tarama kullanıcı tarafından durduruldu")
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.ENDC} Hata oluştu: {e}")

if __name__ == "__main__":
    main()
