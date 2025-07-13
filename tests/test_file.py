#!/usr/bin/env python3
"""
CyberSecAudit Test Suite
Unit testler ve fonksiyonel testler
"""

import unittest
import sys
import os
import json
from unittest.mock import patch, MagicMock, mock_open
import socket

# Ana modülü import et
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from cybersec_audit import SecurityAuditor, Colors

class TestSecurityAuditor(unittest.TestCase):
    """SecurityAuditor sınıfı için unit testler"""
    
    def setUp(self):
        """Her test öncesi çalışır"""
        self.auditor = SecurityAuditor()
        self.test_host = "127.0.0.1"
        self.test_ports = [80, 443, 22]
    
    def test_init(self):
        """SecurityAuditor başlatma testi"""
        self.assertIsInstance(self.auditor.results, dict)
        self.assertIn('scan_time', self.auditor.results)
        self.assertIn('port_scan', self.auditor.results)
        self.assertIn('vulnerability_scan', self.auditor.results)
        self.assertIsInstance(self.auditor.common_ports, list)
        self.assertGreater(len(self.auditor.common_ports), 0)
    
    def test_get_service_name(self):
        """Servis adı alma testi"""
        self.assertEqual(self.auditor.get_service_name(80), 'HTTP')
        self.assertEqual(self.auditor.get_service_name(443), 'HTTPS')
        self.assertEqual(self.auditor.get_service_name(22), 'SSH')
        self.assertEqual(self.auditor.get_service_name(9999), 'Unknown')
    
    @patch('socket.socket')
    def test_scan_port_open(self, mock_socket):
        """Açık port tarama testi"""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket.return_value = mock_sock
        
        result = self.auditor.scan_port(self.test_host, 80)
        self.assertEqual(result, 80)
        mock_sock.connect_ex.assert_called_once_with((self.test_host, 80))
        mock_sock.close.assert_called_once()
    
    @patch('socket.socket')
    def test_scan_port_closed(self, mock_socket):
        """Kapalı port tarama testi"""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1
        mock_socket.return_value = mock_sock
        
        result = self.auditor.scan_port(self.test_host, 80)
        self.assertIsNone(result)
    
    @patch('socket.socket')
    def test_scan_port_timeout(self, mock_socket):
        """Port tarama timeout testi"""
        mock_socket.side_effect = socket.timeout()
        
        result = self.auditor.scan_port(self.test_host, 80)
        self.assertIsNone(result)
    
    def test_password_strength_weak(self):
        """Zayıf şifre analizi testi"""
        result = self.auditor.password_strength_analyzer("123")
        self.assertEqual(result['strength'], 'WEAK')
        self.assertLess(result['score'], 4)
        self.assertFalse(result['has_upper'])
        self.assertFalse(result['has_lower'])
        self.assertTrue(result['has_digit'])
    
    def test_password_strength_medium(self):
        """Orta şifre analizi testi"""
        result = self.auditor.password_strength_analyzer("Password123")
        self.assertEqual(result['strength'], 'MEDIUM')
        self.assertGreaterEqual(result['score'], 4)
        self.assertLess(result['score'], 7)
        self.assertTrue(result['has_upper'])
        self.assertTrue(result['has_lower'])
        self.assertTrue(result['has_digit'])
    
    def test_password_strength_strong(self):
        """Güçlü şifre analizi testi"""
        result = self.auditor.password_strength_analyzer("MyStr0ng!P@ssw0rd")
        self.assertEqual(result['strength'], 'STRONG')
        self.assertGreaterEqual(result['score'], 7)
        self.assertTrue(result['has_upper'])
        self.assertTrue(result['has_lower'])
        self.assertTrue(result['has_digit'])
        self.assertTrue(result['has_special'])
    
    def test_vulnerability_check_risky_ports(self):
        """Riskli port güvenlik açığı testi"""
        risky_ports = [21, 23, 25]
        vulnerabilities = self.auditor.vulnerability_check(self.test_host, risky_ports)
        
        self.assertGreater(len(vulnerabilities), 0)
        self.assertTrue(any(vuln['port'] in risky_ports for vuln in vulnerabilities))
        self.assertTrue(any(vuln['severity'] in ['HIGH', 'MEDIUM'] for vuln in vulnerabilities))
    
    def test_vulnerability_check_safe_ports(self):
        """Güvenli port güvenlik açığı testi"""
        safe_ports = [443, 993, 995]
        vulnerabilities = self.auditor.vulnerability_check(self.test_host, safe_ports)
        
        # SSH port kontrolü hariç vulnerability olmamalı
        non_ssh_vulnerabilities = [v for v in vulnerabilities if v['port'] != 22]
        self.assertEqual(len(non_ssh_vulnerabilities), 0)
    
    @patch('socket.gethostbyname')
    @patch('socket.gethostbyaddr')
    @patch('subprocess.run')
    def test_network_info_gather(self, mock_subprocess, mock_gethostbyaddr, mock_gethostbyname):
        """Network bilgi toplama testi"""
        mock_gethostbyname.return_value = "192.168.1.1"
        mock_gethostbyaddr.return_value = ("test.local", [], ["192.168.1.1"])
        
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = "time=10.5 ms\ntime=12.3 ms\n"
        mock_subprocess.return_value = mock_process
        
        result = self.auditor.network_info_gather("test.local")
        
        self.assertTrue(result['ping_success'])
        self.assertEqual(result['ip_address'], "192.168.1.1")
        self.assertEqual(result['hostname'], "test.local")
        self.assertIn('avg_ping', result)
    
    def test_generate_recommendations(self):
        """Güvenlik önerileri oluşturma testi"""
        # Test verileri hazırla
        self.auditor.results['port_scan'] = {self.test_host: [21, 23, 80]}
        self.auditor.results['vulnerability_scan'] = [
            {'severity': 'HIGH', 'port': 21, 'description': 'FTP Risk', 'recommendation': 'Use SFTP'}
        ]
        
        recommendations = self.auditor.generate_recommendations()
        
        self.assertIsInstance(recommendations, list)
        self.assertGreater(len(recommendations), 0)
        self.assertTrue(any('FTP' in rec or 'SFTP' in rec for rec in recommendations))
        self.assertTrue(any('Telnet' in rec or 'SSH' in rec for rec in recommendations))
    
    @patch('builtins.open', new_callable=mock_open)
    @patch('json.dump')
    def test_generate_report(self, mock_json_dump, mock_file):
        """Rapor oluşturma testi"""
        test_filename = "test_report.json"
        
        with patch.object(self.auditor, 'generate_recommendations') as mock_recommendations:
            mock_recommendations.return_value = ["Test recommendation"]
            
            with patch.object(self.auditor, 'print_console_report') as mock_print:
                self.auditor.generate_report(test_filename)
                
                mock_file.assert_called_once_with(test_filename, 'w', encoding='utf-8')
                mock_json_dump.assert_called_once()
                mock_recommendations.assert_called_once()
                mock_print.assert_called_once()

class TestColors(unittest.TestCase):
    """Colors sınıfı için testler"""
    
    def test_color_codes(self):
        """Renk kodlarının varlığı testi"""
        self.assertTrue(hasattr(Colors, 'RED'))
        self.assertTrue(hasattr(Colors, 'GREEN'))
        self.assertTrue(hasattr(Colors, 'YELLOW'))
        self.assertTrue(hasattr(Colors, 'BLUE'))
        self.assertTrue(hasattr(Colors, 'ENDC'))
        self.assertTrue(hasattr(Colors, 'BOLD'))
    
    def test_color_values(self):
        """Renk kodlarının değerleri testi"""
        self.assertIsInstance(Colors.RED, str)
        self.assertIsInstance(Colors.GREEN, str)
        self.assertIsInstance(Colors.ENDC, str)
        self.assertTrue(Colors.RED.startswith('\033['))
        self.assertTrue(Colors.ENDC.startswith('\033['))

class TestIntegration(unittest.TestCase):
    """Entegrasyon testleri"""
    
    def setUp(self):
        """Test ortamı hazırlama"""
        self.auditor = SecurityAuditor()
    
    @patch('socket.gethostbyname')
    def test_full_scan_workflow(self, mock_gethostbyname):
        """Tam tarama iş akışı testi"""
        mock_gethostbyname.return_value = "127.0.0.1"
        
        # Mock port scanner
        with patch.object(self.auditor, 'scan_port') as mock_scan_port:
            mock_scan_port.side_effect = lambda host, port: port if port in [80, 443] else None
            
            # Port taraması
            open_ports = self.auditor.port_scanner("127.0.0.1", [80, 443, 22])
            
            # Güvenlik açığı taraması
            vulnerabilities = self.auditor.vulnerability_check("127.0.0.1", open_ports)
            
            # Sonuçları kontrol et
            self.assertEqual(set(open_ports), {80, 443})
            self.assertIsInstance(vulnerabilities, list)
            self.assertIn("127.0.0.1", self.auditor.results['port_scan'])

if __name__ == '__main__':
    # Test paketlerini çalıştır
    unittest.main(verbosity=2)
