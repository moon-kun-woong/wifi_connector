import json
import logging
import os
import sqlite3
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

class NetworkController:
    """네트워크 접근 제어를 위한 기본 클래스"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.controller_type = config.get('type', 'iptables')
        
    def allow_device(self, ip_address: str, mac_address: str) -> bool:
        """디바이스의 인터넷 접근을 허용합니다."""
        raise NotImplementedError
        
    def block_device(self, ip_address: str, mac_address: str) -> bool:
        """디바이스의 인터넷 접근을 차단합니다."""
        raise NotImplementedError
        
    def is_device_allowed(self, ip_address: str, mac_address: str) -> bool:
        """디바이스의 접근 허용 상태를 확인합니다."""
        raise NotImplementedError


class IptablesController(NetworkController):
    """iptables 기반 네트워크 제어"""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.chain_name = config.get('chain_name', 'WIFI_CAPTIVE')
        self.interface = config.get('interface', 'wlan0')
        self.captive_portal_ip = config.get('captive_portal_ip', '192.168.1.1')
        self.captive_portal_port = config.get('captive_portal_port', '8000')
        
        # 초기 설정
        self._setup_iptables_rules()
    
    def _setup_iptables_rules(self):
        """초기 iptables 규칙을 설정합니다."""
        try:
            # 캡티브 포털용 체인 생성
            subprocess.run(['iptables', '-t', 'nat', '-N', self.chain_name], 
                         capture_output=True, check=False)
            subprocess.run(['iptables', '-t', 'filter', '-N', self.chain_name], 
                         capture_output=True, check=False)
            
            # 기본 규칙 추가
            # 1. 캡티브 포털 서버로의 접근 허용
            subprocess.run([
                'iptables', '-t', 'nat', '-A', self.chain_name,
                '-d', self.captive_portal_ip, '-j', 'ACCEPT'
            ], capture_output=True, check=True)
            
            # 2. DNS 쿼리를 캡티브 포털로 리다이렉트
            subprocess.run([
                'iptables', '-t', 'nat', '-A', self.chain_name,
                '-p', 'udp', '--dport', '53',
                '-j', 'DNAT', '--to-destination', f'{self.captive_portal_ip}:53'
            ], capture_output=True, check=True)
            
            # 3. HTTP 트래픽을 캡티브 포털로 리다이렉트
            subprocess.run([
                'iptables', '-t', 'nat', '-A', self.chain_name,
                '-p', 'tcp', '--dport', '80',
                '-j', 'DNAT', '--to-destination', f'{self.captive_portal_ip}:{self.captive_portal_port}'
            ], capture_output=True, check=True)
            
            # 4. HTTPS 트래픽 차단 (인증 후 허용)
            subprocess.run([
                'iptables', '-t', 'filter', '-A', self.chain_name,
                '-p', 'tcp', '--dport', '443', '-j', 'DROP'
            ], capture_output=True, check=True)
            
            # 메인 체인에 연결
            subprocess.run([
                'iptables', '-t', 'nat', '-I', 'PREROUTING',
                '-i', self.interface, '-j', self.chain_name
            ], capture_output=True, check=True)
            
            subprocess.run([
                'iptables', '-t', 'filter', '-I', 'FORWARD',
                '-i', self.interface, '-j', self.chain_name
            ], capture_output=True, check=True)
            
            logger.info("iptables 초기 규칙 설정 완료")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"iptables 설정 실패: {e}")
            raise
    
    def allow_device(self, ip_address: str, mac_address: str) -> bool:
        """디바이스의 인터넷 접근을 허용합니다."""
        try:
            # MAC 주소 기반 허용 규칙 추가
            subprocess.run([
                'iptables', '-t', 'nat', '-I', self.chain_name, '1',
                '-m', 'mac', '--mac-source', mac_address,
                '-j', 'ACCEPT'
            ], capture_output=True, check=True)
            
            subprocess.run([
                'iptables', '-t', 'filter', '-I', self.chain_name, '1',
                '-m', 'mac', '--mac-source', mac_address,
                '-j', 'ACCEPT'
            ], capture_output=True, check=True)
            
            logger.info(f"디바이스 접근 허용: IP={ip_address}, MAC={mac_address}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"디바이스 허용 실패: {e}")
            return False
    
    def block_device(self, ip_address: str, mac_address: str) -> bool:
        """디바이스의 인터넷 접근을 차단합니다."""
        try:
            # 기존 허용 규칙 제거
            subprocess.run([
                'iptables', '-t', 'nat', '-D', self.chain_name,
                '-m', 'mac', '--mac-source', mac_address,
                '-j', 'ACCEPT'
            ], capture_output=True, check=False)
            
            subprocess.run([
                'iptables', '-t', 'filter', '-D', self.chain_name,
                '-m', 'mac', '--mac-source', mac_address,
                '-j', 'ACCEPT'
            ], capture_output=True, check=False)
            
            logger.info(f"디바이스 접근 차단: IP={ip_address}, MAC={mac_address}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"디바이스 차단 실패: {e}")
            return False
    
    def is_device_allowed(self, ip_address: str, mac_address: str) -> bool:
        """디바이스의 접근 허용 상태를 확인합니다."""
        try:
            result = subprocess.run([
                'iptables', '-t', 'nat', '-L', self.chain_name, '-n'
            ], capture_output=True, text=True, check=True)
            
            return mac_address.lower() in result.stdout.lower()
            
        except subprocess.CalledProcessError as e:
            logger.error(f"디바이스 상태 확인 실패: {e}")
            return False


class PfSenseController(NetworkController):
    """pfSense API 기반 네트워크 제어"""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.api_url = config.get('api_url', 'https://192.168.1.1')
        self.api_key = config.get('api_key')
        self.api_secret = config.get('api_secret')
        self.interface_name = config.get('interface', 'LAN')
        
        if not self.api_key or not self.api_secret:
            raise ValueError("pfSense API 키와 시크릿이 필요합니다")
    
    def _make_api_request(self, method: str, endpoint: str, data: Dict = None) -> Dict:
        """pfSense API 요청을 수행합니다."""
        url = f"{self.api_url}/api/v1/{endpoint}"
        headers = {
            'Authorization': f'Bearer {self.api_key}:{self.api_secret}',
            'Content-Type': 'application/json'
        }
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, verify=False, timeout=10)
            elif method == 'POST':
                response = requests.post(url, headers=headers, json=data, verify=False, timeout=10)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, verify=False, timeout=10)
            
            response.raise_for_status()
            return response.json()
            
        except requests.RequestException as e:
            logger.error(f"pfSense API 요청 실패: {e}")
            raise
    
    def allow_device(self, ip_address: str, mac_address: str) -> bool:
        """디바이스의 인터넷 접근을 허용합니다."""
        try:
            # 방화벽 규칙 추가
            rule_data = {
                'type': 'pass',
                'interface': self.interface_name,
                'source': {'address': ip_address},
                'destination': {'address': 'any'},
                'description': f'WiFi Auth Allow - {mac_address}'
            }
            
            self._make_api_request('POST', 'firewall/rule', rule_data)
            logger.info(f"pfSense에서 디바이스 허용: IP={ip_address}, MAC={mac_address}")
            return True
            
        except Exception as e:
            logger.error(f"pfSense 디바이스 허용 실패: {e}")
            return False
    
    def block_device(self, ip_address: str, mac_address: str) -> bool:
        """디바이스의 인터넷 접근을 차단합니다."""
        try:
            # 기존 허용 규칙 찾기 및 제거
            rules = self._make_api_request('GET', 'firewall/rule')
            
            for rule in rules.get('data', []):
                if (rule.get('description', '').startswith('WiFi Auth Allow') and 
                    mac_address in rule.get('description', '')):
                    rule_id = rule.get('id')
                    self._make_api_request('DELETE', f'firewall/rule/{rule_id}')
            
            logger.info(f"pfSense에서 디바이스 차단: IP={ip_address}, MAC={mac_address}")
            return True
            
        except Exception as e:
            logger.error(f"pfSense 디바이스 차단 실패: {e}")
            return False
    
    def is_device_allowed(self, ip_address: str, mac_address: str) -> bool:
        """디바이스의 접근 허용 상태를 확인합니다."""
        try:
            rules = self._make_api_request('GET', 'firewall/rule')
            
            for rule in rules.get('data', []):
                if (rule.get('description', '').startswith('WiFi Auth Allow') and 
                    mac_address in rule.get('description', '') and
                    rule.get('source', {}).get('address') == ip_address):
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"pfSense 디바이스 상태 확인 실패: {e}")
            return False


class RadiusController(NetworkController):
    """RADIUS 서버 기반 네트워크 제어"""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.radius_server = config.get('radius_server', 'localhost')
        self.radius_port = config.get('radius_port', 1812)
        self.radius_secret = config.get('radius_secret', 'testing123')
        self.nas_identifier = config.get('nas_identifier', 'wifi-captive-portal')
    
    def allow_device(self, ip_address: str, mac_address: str) -> bool:
        """RADIUS를 통해 디바이스 접근을 허용합니다."""
        # RADIUS 구현은 pyrad 라이브러리 필요
        # 여기서는 기본 구조만 제공
        logger.info(f"RADIUS 디바이스 허용: IP={ip_address}, MAC={mac_address}")
        return True
    
    def block_device(self, ip_address: str, mac_address: str) -> bool:
        """RADIUS를 통해 디바이스 접근을 차단합니다."""
        logger.info(f"RADIUS 디바이스 차단: IP={ip_address}, MAC={mac_address}")
        return True
    
    def is_device_allowed(self, ip_address: str, mac_address: str) -> bool:
        """RADIUS를 통해 디바이스 상태를 확인합니다."""
        return False


# ===== 네트워크 제어 팩토리 =====

def create_network_controller(config: Dict) -> NetworkController:
    """설정에 따라 적절한 네트워크 컨트롤러를 생성합니다."""
    controller_type = config.get('type', 'iptables')
    
    if controller_type == 'iptables':
        return IptablesController(config)
    elif controller_type == 'pfsense':
        return PfSenseController(config)
    elif controller_type == 'radius':
        return RadiusController(config)
    else:
        raise ValueError(f"지원하지 않는 네트워크 컨트롤러 타입: {controller_type}")


# ===== 통합 네트워크 제어 서비스 =====

class NetworkControlService:
    """네트워크 제어 서비스 통합 관리"""
    
    def __init__(self, db: sqlite3.Connection, config: Dict):
        self.db = db
        self.controller = create_network_controller(config)
        self.config = config
    
    def authenticate_and_allow_device(self, wifi_auth_id: int, ip_address: str, mac_address: str) -> bool:
        """디바이스 인증 후 네트워크 접근을 허용합니다."""
        try:
            # 1. 네트워크 제어기를 통해 접근 허용
            if not self.controller.allow_device(ip_address, mac_address):
                return False
            
            # 2. 데이터베이스에 네트워크 세션 기록
            from .network_service import create_network_session
            session_token = create_network_session(self.db, wifi_auth_id, ip_address, mac_address)
            
            # 3. 시스템 로그 기록
            from .network_service import log_system_event
            log_system_event(
                self.db, 'INFO', 'NETWORK', 
                f'디바이스 네트워크 접근 허용: {ip_address} ({mac_address})',
                mac_address=mac_address, ip_address=ip_address
            )
            
            return True
            
        except Exception as e:
            logger.error(f"디바이스 인증 및 허용 실패: {e}")
            return False
    
    def revoke_device_access(self, wifi_auth_id: int, ip_address: str, mac_address: str) -> bool:
        """디바이스의 네트워크 접근을 취소합니다."""
        try:
            # 1. 네트워크 제어기를 통해 접근 차단
            if not self.controller.block_device(ip_address, mac_address):
                return False
            
            # 2. 데이터베이스에서 세션 종료
            from .network_service import end_active_sessions
            end_active_sessions(self.db, wifi_auth_id)
            
            # 3. 시스템 로그 기록
            from .network_service import log_system_event
            log_system_event(
                self.db, 'INFO', 'NETWORK', 
                f'디바이스 네트워크 접근 차단: {ip_address} ({mac_address})',
                mac_address=mac_address, ip_address=ip_address
            )
            
            return True
            
        except Exception as e:
            logger.error(f"디바이스 접근 취소 실패: {e}")
            return False
    
    def check_device_access(self, ip_address: str, mac_address: str) -> bool:
        """디바이스의 네트워크 접근 상태를 확인합니다."""
        return self.controller.is_device_allowed(ip_address, mac_address)
    
    def cleanup_expired_sessions(self) -> int:
        """만료된 세션들을 정리합니다."""
        try:
            # 1일 이상 된 세션 조회
            query = """
                SELECT ns.wifi_auth_id, wa.ip_address, wa.mac_address
                FROM network_sessions ns
                JOIN wifi_auth wa ON ns.wifi_auth_id = wa.id
                WHERE ns.is_active = 1 
                AND datetime(ns.started_at, '+1 day') < datetime('now')
            """
            
            cursor = self.db.execute(query)
            expired_sessions = cursor.fetchall()
            
            cleaned_count = 0
            for session in expired_sessions:
                wifi_auth_id, ip_address, mac_address = session
                if self.revoke_device_access(wifi_auth_id, ip_address, mac_address):
                    cleaned_count += 1
            
            logger.info(f"만료된 세션 {cleaned_count}개 정리 완료")
            return cleaned_count
            
        except Exception as e:
            logger.error(f"세션 정리 실패: {e}")
            return 0


# ===== DNS 리다이렉션 서비스 =====

class DNSRedirectService:
    """캡티브 포털용 DNS 리다이렉션"""
    
    def __init__(self, captive_portal_ip: str):
        self.captive_portal_ip = captive_portal_ip
    
    def handle_dns_query(self, domain: str, client_ip: str) -> str:
        """DNS 쿼리를 처리하고 캡티브 포털 IP를 반환합니다."""
        # 인증되지 않은 사용자는 모든 도메인을 캡티브 포털로 리다이렉트
        logger.info(f"DNS 리다이렉션: {domain} -> {self.captive_portal_ip} (클라이언트: {client_ip})")
        return self.captive_portal_ip
