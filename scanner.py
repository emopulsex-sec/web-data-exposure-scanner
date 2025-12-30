#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    WEB DATA EXPOSURE SCANNER (WDES)                          ║
║                                                                              ║
║  Herramienta OSINT para detectar datos sensibles expuestos en sitios web     ║
║  Detecta: emails, documentos de identidad, teléfonos y patrones custom       ║
║                                                                              ║
║  Autor: emopulsex-sec (https://github.com/emopulsex-sec)                     ║
║  Licencia: MIT                                                               ║
║  Versión: 1.1.0                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

USO ÉTICO Y LEGAL:
------------------
Esta herramienta está diseñada ÚNICAMENTE para:
- Auditorías de seguridad autorizadas
- Evaluación de tu propia infraestructura
- Investigación con permiso explícito del propietario del sitio

El uso no autorizado puede violar leyes locales e internacionales.
El autor no se responsabiliza por el mal uso de esta herramienta.

REQUISITOS:
-----------
pip install requests beautifulsoup4 colorama tqdm
pip install requests[socks]  # Opcional, solo si vas a usar Tor

USO:
----
python scanner.py                    # Modo interactivo
python scanner.py -u ejemplo.com     # Escaneo directo
python scanner.py -u ejemplo.com --tor  # Escaneo a través de Tor
python scanner.py -u ejemplo.com -o reporte.json  # Con salida JSON
"""

import re
import sys
import json
import argparse
import urllib.parse
from datetime import datetime
from collections import defaultdict
from typing import Set, Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from bs4 import BeautifulSoup
    from colorama import init, Fore, Style
    from tqdm import tqdm
    init(autoreset=True)
except ImportError as e:
    print(f"Error: Faltan dependencias. Ejecuta: pip install requests beautifulsoup4 colorama tqdm")
    print(f"Detalle: {e}")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURACIÓN Y CONSTANTES
# ══════════════════════════════════════════════════════════════════════════════

VERSION = "1.1.0"
BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║ {Fore.WHITE}██╗    ██╗██████╗ ███████╗███████╗{Fore.CYAN}                                           ║
║ {Fore.WHITE}██║    ██║██╔══██╗██╔════╝██╔════╝{Fore.CYAN}   Web Data Exposure Scanner              ║
║ {Fore.WHITE}██║ █╗ ██║██║  ██║█████╗  ███████╗{Fore.CYAN}   v{VERSION}                                 ║
║ {Fore.WHITE}██║███╗██║██║  ██║██╔══╝  ╚════██║{Fore.CYAN}                                           ║
║ {Fore.WHITE}╚███╔███╔╝██████╔╝███████╗███████║{Fore.CYAN}   OSINT Tool for Security Audits         ║
║ {Fore.WHITE} ╚══╝╚══╝ ╚═════╝ ╚══════╝╚══════╝{Fore.CYAN}                                           ║
╚══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

# Configuración de Tor
TOR_PROXY = "socks5h://127.0.0.1:9050"
TOR_CHECK_URL = "https://check.torproject.org/api/ip"

# Patrones de documentos de identidad por país
# Nota: Algunos patrones usan múltiples regex para capturar diferentes formatos
ID_PATTERNS = {
    "uruguay": {
        "name": "Cédula de Identidad (Uruguay)",
        # Captura múltiples formatos:
        # - Con puntos y guión: 1.234.567-8
        # - Solo con guión: 1234567-8  
        # - Sin separadores: 12345678
        "patterns": [
            r'\b\d{1,2}\.\d{3}\.\d{3}[-]?\d?\b',  # 1.234.567-8 o 1.234.567
            r'(?<!\d)(\d{7,8})(?:[-]\d)?(?!\d)',   # 12345678 o 1234567-8
        ],
        "example": "1.234.567-8, 12345678, 1234567-8",
        "description": "Formatos: X.XXX.XXX-X, XXXXXXXX, XXXXXXX-X"
    },
    "argentina": {
        "name": "DNI (Argentina)", 
        "pattern": r'\b\d{2}\.?\d{3}\.?\d{3}\b',
        "example": "12.345.678 o 12345678",
        "description": "Formato: XX.XXX.XXX o XXXXXXXX"
    },
    "brasil": {
        "name": "CPF (Brasil)",
        "pattern": r'\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b',
        "example": "123.456.789-00",
        "description": "Formato: XXX.XXX.XXX-XX"
    },
    "chile": {
        "name": "RUT (Chile)",
        "pattern": r'\b\d{1,2}\.?\d{3}\.?\d{3}-?[\dkK]\b',
        "example": "12.345.678-9",
        "description": "Formato: XX.XXX.XXX-X"
    },
    "mexico": {
        "name": "CURP (México)",
        "pattern": r'\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z\d]\d\b',
        "example": "GARC850101HDFRRL09",
        "description": "18 caracteres alfanuméricos"
    },
    "colombia": {
        "name": "Cédula de Ciudadanía (Colombia)",
        "pattern": r'\b\d{6,10}\b',
        "example": "1234567890",
        "description": "6 a 10 dígitos"
    },
    "peru": {
        "name": "DNI (Perú)",
        "pattern": r'\b\d{8}\b',
        "example": "12345678",
        "description": "8 dígitos"
    },
    "espana": {
        "name": "DNI/NIE (España)",
        "pattern": r'\b[XYZ]?\d{7,8}[A-Z]\b',
        "example": "12345678A o X1234567A",
        "description": "DNI: 8 dígitos + letra, NIE: letra + 7 dígitos + letra"
    },
    "generic": {
        "name": "Patrón Genérico (números de documento)",
        # Excluye números que empiezan con múltiples ceros (IDs de sistema)
        # y números que parecen fechas o códigos
        "pattern": r'\b[1-9]\d{5,10}\b',
        "example": "123456789",
        "description": "6-11 dígitos, no empieza con cero (reduce falsos positivos)",
        "warning": "⚠️ Modo genérico: puede generar falsos positivos"
    }
}

# Patrón de email
EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

# Patrón de teléfonos (genérico internacional)
PHONE_PATTERNS = {
    "international": r'\+\d{1,3}[\s.-]?\d{2,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4}',
    "local": r'\b\d{2,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b'
}

# User-Agent para requests
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# Extensiones de archivos a buscar
INTERESTING_EXTENSIONS = [
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.csv', '.txt', 
    '.json', '.xml', '.sql', '.bak', '.log', '.conf', '.env'
]


# ══════════════════════════════════════════════════════════════════════════════
# FUNCIONES DE TOR
# ══════════════════════════════════════════════════════════════════════════════

def check_tor_available() -> Tuple[bool, str]:
    """
    Verifica si Tor está disponible y funcionando.
    Retorna (disponible, mensaje)
    """
    try:
        # Primero verificar si PySocks está instalado
        import socks
    except ImportError:
        return False, "PySocks no está instalado. Ejecuta: pip install requests[socks]"
    
    try:
        # Intentar conectar a través de Tor
        session = requests.Session()
        session.proxies = {
            'http': TOR_PROXY,
            'https': TOR_PROXY
        }
        
        response = session.get(TOR_CHECK_URL, timeout=15)
        data = response.json()
        
        if data.get('IsTor', False):
            ip = data.get('IP', 'desconocida')
            return True, f"Conectado a Tor. IP de salida: {ip}"
        else:
            return False, "Conexión establecida pero no está pasando por Tor"
            
    except requests.exceptions.ConnectionError:
        return False, "No se puede conectar al servicio Tor. ¿Está Tor ejecutándose? (puerto 9050)"
    except requests.exceptions.Timeout:
        return False, "Timeout conectando a Tor. La red puede estar lenta o Tor no está corriendo."
    except Exception as e:
        return False, f"Error verificando Tor: {str(e)}"


def get_current_ip() -> str:
    """Obtiene la IP pública actual (sin Tor)"""
    try:
        response = requests.get("https://api.ipify.org?format=json", timeout=10)
        return response.json().get('ip', 'desconocida')
    except:
        return "no se pudo obtener"


# ══════════════════════════════════════════════════════════════════════════════
# ESTRUCTURAS DE DATOS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScanResult:
    """Resultado de un escaneo individual"""
    url: str
    emails: Set[str] = field(default_factory=set)
    documents: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    documents_with_urls: Dict[str, List[Dict[str, str]]] = field(default_factory=lambda: defaultdict(list))  # {tipo: [{doc: x, url: y}]}
    phones: Set[str] = field(default_factory=set)
    interesting_files: Set[str] = field(default_factory=set)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "emails": list(self.emails),
            "documents": {k: list(v) for k, v in self.documents.items()},
            "documents_with_urls": dict(self.documents_with_urls),
            "phones": list(self.phones),
            "interesting_files": list(self.interesting_files),
            "errors": self.errors
        }


@dataclass  
class ScanReport:
    """Reporte completo del escaneo"""
    target: str
    scan_date: str
    total_urls_scanned: int = 0
    total_emails: int = 0
    total_documents: int = 0
    total_phones: int = 0
    unique_emails: Set[str] = field(default_factory=set)
    unique_documents: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    unique_phones: Set[str] = field(default_factory=set)
    interesting_files: Set[str] = field(default_factory=set)
    results_by_url: List[ScanResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    # Nuevo: tracking de documentos con sus URLs de origen
    documents_detail: Dict[str, List[Dict[str, str]]] = field(default_factory=lambda: defaultdict(list))
    
    def to_dict(self) -> dict:
        # Crear resumen de documentos con conteo
        docs_summary = {}
        for doc_type, docs in self.unique_documents.items():
            docs_summary[doc_type] = {
                "unique_count": len(docs),
                "documents": sorted(list(docs))
            }
        
        # Crear detalle de documentos con URLs
        docs_with_urls = {}
        for doc_type, entries in self.documents_detail.items():
            docs_with_urls[doc_type] = entries
        
        return {
            "target": self.target,
            "scan_date": self.scan_date,
            "summary": {
                "total_urls_scanned": self.total_urls_scanned,
                "unique_emails_found": len(self.unique_emails),
                "unique_documents_found": sum(len(v) for v in self.unique_documents.values()),
                "unique_phones_found": len(self.unique_phones),
                "interesting_files_found": len(self.interesting_files)
            },
            "findings": {
                "emails": sorted(list(self.unique_emails)),
                "documents_summary": docs_summary,
                "documents_detail": docs_with_urls,
                "phones": sorted(list(self.unique_phones)),
                "interesting_files": sorted(list(self.interesting_files))
            },
            "detailed_results": [r.to_dict() for r in self.results_by_url],
            "errors": self.errors
        }


# ══════════════════════════════════════════════════════════════════════════════
# CLASE PRINCIPAL DEL SCANNER
# ══════════════════════════════════════════════════════════════════════════════

class WebDataExposureScanner:
    """Scanner principal para detectar datos expuestos"""
    
    def __init__(
        self,
        target: str,
        id_patterns: List[str] = None,
        max_depth: int = 3,
        max_pages: int = 100,
        threads: int = 5,
        timeout: int = 10,
        verify_ssl: bool = True,
        scan_emails: bool = True,
        scan_phones: bool = True,
        scan_files: bool = True,
        verbose: bool = True,
        use_tor: bool = False
    ):
        self.target = self._normalize_url(target)
        self.base_domain = urllib.parse.urlparse(self.target).netloc
        self.id_patterns = id_patterns or ["uruguay"]
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.threads = threads if not use_tor else min(threads, 3)  # Limitar threads con Tor
        self.timeout = timeout if not use_tor else max(timeout, 20)  # Mayor timeout con Tor
        self.verify_ssl = verify_ssl
        self.scan_emails = scan_emails
        self.scan_phones = scan_phones
        self.scan_files = scan_files
        self.verbose = verbose
        self.use_tor = use_tor
        
        self.visited_urls: Set[str] = set()
        self.urls_to_visit: Set[str] = {self.target}
        self.session = self._create_session()
        
        self.report = ScanReport(
            target=self.target,
            scan_date=datetime.now().isoformat()
        )
    
    def _normalize_url(self, url: str) -> str:
        """Normaliza la URL agregando esquema si falta"""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def _create_session(self) -> requests.Session:
        """Crea una sesión HTTP configurada"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        # Configurar proxy Tor si está habilitado
        if self.use_tor:
            session.proxies = {
                'http': TOR_PROXY,
                'https': TOR_PROXY
            }
        
        return session
    
    def _log(self, message: str, level: str = "info"):
        """Imprime mensaje si verbose está activo"""
        if not self.verbose:
            return
            
        colors = {
            "info": Fore.CYAN,
            "success": Fore.GREEN,
            "warning": Fore.YELLOW,
            "error": Fore.RED,
            "found": Fore.MAGENTA
        }
        color = colors.get(level, Fore.WHITE)
        print(f"{color}[{level.upper()}]{Style.RESET_ALL} {message}")
    
    def _is_same_domain(self, url: str) -> bool:
        """Verifica si la URL pertenece al mismo dominio"""
        try:
            parsed = urllib.parse.urlparse(url)
            return parsed.netloc == self.base_domain or parsed.netloc.endswith('.' + self.base_domain)
        except:
            return False
    
    def _extract_links(self, soup: BeautifulSoup, current_url: str) -> Set[str]:
        """Extrae todos los links de una página"""
        links = set()
        
        for tag in soup.find_all(['a', 'link'], href=True):
            href = tag['href']
            
            # Resolver URLs relativas
            full_url = urllib.parse.urljoin(current_url, href)
            
            # Limpiar fragmentos y parámetros innecesarios
            parsed = urllib.parse.urlparse(full_url)
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            if self._is_same_domain(clean_url):
                links.add(clean_url)
        
        return links
    
    def _extract_emails(self, text: str) -> Set[str]:
        """Extrae emails del texto"""
        emails = set(re.findall(EMAIL_PATTERN, text, re.IGNORECASE))
        # Filtrar emails obvios de ejemplo o placeholder
        filtered = {e.lower() for e in emails if not any(x in e.lower() for x in 
                   ['example.com', 'test.com', 'localhost', 'domain.com', '@email.com'])}
        return filtered
    
    def _extract_documents(self, text: str) -> Dict[str, Set[str]]:
        """Extrae documentos de identidad según los patrones configurados"""
        documents = defaultdict(set)
        
        for pattern_key in self.id_patterns:
            if pattern_key in ID_PATTERNS:
                pattern_info = ID_PATTERNS[pattern_key]
                
                # Soportar tanto 'pattern' (singular) como 'patterns' (lista)
                patterns = pattern_info.get('patterns', [])
                if 'pattern' in pattern_info:
                    patterns.append(pattern_info['pattern'])
                
                for pattern in patterns:
                    matches = re.findall(pattern, text)
                    if matches:
                        for match in matches:
                            if isinstance(match, tuple):
                                clean_match = next((m for m in match if m), None)
                            else:
                                clean_match = match
                            if clean_match and len(clean_match) >= 7:  # Mínimo 7 dígitos para CI
                                documents[pattern_info['name']].add(clean_match)
        
        return documents
    
    def _extract_documents_from_urls(self, soup: BeautifulSoup) -> Tuple[Dict[str, Set[str]], Dict[str, List[Dict[str, str]]]]:
        """
        Extrae documentos de identidad de URLs de imágenes y otros recursos.
        Retorna: (documentos_unicos, documentos_con_urls)
        """
        documents = defaultdict(set)
        documents_with_urls = defaultdict(list)
        
        # Buscar en src de imágenes, href de links, etc.
        url_attributes = []
        
        # Imágenes
        for img in soup.find_all('img', src=True):
            url_attributes.append(img['src'])
        
        # Links a archivos
        for a in soup.find_all('a', href=True):
            href = a['href']
            # Solo incluir si parece un archivo (tiene extensión)
            if '.' in href.split('/')[-1]:
                url_attributes.append(href)
        
        # Iframes, videos, etc.
        for tag in soup.find_all(['iframe', 'video', 'audio', 'source', 'embed'], src=True):
            url_attributes.append(tag.get('src', ''))
        
        # Buscar patrones en todas las URLs encontradas
        for url in url_attributes:
            for pattern_key in self.id_patterns:
                if pattern_key in ID_PATTERNS:
                    pattern_info = ID_PATTERNS[pattern_key]
                    
                    # Soportar tanto 'pattern' (singular) como 'patterns' (lista)
                    patterns = pattern_info.get('patterns', [])
                    if 'pattern' in pattern_info:
                        patterns.append(pattern_info['pattern'])
                    
                    for pattern in patterns:
                        matches = re.findall(pattern, url)
                        if matches:
                            for match in matches:
                                if isinstance(match, tuple):
                                    clean_match = next((m for m in match if m), None)
                                else:
                                    clean_match = match
                                if clean_match and len(clean_match) >= 7:
                                    documents[pattern_info['name']].add(clean_match)
                                    # Guardar relación documento -> URL
                                    documents_with_urls[pattern_info['name']].append({
                                        'document': clean_match,
                                        'source_url': url
                                    })
        
        return documents, documents_with_urls
    
    def _extract_phones(self, text: str) -> Set[str]:
        """Extrae números de teléfono del texto"""
        phones = set()
        for pattern in PHONE_PATTERNS.values():
            matches = re.findall(pattern, text)
            phones.update(matches)
        return phones
    
    def _find_interesting_files(self, soup: BeautifulSoup, current_url: str) -> Set[str]:
        """Busca archivos potencialmente interesantes"""
        files = set()
        
        for tag in soup.find_all(['a', 'link', 'script', 'img'], href=True):
            href = tag.get('href', '') or tag.get('src', '')
            full_url = urllib.parse.urljoin(current_url, href)
            
            if any(full_url.lower().endswith(ext) for ext in INTERESTING_EXTENSIONS):
                if self._is_same_domain(full_url):
                    files.add(full_url)
        
        return files
    
    def _scan_page(self, url: str) -> Optional[ScanResult]:
        """Escanea una página individual"""
        result = ScanResult(url=url)
        
        try:
            response = self.session.get(
                url, 
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            response.raise_for_status()
            
            # Obtener contenido como texto
            text = response.text
            soup = BeautifulSoup(text, 'html.parser')
            
            # Extraer texto limpio (sin tags HTML)
            clean_text = soup.get_text(separator=' ')
            
            # Buscar emails
            if self.scan_emails:
                result.emails = self._extract_emails(clean_text)
                result.emails.update(self._extract_emails(text))  # También en HTML crudo
            
            # Buscar documentos en texto
            result.documents = self._extract_documents(clean_text)
            
            # Buscar documentos en URLs de imágenes y recursos (CRÍTICO para CI en nombres de archivo)
            docs_from_urls, docs_with_urls = self._extract_documents_from_urls(soup)
            for doc_type, docs in docs_from_urls.items():
                result.documents[doc_type].update(docs)
            
            # Guardar detalle de documentos con sus URLs
            for doc_type, entries in docs_with_urls.items():
                result.documents_with_urls[doc_type].extend(entries)
            
            # Buscar teléfonos
            if self.scan_phones:
                result.phones = self._extract_phones(clean_text)
            
            # Buscar archivos interesantes
            if self.scan_files:
                result.interesting_files = self._find_interesting_files(soup, url)
            
            # Extraer nuevos links para continuar crawling
            new_links = self._extract_links(soup, url)
            self.urls_to_visit.update(new_links - self.visited_urls)
            
        except requests.exceptions.SSLError:
            result.errors.append(f"Error SSL en {url}")
            self._log(f"Error SSL: {url}", "warning")
        except requests.exceptions.Timeout:
            result.errors.append(f"Timeout en {url}")
            self._log(f"Timeout: {url}", "warning")
        except requests.exceptions.RequestException as e:
            result.errors.append(f"Error en {url}: {str(e)}")
            self._log(f"Error request: {url} - {e}", "error")
        except Exception as e:
            result.errors.append(f"Error inesperado en {url}: {str(e)}")
            self._log(f"Error inesperado: {url} - {e}", "error")
        
        return result
    
    def scan(self) -> ScanReport:
        """Ejecuta el escaneo completo"""
        self._log(f"Iniciando escaneo de: {self.target}", "info")
        self._log(f"Patrones de documentos: {', '.join(self.id_patterns)}", "info")
        self._log(f"Profundidad máxima: {self.max_depth}, Páginas máximas: {self.max_pages}", "info")
        
        if self.use_tor:
            self._log(f"🧅 Modo Tor ACTIVADO - Conexión anónima", "success")
            self._log(f"   Threads reducidos a {self.threads}, Timeout aumentado a {self.timeout}s", "info")
        else:
            self._log(f"Modo directo (sin Tor)", "info")
        
        print()
        
        depth = 0
        
        with tqdm(total=self.max_pages, desc="Escaneando páginas", unit="pág") as pbar:
            while self.urls_to_visit and len(self.visited_urls) < self.max_pages and depth < self.max_depth:
                current_batch = list(self.urls_to_visit - self.visited_urls)[:self.threads * 2]
                self.urls_to_visit -= set(current_batch)
                
                if not current_batch:
                    break
                
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    futures = {executor.submit(self._scan_page, url): url for url in current_batch}
                    
                    for future in as_completed(futures):
                        url = futures[future]
                        self.visited_urls.add(url)
                        
                        try:
                            result = future.result()
                            if result:
                                self.report.results_by_url.append(result)
                                
                                # Actualizar totales
                                self.report.unique_emails.update(result.emails)
                                for doc_type, docs in result.documents.items():
                                    self.report.unique_documents[doc_type].update(docs)
                                self.report.unique_phones.update(result.phones)
                                self.report.interesting_files.update(result.interesting_files)
                                
                                # Agregar detalle de documentos con URLs
                                for doc_type, entries in result.documents_with_urls.items():
                                    self.report.documents_detail[doc_type].extend(entries)
                                
                                # Mostrar hallazgos
                                if result.emails:
                                    self._log(f"Encontrados {len(result.emails)} emails en {url}", "found")
                                if any(result.documents.values()):
                                    total_docs = sum(len(v) for v in result.documents.values())
                                    self._log(f"Encontrados {total_docs} documentos en {url}", "found")
                                
                        except Exception as e:
                            self.report.errors.append(f"Error procesando {url}: {str(e)}")
                        
                        pbar.update(1)
                        
                        if len(self.visited_urls) >= self.max_pages:
                            break
                
                depth += 1
        
        self.report.total_urls_scanned = len(self.visited_urls)
        return self.report
    
    def print_summary(self):
        """Imprime un resumen del escaneo"""
        print(f"\n{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}                    RESUMEN DEL ESCANEO{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}\n")
        
        print(f"  {Fore.WHITE}Objetivo:{Style.RESET_ALL} {self.report.target}")
        print(f"  {Fore.WHITE}Fecha:{Style.RESET_ALL} {self.report.scan_date}")
        print(f"  {Fore.WHITE}URLs escaneadas:{Style.RESET_ALL} {self.report.total_urls_scanned}")
        
        print(f"\n{Fore.YELLOW}  HALLAZGOS:{Style.RESET_ALL}")
        print(f"  {'─' * 40}")
        
        # Emails
        email_count = len(self.report.unique_emails)
        email_color = Fore.RED if email_count > 0 else Fore.GREEN
        print(f"  {email_color}📧 Emails únicos encontrados: {email_count}{Style.RESET_ALL}")
        if email_count > 0 and email_count <= 20:
            for email in sorted(self.report.unique_emails):
                print(f"      • {email}")
        elif email_count > 20:
            for email in sorted(list(self.report.unique_emails)[:20]):
                print(f"      • {email}")
            print(f"      ... y {email_count - 20} más")
        
        # Documentos
        for doc_type, docs in self.report.unique_documents.items():
            doc_count = len(docs)
            doc_color = Fore.RED if doc_count > 0 else Fore.GREEN
            print(f"  {doc_color}🪪 {doc_type}: {doc_count}{Style.RESET_ALL}")
            if doc_count > 0 and doc_count <= 10:
                for doc in sorted(docs):
                    print(f"      • {doc}")
            elif doc_count > 10:
                for doc in sorted(list(docs)[:10]):
                    print(f"      • {doc}")
                print(f"      ... y {doc_count - 10} más")
        
        # Teléfonos
        phone_count = len(self.report.unique_phones)
        if phone_count > 0:
            phone_color = Fore.YELLOW
            print(f"  {phone_color}📞 Teléfonos encontrados: {phone_count}{Style.RESET_ALL}")
        
        # Archivos interesantes
        file_count = len(self.report.interesting_files)
        if file_count > 0:
            file_color = Fore.YELLOW
            print(f"  {file_color}📁 Archivos interesantes: {file_count}{Style.RESET_ALL}")
            for f in sorted(list(self.report.interesting_files)[:10]):
                print(f"      • {f}")
            if file_count > 10:
                print(f"      ... y {file_count - 10} más")
        
        # Errores
        if self.report.errors:
            print(f"\n  {Fore.RED}⚠️  Errores durante el escaneo: {len(self.report.errors)}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}\n")
    
    def save_report(self, filename: str, format: str = "json"):
        """Guarda el reporte en archivo"""
        if format == "json":
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.report.to_dict(), f, indent=2, ensure_ascii=False)
        elif format == "txt":
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("=" * 70 + "\n")
                f.write(f"REPORTE DE ESCANEO - {self.report.target}\n")
                f.write("=" * 70 + "\n\n")
                f.write(f"Fecha: {self.report.scan_date}\n")
                f.write(f"URLs escaneadas: {self.report.total_urls_scanned}\n\n")
                
                # Emails
                f.write("=" * 70 + "\n")
                f.write("EMAILS ENCONTRADOS\n")
                f.write("=" * 70 + "\n")
                f.write(f"Total únicos: {len(self.report.unique_emails)}\n\n")
                for i, email in enumerate(sorted(self.report.unique_emails), 1):
                    f.write(f"{i:4d}. {email}\n")
                
                # Documentos - Resumen con conteo
                f.write("\n" + "=" * 70 + "\n")
                f.write("DOCUMENTOS DE IDENTIDAD - RESUMEN\n")
                f.write("=" * 70 + "\n")
                
                for doc_type, docs in self.report.unique_documents.items():
                    f.write(f"\n{doc_type}:\n")
                    f.write("-" * 50 + "\n")
                    f.write(f"Total únicos: {len(docs)}\n\n")
                    
                    # Contar ocurrencias de cada documento
                    from collections import Counter
                    doc_counts = Counter()
                    for entry in self.report.documents_detail.get(doc_type, []):
                        doc_counts[entry['document']] += 1
                    
                    f.write("IMPORTANTE: Estos números están expuestos públicamente\n")
                    f.write("en nombres de archivos en el sitio web.\n\n")
                    
                    for i, doc in enumerate(sorted(docs), 1):
                        count = doc_counts.get(doc, 1)
                        plural = "fotos" if count > 1 else "foto"
                        f.write(f"{i:4d}. CI: {doc} ({count} {plural})\n")
                
                # Documentos - Detalle con URLs
                f.write("\n" + "=" * 70 + "\n")
                f.write("DOCUMENTOS DE IDENTIDAD - DETALLE CON URLs\n")
                f.write("=" * 70 + "\n")
                
                for doc_type, entries in self.report.documents_detail.items():
                    f.write(f"\n{doc_type}:\n")
                    f.write("-" * 50 + "\n")
                    
                    for i, entry in enumerate(entries, 1):
                        f.write(f"{i:4d}. CI: {entry['document']}\n")
                        f.write(f"      URL: {entry['source_url']}\n")
                
                # Archivos interesantes
                if self.report.interesting_files:
                    f.write("\n" + "=" * 70 + "\n")
                    f.write("ARCHIVOS INTERESANTES\n")
                    f.write("=" * 70 + "\n\n")
                    for i, file in enumerate(sorted(self.report.interesting_files), 1):
                        f.write(f"{i:4d}. {file}\n")
        
        self._log(f"Reporte guardado en: {filename}", "success")
    
    def save_detailed_report(self, base_filename: str):
        """Guarda múltiples reportes detallados para auditorías de seguridad"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = urllib.parse.urlparse(self.report.target).netloc.replace('.', '_')
        
        # 1. Reporte JSON completo
        json_file = f"{base_filename}_{timestamp}.json"
        self.save_report(json_file, format="json")
        
        # 2. Reporte TXT general
        txt_file = f"{base_filename}_{timestamp}.txt"
        self.save_report(txt_file, format="txt")
        
        # 3. Archivo de documentos con URLs (detalle completo)
        if self.report.documents_detail:
            detail_file = f"{base_filename}_Detalle_CI_URLs_{timestamp}.txt"
            with open(detail_file, 'w', encoding='utf-8') as f:
                f.write("AUDITORÍA - Documentos con URLs de origen\n")
                f.write("=" * 70 + "\n")
                f.write(f"Fecha: {self.report.scan_date}\n")
                f.write(f"Sitio: {self.report.target}\n")
                f.write("=" * 70 + "\n\n")
                
                total = 0
                for doc_type, entries in self.report.documents_detail.items():
                    f.write(f"\n{doc_type}:\n")
                    f.write("-" * 60 + "\n\n")
                    
                    for i, entry in enumerate(entries, 1):
                        f.write(f"{i}. CI: {entry['document']}\n")
                        f.write(f"   URL: {entry['source_url']}\n\n")
                        total += 1
                
                f.write(f"\nTotal de exposiciones: {total}\n")
            
            self._log(f"Reporte detallado guardado en: {detail_file}", "success")
        
        # 4. Archivo de documentos únicos con conteo
        if self.report.unique_documents:
            unique_file = f"{base_filename}_CIs_Unicos_{timestamp}.txt"
            with open(unique_file, 'w', encoding='utf-8') as f:
                f.write("AUDITORÍA - Documentos Únicos Expuestos\n")
                f.write("=" * 70 + "\n")
                f.write(f"Fecha: {self.report.scan_date}\n")
                f.write(f"Sitio: {self.report.target}\n")
                f.write("=" * 70 + "\n\n")
                f.write("IMPORTANTE: Estos números están expuestos públicamente\n")
                f.write("en nombres de archivos en el sitio web.\n\n")
                
                for doc_type, docs in self.report.unique_documents.items():
                    f.write(f"{doc_type}:\n")
                    f.write("-" * 50 + "\n")
                    f.write(f"Total únicos: {len(docs)}\n\n")
                    
                    # Contar ocurrencias
                    from collections import Counter
                    doc_counts = Counter()
                    for entry in self.report.documents_detail.get(doc_type, []):
                        doc_counts[entry['document']] += 1
                    
                    for i, doc in enumerate(sorted(docs), 1):
                        count = doc_counts.get(doc, 1)
                        plural = "fotos" if count > 1 else "foto"
                        f.write(f"{i:4d}. CI: {doc} ({count} {plural})\n")
                    
                    f.write("\n")
            
            self._log(f"Reporte de únicos guardado en: {unique_file}", "success")
        
        return {
            'json': json_file,
            'txt': txt_file,
            'detail': detail_file if self.report.documents_detail else None,
            'unique': unique_file if self.report.unique_documents else None
        }


# ══════════════════════════════════════════════════════════════════════════════
# INTERFAZ DE USUARIO
# ══════════════════════════════════════════════════════════════════════════════

def show_menu():
    """Muestra el menú interactivo"""
    print(BANNER)
    print(f"{Fore.YELLOW}  ⚠️  ADVERTENCIA: Use esta herramienta solo en sitios autorizados{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  ⚠️  El uso no autorizado puede violar leyes locales e internacionales{Style.RESET_ALL}")
    print()

def get_user_input() -> dict:
    """Obtiene la configuración del usuario de forma interactiva"""
    config = {}
    
    # ══════════════════════════════════════════════════════════════════════════
    # MENÚ DE CONEXIÓN (TOR O DIRECTA)
    # ══════════════════════════════════════════════════════════════════════════
    print(f"{Fore.CYAN}┌─ Modo de Conexión ───────────────────────────────────────────────────┐{Style.RESET_ALL}")
    print(f"{Fore.CYAN}│{Style.RESET_ALL}")
    print(f"{Fore.CYAN}│{Style.RESET_ALL}  {Fore.WHITE}1.{Style.RESET_ALL} 🌐 Conexión directa (más rápido)")
    print(f"{Fore.CYAN}│{Style.RESET_ALL}  {Fore.WHITE}2.{Style.RESET_ALL} 🧅 Conexión a través de Tor (anónimo)")
    print(f"{Fore.CYAN}│{Style.RESET_ALL}")
    
    while True:
        tor_choice = input(f"{Fore.CYAN}│{Style.RESET_ALL} Seleccione modo de conexión [1/2]: ").strip()
        
        if tor_choice == "1" or tor_choice == "":
            config['use_tor'] = False
            print(f"{Fore.CYAN}│{Style.RESET_ALL}")
            print(f"{Fore.CYAN}│{Style.RESET_ALL}  {Fore.GREEN}✓ Modo: Conexión directa{Style.RESET_ALL}")
            current_ip = get_current_ip()
            print(f"{Fore.CYAN}│{Style.RESET_ALL}  {Fore.YELLOW}ℹ Tu IP pública: {current_ip}{Style.RESET_ALL}")
            break
            
        elif tor_choice == "2":
            print(f"{Fore.CYAN}│{Style.RESET_ALL}")
            print(f"{Fore.CYAN}│{Style.RESET_ALL}  {Fore.YELLOW}⏳ Verificando conexión a Tor...{Style.RESET_ALL}")
            
            tor_available, tor_message = check_tor_available()
            
            if tor_available:
                config['use_tor'] = True
                print(f"{Fore.CYAN}│{Style.RESET_ALL}  {Fore.GREEN}✓ {tor_message}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}│{Style.RESET_ALL}")
                print(f"{Fore.CYAN}│{Style.RESET_ALL}  {Fore.YELLOW}⚠️  Nota: El escaneo será más lento a través de Tor{Style.RESET_ALL}")
                print(f"{Fore.CYAN}│{Style.RESET_ALL}  {Fore.YELLOW}⚠️  Algunos sitios pueden bloquear tráfico de Tor{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.CYAN}│{Style.RESET_ALL}  {Fore.RED}✗ {tor_message}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}│{Style.RESET_ALL}")
                retry = input(f"{Fore.CYAN}│{Style.RESET_ALL}  ¿Reintentar (r) o usar conexión directa (d)? [r/d]: ").strip().lower()
                if retry == 'd':
                    config['use_tor'] = False
                    print(f"{Fore.CYAN}│{Style.RESET_ALL}  {Fore.GREEN}✓ Usando conexión directa{Style.RESET_ALL}")
                    break
                # Si elige reintentar, el loop continúa
        else:
            print(f"{Fore.CYAN}│{Style.RESET_ALL}  {Fore.RED}Opción no válida. Ingrese 1 o 2{Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}│{Style.RESET_ALL}")
    print(f"{Fore.CYAN}└──────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
    print()
    
    # ══════════════════════════════════════════════════════════════════════════
    # CONFIGURACIÓN DEL ESCANEO
    # ══════════════════════════════════════════════════════════════════════════
    
    # URL objetivo
    print(f"{Fore.CYAN}┌─ Configuración del Escaneo ─────────────────────────────────────────┐{Style.RESET_ALL}")
    print(f"{Fore.CYAN}│{Style.RESET_ALL}")
    
    while True:
        url = input(f"{Fore.CYAN}│{Style.RESET_ALL} 🎯 URL del sitio objetivo: ").strip()
        if url:
            config['target'] = url
            break
        print(f"{Fore.CYAN}│{Style.RESET_ALL}   {Fore.RED}Por favor ingrese una URL válida{Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}│{Style.RESET_ALL}")
    
    # Patrones de documentos
    print(f"{Fore.CYAN}│{Style.RESET_ALL} 📋 Patrones de documentos disponibles:")
    for i, (key, info) in enumerate(ID_PATTERNS.items(), 1):
        print(f"{Fore.CYAN}│{Style.RESET_ALL}    {i}. {key}: {info['name']} (ej: {info['example']})")
    
    print(f"{Fore.CYAN}│{Style.RESET_ALL}")
    patterns_input = input(f"{Fore.CYAN}│{Style.RESET_ALL} 🪪 Seleccione patrones (números separados por coma, Enter=uruguay): ").strip()
    
    if patterns_input:
        pattern_keys = list(ID_PATTERNS.keys())
        selected = []
        for num in patterns_input.split(','):
            try:
                idx = int(num.strip()) - 1
                if 0 <= idx < len(pattern_keys):
                    selected.append(pattern_keys[idx])
            except ValueError:
                pass
        config['id_patterns'] = selected if selected else ['uruguay']
    else:
        config['id_patterns'] = ['uruguay']
    
    # Mostrar advertencias si hay patrones con warnings
    for pattern_key in config['id_patterns']:
        if pattern_key in ID_PATTERNS and 'warning' in ID_PATTERNS[pattern_key]:
            print(f"{Fore.CYAN}│{Style.RESET_ALL}   {Fore.YELLOW}{ID_PATTERNS[pattern_key]['warning']}{Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}│{Style.RESET_ALL}")
    
    # Opciones avanzadas
    advanced = input(f"{Fore.CYAN}│{Style.RESET_ALL} ⚙️  ¿Configurar opciones avanzadas? (s/N): ").strip().lower()
    
    if advanced == 's':
        print(f"{Fore.CYAN}│{Style.RESET_ALL}")
        
        try:
            depth = input(f"{Fore.CYAN}│{Style.RESET_ALL}    Profundidad máxima (1-10, default=3): ").strip()
            config['max_depth'] = int(depth) if depth else 3
        except ValueError:
            config['max_depth'] = 3
        
        try:
            pages = input(f"{Fore.CYAN}│{Style.RESET_ALL}    Máximo de páginas (10-500, default=100): ").strip()
            config['max_pages'] = int(pages) if pages else 100
        except ValueError:
            config['max_pages'] = 100
        
        try:
            threads = input(f"{Fore.CYAN}│{Style.RESET_ALL}    Threads concurrentes (1-10, default=5): ").strip()
            config['threads'] = int(threads) if threads else 5
        except ValueError:
            config['threads'] = 5
        
        ssl = input(f"{Fore.CYAN}│{Style.RESET_ALL}    Verificar SSL (S/n): ").strip().lower()
        config['verify_ssl'] = ssl != 'n'
    else:
        config['max_depth'] = 3
        config['max_pages'] = 100
        config['threads'] = 5
        config['verify_ssl'] = True
    
    print(f"{Fore.CYAN}│{Style.RESET_ALL}")
    
    # Nombre del reporte
    report_name = input(f"{Fore.CYAN}│{Style.RESET_ALL} 📄 Nombre del reporte (Enter=reporte_<dominio>.json): ").strip()
    if not report_name:
        domain = urllib.parse.urlparse(config['target'] if config['target'].startswith('http') else 'https://' + config['target']).netloc
        report_name = f"reporte_{domain.replace('.', '_')}.json"
    if not report_name.endswith('.json'):
        report_name += '.json'
    config['report_name'] = report_name
    
    print(f"{Fore.CYAN}│{Style.RESET_ALL}")
    print(f"{Fore.CYAN}└──────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
    
    return config


def run_interactive():
    """Ejecuta el escáner en modo interactivo"""
    show_menu()
    config = get_user_input()
    
    tor_status = "🧅 Tor" if config.get('use_tor', False) else "🌐 Directa"
    print(f"\n{Fore.GREEN}✓ Configuración confirmada. Iniciando escaneo ({tor_status})...{Style.RESET_ALL}\n")
    
    scanner = WebDataExposureScanner(
        target=config['target'],
        id_patterns=config['id_patterns'],
        max_depth=config['max_depth'],
        max_pages=config['max_pages'],
        threads=config['threads'],
        verify_ssl=config['verify_ssl'],
        use_tor=config.get('use_tor', False)
    )
    
    scanner.scan()
    scanner.print_summary()
    
    # Generar reportes detallados (múltiples archivos)
    base_name = config['report_name'].replace('.json', '')
    reports = scanner.save_detailed_report(base_name)
    
    print(f"\n{Fore.GREEN}✓ Reportes guardados:{Style.RESET_ALL}")
    print(f"  • {reports['json']} (JSON completo)")
    print(f"  • {reports['txt']} (Texto general)")
    if reports.get('detail'):
        print(f"  • {reports['detail']} (Detalle CI con URLs)")
    if reports.get('unique'):
        print(f"  • {reports['unique']} (CIs únicos con conteo)")


def run_cli(args):
    """Ejecuta el escáner desde línea de comandos"""
    print(BANNER)
    
    # Verificar Tor si está habilitado
    if args.tor:
        print(f"{Fore.YELLOW}⏳ Verificando conexión a Tor...{Style.RESET_ALL}")
        tor_available, tor_message = check_tor_available()
        
        if tor_available:
            print(f"{Fore.GREEN}✓ {tor_message}{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.RED}✗ {tor_message}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Continuando sin Tor...{Style.RESET_ALL}\n")
            args.tor = False
    
    scanner = WebDataExposureScanner(
        target=args.url,
        id_patterns=args.patterns.split(',') if args.patterns else ['uruguay'],
        max_depth=args.depth,
        max_pages=args.pages,
        threads=args.threads,
        verify_ssl=not args.no_ssl,
        verbose=not args.quiet,
        use_tor=args.tor
    )
    
    scanner.scan()
    
    if not args.quiet:
        scanner.print_summary()
    
    if args.output:
        scanner.save_report(args.output)
        if not args.quiet:
            print(f"{Fore.GREEN}✓ Reporte guardado en: {args.output}{Style.RESET_ALL}")


def main():
    """Punto de entrada principal"""
    parser = argparse.ArgumentParser(
        description='Web Data Exposure Scanner - Herramienta OSINT para detectar datos sensibles expuestos',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  %(prog)s                                    # Modo interactivo
  %(prog)s -u ejemplo.com                     # Escaneo básico
  %(prog)s -u ejemplo.com --tor               # Escaneo anónimo vía Tor
  %(prog)s -u ejemplo.com -p uruguay,argentina # Múltiples patrones
  %(prog)s -u ejemplo.com -o reporte.json     # Guardar reporte
  %(prog)s -u ejemplo.com -d 5 -m 200         # Profundidad y páginas custom
        """
    )
    
    parser.add_argument('-u', '--url', help='URL del sitio objetivo')
    parser.add_argument('-p', '--patterns', help='Patrones de documentos (separados por coma)', default='uruguay')
    parser.add_argument('-d', '--depth', type=int, default=3, help='Profundidad máxima de crawling (default: 3)')
    parser.add_argument('-m', '--pages', type=int, default=100, help='Máximo de páginas a escanear (default: 100)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Threads concurrentes (default: 5)')
    parser.add_argument('-o', '--output', help='Archivo de salida para el reporte (JSON)')
    parser.add_argument('--tor', action='store_true', help='Usar red Tor para anonimato (requiere Tor corriendo)')
    parser.add_argument('--no-ssl', action='store_true', help='Deshabilitar verificación SSL')
    parser.add_argument('-q', '--quiet', action='store_true', help='Modo silencioso (menos output)')
    parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {VERSION}')
    parser.add_argument('--list-patterns', action='store_true', help='Listar patrones de documentos disponibles')
    
    args = parser.parse_args()
    
    if args.list_patterns:
        print(f"\n{Fore.CYAN}Patrones de documentos disponibles:{Style.RESET_ALL}\n")
        for key, info in ID_PATTERNS.items():
            print(f"  {Fore.WHITE}{key}{Style.RESET_ALL}")
            print(f"    Nombre: {info['name']}")
            print(f"    Ejemplo: {info['example']}")
            print(f"    Descripción: {info['description']}")
            print()
        return
    
    if args.url:
        run_cli(args)
    else:
        run_interactive()


if __name__ == "__main__":
    main()
