#!/usr/bin/env python3
"""
OPC UA Certificate Wizard (OOP) with runtime-aware SAN detection.
Generates RSA keys, self-signed certs or CSRs, writes PEM/DER files,
creates Siemens-style trustlist folders, detects WSL/Docker/native host,
auto-populates SAN entries, and allows user confirmation/editing.
"""

import sys
import socket
import ipaddress
import datetime
import os
import logging
import argparse
from pathlib import Path
from typing import List, Optional, Tuple

from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.general_name import DNSName, IPAddress, UniformResourceIdentifier

SIEMENS_SUBDIRS = ["trusted/certs", "trusted/crl", "rejected", "own/certs", "own/private"]

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class FileManager:
    def __init__(self, base: Path):
        self.base = base.expanduser().resolve()

    def make_structure(self):
        for sub in SIEMENS_SUBDIRS:
            (self.base / sub).mkdir(parents=True, exist_ok=True)

    def _check_overwrite(self, path: Path, interactive: bool = True) -> bool:
        """Check if file exists and ask for overwrite confirmation if interactive."""
        if not path.exists():
            return True

        if not interactive:
            logger.warning(f"Overwriting existing file: {path}")
            return True

        try:
            from prompt_toolkit import prompt
            response = prompt(f"File {path} exists. Overwrite? (y/n) [n]: ")
            return response.lower() in ("y", "yes")
        except:
            # Fallback to input() if prompt_toolkit fails
            response = input(f"File {path} exists. Overwrite? (y/n) [n]: ")
            return response.lower() in ("y", "yes")

    def _save_pem_and_optional_der(self,
                                   pem_bytes: bytes,
                                   pem_name: str,
                                   der_bytes: Optional[bytes] = None,
                                   der_name: Optional[str] = None,
                                   interactive: bool = True) -> Path:
        """Helper to save a PEM file and optionally a DER file with overwrite checks.

        Returns the path of the written file (DER path if DER was written, else PEM path).
        Raises FileExistsError if overwrite is denied by the user (interactive) or interactive=False is respected.
        """
        path_pem = self.base / "own" / "certs" / pem_name

        if not self._check_overwrite(path_pem, interactive):
            raise FileExistsError(f"File {path_pem} exists and overwrite was denied")

        path_pem.write_bytes(pem_bytes)
        logger.info(f"Saved PEM: {path_pem}")

        if der_name and der_bytes is not None:
            path_der = self.base / "own" / "certs" / der_name
            if not self._check_overwrite(path_der, interactive):
                raise FileExistsError(f"File {path_der} exists and overwrite was denied")
            path_der.write_bytes(der_bytes)
            logger.info(f"Saved DER: {path_der}")
            return path_der

        return path_pem

    def save_private_key(self, key: rsa.RSAPrivateKey, filename: str, password: Optional[str] = None, interactive: bool = True) -> Path:
        path = self.base / "own" / "private" / filename

        if not self._check_overwrite(path, interactive):
            raise FileExistsError(f"Private key file {path} exists and overwrite was denied")

        enc = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            enc
        )
        path.write_bytes(pem)

        # Set secure permissions for private key (owner-only on POSIX)
        try:
            if os.name != "nt":  # Not Windows
                os.chmod(path, 0o600)
                logger.info(f"Set secure permissions (600) for private key: {path}")
        except Exception as e:
            logger.warning(f"Could not set secure permissions for {path}: {e}")

        logger.info(f"Private key saved: {path}")
        return path

    def save_certificate(self, cert: x509.Certificate, pem_name: str, der_name: Optional[str] = None, interactive: bool = True) -> Path:
        pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
        der_bytes = cert.public_bytes(serialization.Encoding.DER) if der_name else None
        return self._save_pem_and_optional_der(pem_bytes, pem_name, der_bytes, der_name, interactive)

    def save_csr(self, csr: x509.CertificateSigningRequest, pem_name: str, der_name: Optional[str] = None, interactive: bool = True) -> Path:
        pem_bytes = csr.public_bytes(serialization.Encoding.PEM)
        der_bytes = csr.public_bytes(serialization.Encoding.DER) if der_name else None
        return self._save_pem_and_optional_der(pem_bytes, pem_name, der_bytes, der_name, interactive)


class CertificateManager:
    def __init__(self, key_size: int = 2048):
        if key_size < 2048:
            raise ValueError("Key size must be >= 2048")
        if key_size > 4096:
            logger.warning("Key sizes > 4096 may not be supported by all S7-1500 PLCs")
        self.key_size = key_size

    def generate_key(self) -> rsa.RSAPrivateKey:
        logger.info(f"Generating {self.key_size}-bit RSA key...")
        return rsa.generate_private_key(public_exponent=65537, key_size=self.key_size)

    def build_subject(self, cn: str, org: str, country: str) -> x509.Name:
        attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
        if org:
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
        if country:
            attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
        return x509.Name(attrs)

    def create_self_signed(self, key, subject: x509.Name, san_list: List[x509.GeneralName], days: int = 365) -> x509.Certificate:
        # Use timezone-aware UTC datetime to avoid deprecated utcnow() usage
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = x509.CertificateBuilder()\
            .subject_name(subject)\
            .issuer_name(subject)\
            .public_key(key.public_key())\
            .serial_number(x509.random_serial_number())\
            .not_valid_before(now - datetime.timedelta(minutes=5))\
            .not_valid_after(now + datetime.timedelta(days=days))\
            .add_extension(x509.SubjectAlternativeName(san_list), critical=False)\
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)\
            .add_extension(x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ), critical=True)\
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)

        # Add Subject Key Identifier and Authority Key Identifier for better interoperability
        try:
            ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
            builder = builder.add_extension(ski, critical=False)
            aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key())
            builder = builder.add_extension(aki, critical=False)
            logger.info("Added Subject Key Identifier and Authority Key Identifier extensions")
        except Exception as e:
            logger.warning(f"Could not add SKI/AKI extensions: {e}")

        logger.info(f"Creating self-signed certificate valid for {days} days")
        return builder.sign(private_key=key, algorithm=hashes.SHA256())

    def create_csr(self, key, subject: x509.Name, san_list: List[x509.GeneralName]) -> x509.CertificateSigningRequest:
        builder = x509.CertificateSigningRequestBuilder().subject_name(subject)\
            .add_extension(x509.SubjectAlternativeName(san_list), critical=False)\
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)

        logger.info("Creating Certificate Signing Request")
        return builder.sign(key, hashes.SHA256())


def build_san_list(hostname: str, ip: str, app_uri: str, extra_dns: List[str] = None, extra_ip: List[str] = None) -> List[x509.GeneralName]:
    san_entries: List[x509.GeneralName] = []
    if hostname:
        san_entries.append(DNSName(hostname))
    if ip:
        try:
            san_entries.append(IPAddress(ipaddress.ip_address(ip)))
        except ValueError:
            logger.warning(f"Invalid IP '{ip}', skipped")
    if app_uri:
        san_entries.append(UniformResourceIdentifier(app_uri))
    if extra_dns:
        for d in extra_dns:
            san_entries.append(DNSName(d))
    if extra_ip:
        for i in extra_ip:
            try:
                san_entries.append(IPAddress(ipaddress.ip_address(i)))
            except ValueError:
                logger.warning(f"Invalid extra IP '{i}', skipped")
    return san_entries


class OPCUAWizard:
    def __init__(self):
        self.mode_completer = WordCompleter(["selfsigned", "csr"], ignore_case=True)
        self.yesno_completer = WordCompleter(["y", "n", "yes", "no"], ignore_case=True)
        self.file_mgr: Optional[FileManager] = None
        self.cert_mgr = CertificateManager()

    @staticmethod
    def prompt(q: str, default: str = None, completer=None) -> str:
        text = f"{q} " + (f"[{default}] " if default else "")
        ans = prompt(text, completer=completer)
        return ans.strip() if ans.strip() else (default or "")

    @staticmethod
    def detect_runtime():
        runtime = "native"
        try:
            with open("/proc/version", "r") as f:
                if "Microsoft" in f.read():
                    runtime = "wsl"
        except FileNotFoundError:
            pass
        if os.path.exists("/.dockerenv"):
            runtime = "docker"
        return runtime

    @staticmethod
    def detect_host_ip(runtime="native") -> Tuple[str, List[str]]:
        host = socket.gethostname()
        ip_list = []

        # Try IPv4 main interface
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip_list.append(s.getsockname()[0])
            s.close()
        except Exception:
            pass

        # Try IPv6 main interface
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.connect(("2001:4860:4860::8888", 80))  # Google's IPv6 DNS
            ipv6_addr = s.getsockname()[0]
            if not ipv6_addr.startswith("fe80:"):  # Skip link-local
                ip_list.append(ipv6_addr)
            s.close()
        except Exception:
            pass

        # Add loopback addresses
        ip_list.append("127.0.0.1")
        ip_list.append("::1")

        logger.info(f"Detected IP addresses: {ip_list}")
        return host, ip_list

    @staticmethod
    def validate_uri(uri: str) -> bool:
        """Basic URI validation for ApplicationUri."""
        if not uri:
            return False
        return uri.startswith(("urn:", "http://", "https://"))

    @staticmethod
    def prompt_password(question: str) -> str:
        """Prompt for password with hidden input if supported."""
        try:
            # Try to use hidden password input
            return prompt(f"{question}: ", is_password=True)
        except TypeError:
            # Fallback if is_password parameter not supported
            logger.warning("Password input will be visible (prompt_toolkit version doesn't support hidden input)")
            return prompt(f"{question}: ")

    def run(self):
        print("=== OPC UA Certificate Wizard (Runtime-aware SAN) ===")
        runtime = self.detect_runtime()
        print(f"[i] Detected runtime: {runtime}")

        base_path = Path(self.prompt("Base path for Siemens trustlist", default="./opcua_certs"))
        self.file_mgr = FileManager(base_path)
        self.file_mgr.make_structure()

        # Key size selection with S7-1500 compatibility warning
        key_size = int(self.prompt("RSA key size (2048/4096)", default="2048"))
        if key_size == 4096:
            print("[!] Warning: 4096-bit keys may not be supported by all S7-1500 PLCs. Verify compatibility.")
        self.cert_mgr = CertificateManager(key_size)

        mode = self.prompt("Certificate type? (selfsigned/csr)", default="selfsigned", completer=self.mode_completer).lower()
        host_name, ip_candidates = self.detect_host_ip(runtime)

        hostname = self.prompt("Hostname", default=host_name)
        ip_default = ",".join(ip_candidates)
        extra_ip_raw = self.prompt(f"Detected IPs (comma separated, edit if needed)", default=ip_default)
        extra_ip = [ip.strip() for ip in extra_ip_raw.split(",") if ip.strip()]

        # Determine primary IP for SAN (first valid IP from user input or detected)
        primary_ip = None
        if extra_ip:
            try:
                ipaddress.ip_address(extra_ip[0])
                primary_ip = extra_ip[0]
            except ValueError:
                logger.warning(f"First IP '{extra_ip[0]}' is invalid, will not be used as primary")

        if not primary_ip and ip_candidates:
            primary_ip = ip_candidates[0]

        logger.info(f"Using primary IP for SAN: {primary_ip}")

        app_uri = self.prompt("ApplicationUri (urn:hostname:app)", default=f"urn:{hostname}:MyOPCUAClient")

        # Validate URI
        if not self.validate_uri(app_uri):
            print("[!] Warning: ApplicationUri does not look like a valid URI; recommended to start with 'urn:'")

        cn = self.prompt("Common Name (CN)", default="MyOPCUAClient")
        org = self.prompt("Organization (O)", default="MyCompany")
        country = self.prompt("Country (C)", default="DE")
        days = int(self.prompt("Validity days", default="365"))

        # Extra DNS
        extra_dns_raw = self.prompt("Extra DNS entries (comma separated, optional)", default="localhost")
        extra_dns = [d.strip() for d in extra_dns_raw.split(",") if d.strip()]

        export_der = self.prompt("Export DER also? (y/n) [Recommended for S7-1500]", default="y", completer=self.yesno_completer).lower() in ("y", "yes")
        if export_der:
            print("[i] DER format is preferred for PLC import and filename conventions align with Siemens expectations")

        password = None
        if self.prompt("Encrypt private key? (y/n)", default="n", completer=self.yesno_completer).lower() in ("y", "yes"):
            password = self.prompt_password("Passphrase")

        key = self.cert_mgr.generate_key()
        subject = self.cert_mgr.build_subject(cn, org, country)

        # Include primary IP in SAN list
        san_list = build_san_list(hostname, primary_ip, app_uri, extra_dns, extra_ip)

        safe_name = "".join(c for c in cn if c.isalnum() or c in ("-", "_"))
        key_fname = f"{safe_name}_key.pem"
        cert_pem = f"{safe_name}.pem"
        cert_der = f"{safe_name}.der"
        csr_pem = f"{safe_name}.csr.pem"
        csr_der = f"{safe_name}.csr.der"

        self.file_mgr.save_private_key(key, key_fname, password=password)

        if mode == "selfsigned":
            cert = self.cert_mgr.create_self_signed(key, subject, san_list, days)
            self.file_mgr.save_certificate(cert, cert_pem, cert_der if export_der else None)
            trusted_copy = self.file_mgr.base / "trusted" / "certs" / cert_pem
            trusted_copy.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            logger.info(f"Certificate generated and copied to trusted store: {trusted_copy}")
            print(f"✓ Self-signed certificate created successfully")
            print(f"✓ Certificate files: {cert_pem}" + (f", {cert_der}" if export_der else ""))
        else:
            csr = self.cert_mgr.create_csr(key, subject, san_list)
            self.file_mgr.save_csr(csr, csr_pem, csr_der if export_der else None)
            logger.info("CSR generated successfully")
            print(f"✓ Certificate Signing Request created successfully")
            print(f"✓ CSR files: {csr_pem}" + (f", {csr_der}" if export_der else ""))

        print("\n=== Next Steps ===")
        print("• Upload client certificate to PLC trusted store via TIA Portal or Web UI")
        print("• Ensure PLC accepts the certificate format (DER recommended for S7-1500)")
        print("• Configure OPC UA client to use the generated private key and certificate")
        if primary_ip:
            print(f"• Verify PLC trusts connections from IP: {primary_ip}")

    def run_non_interactive(self, args):
        """Run in non-interactive mode using command line arguments."""
        logger.info("Running in non-interactive mode")

        self.file_mgr = FileManager(Path(args.output_dir))
        self.file_mgr.make_structure()

        self.cert_mgr = CertificateManager(args.key_size)

        # Use provided values or defaults
        hostname = args.hostname or socket.gethostname()
        primary_ip = args.primary_ip
        app_uri = args.app_uri or f"urn:{hostname}:MyOPCUAClient"

        if not self.validate_uri(app_uri):
            logger.warning("ApplicationUri does not look like a valid URI")

        subject = self.cert_mgr.build_subject(args.common_name, args.organization, args.country)
        extra_dns = args.extra_dns.split(",") if args.extra_dns else []
        extra_ip = args.extra_ip.split(",") if args.extra_ip else []

        san_list = build_san_list(hostname, primary_ip, app_uri, extra_dns, extra_ip)

        key = self.cert_mgr.generate_key()

        safe_name = "".join(c for c in args.common_name if c.isalnum() or c in ("-", "_"))
        key_fname = f"{safe_name}_key.pem"
        cert_pem = f"{safe_name}.pem"
        cert_der = f"{safe_name}.der"
        csr_pem = f"{safe_name}.csr.pem"
        csr_der = f"{safe_name}.csr.der"

        self.file_mgr.save_private_key(key, key_fname, password=args.password, interactive=False)

        if args.mode == "selfsigned":
            cert = self.cert_mgr.create_self_signed(key, subject, san_list, args.validity_days)
            self.file_mgr.save_certificate(cert, cert_pem, cert_der if args.export_der else None, interactive=False)
            trusted_copy = self.file_mgr.base / "trusted" / "certs" / cert_pem
            trusted_copy.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            logger.info("Self-signed certificate created successfully")
        else:
            csr = self.cert_mgr.create_csr(key, subject, san_list)
            self.file_mgr.save_csr(csr, csr_pem, csr_der if args.export_der else None, interactive=False)
            logger.info("CSR created successfully")


def parse_arguments():
    """Parse command line arguments for non-interactive mode."""
    parser = argparse.ArgumentParser(
        description="OPC UA Certificate Wizard - Generate certificates for secure S7-1500 PLC connections",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Interactive mode:
    python tui.py

  Non-interactive mode:
    python tui.py --non-interactive --common-name MyClient --primary-ip 192.168.1.100
    
  Generate 4096-bit certificate:
    python tui.py --non-interactive --key-size 4096 --common-name SecureClient
        """
    )

    parser.add_argument("--non-interactive", action="store_true",
                       help="Run in non-interactive mode using command line arguments")
    parser.add_argument("--output-dir", default="./opcua_certs",
                       help="Output directory for certificates (default: ./opcua_certs)")
    parser.add_argument("--mode", choices=["selfsigned", "csr"], default="selfsigned",
                       help="Certificate type (default: selfsigned)")
    parser.add_argument("--key-size", type=int, choices=[2048, 4096], default=2048,
                       help="RSA key size in bits (default: 2048)")
    parser.add_argument("--common-name", default="MyOPCUAClient",
                       help="Certificate Common Name (default: MyOPCUAClient)")
    parser.add_argument("--organization", default="MyCompany",
                       help="Organization name (default: MyCompany)")
    parser.add_argument("--country", default="DE",
                       help="Country code (default: DE)")
    parser.add_argument("--hostname",
                       help="Hostname for certificate (default: auto-detect)")
    parser.add_argument("--primary-ip",
                       help="Primary IP address to include in SAN")
    parser.add_argument("--extra-ip",
                       help="Additional IP addresses (comma-separated)")
    parser.add_argument("--extra-dns",
                       help="Additional DNS names (comma-separated)")
    parser.add_argument("--app-uri",
                       help="Application URI (default: urn:hostname:MyOPCUAClient)")
    parser.add_argument("--validity-days", type=int, default=365,
                       help="Certificate validity in days (default: 365)")
    parser.add_argument("--password",
                       help="Private key password (leave empty for no encryption)")
    parser.add_argument("--export-der", action="store_true", default=True,
                       help="Export DER format (default: enabled)")
    parser.add_argument("--verbose", action="store_true",
                       help="Enable verbose logging")

    return parser.parse_args()


if __name__ == "__main__":
    try:
        args = parse_arguments()

        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)

        wizard = OPCUAWizard()

        if args.non_interactive:
            wizard.run_non_interactive(args)
        else:
            wizard.run()

    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)
