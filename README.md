# Easy OPC UA Certificate Creator

A Python tool that simplifies generating OPC UA certificates and Certificate Signing Requests (CSRs) for secure industrial automation connections, particularly optimized for Siemens S7-1500 PLCs and other OPC UA devices.

## Features

- **Interactive & Non-Interactive Modes** - User-friendly TUI or command-line automation
- **Smart Runtime Detection** - Automatically detects WSL, Docker, or native environments
- **Automatic IP Discovery** - Detects and suggests network configuration for SAN entries
- **Siemens-Compatible Structure** - Creates trustlist folder structure following Siemens conventions
- **Multiple Certificate Formats** - Supports both PEM and DER formats (DER recommended for S7-1500)
- **Flexible Key Sizes** - 2048-bit (default) or 4096-bit RSA keys with PLC compatibility warnings
- **Security Best Practices** - Implements proper file permissions and cryptographic standards
- **Subject Alternative Names** - Comprehensive SAN support for IP addresses, DNS names, and application URIs

## Installation

### Using UV (Recommended)

```bash
# Clone the repository
git clone https://github.com/mberetvas/Easy-Opcua-Certificate-Creator.git
cd Easy-Opcua-Certificate-Creator

# Install using UV
uv sync
```

### Using pip

```bash
# Clone the repository
git clone https://github.com/mberetvas/Easy-Opcua-Certificate-Creator.git
cd Easy-Opcua-Certificate-Creator

# Install dependencies
pip install -r requirements.txt
```

### Requirements

- Python 3.12+
- cryptography >= 46.0.1
- prompt-toolkit >= 3.0.52

## Usage

### Interactive Mode

Run the tool interactively for guided certificate creation:

```bash
python src/opcua_certificate_tui.py
```

The wizard will guide you through:
1. Setting up the certificate directory structure
2. Choosing RSA key size (2048 or 4096 bits)
3. Selecting certificate type (self-signed or CSR)
4. Configuring certificate details (CN, organization, country)
5. Setting up Subject Alternative Names (SAN)
6. Choosing export formats (PEM/DER)

### Non-Interactive Mode

For automation or CI/CD pipelines:

```bash
# Basic self-signed certificate
python src/opcua_certificate_tui.py --non-interactive \
  --common-name "MyPLCClient" \
  --primary-ip "192.168.1.100" \
  --organization "MyCompany"

# Certificate Signing Request with custom parameters
python src/opcua_certificate_tui.py --non-interactive \
  --mode csr \
  --key-size 4096 \
  --common-name "ProductionLine01" \
  --primary-ip "10.0.1.50" \
  --extra-ip "10.0.1.51,10.0.1.52" \
  --extra-dns "plc1.local,plc1.company.com" \
  --validity-days 730
```

### Command Line Options

```
--non-interactive       Run without prompts using CLI arguments
--output-dir DIR        Output directory (default: ./opcua_certs)
--mode {selfsigned,csr} Certificate type (default: selfsigned)
--key-size {2048,4096}  RSA key size (default: 2048)
--common-name NAME      Certificate Common Name
--organization ORG      Organization name (default: MyCompany)
--country CODE          Country code (default: DE)
--hostname HOST         Hostname for certificate (auto-detected)
--primary-ip IP         Primary IP address for SAN
--extra-ip IPs          Additional IPs (comma-separated)
--extra-dns NAMES       Additional DNS names (comma-separated)
--app-uri URI           Application URI (default: urn:hostname:MyOPCUAClient)
--validity-days DAYS    Certificate validity period (default: 365)
--password PASS         Private key encryption password
--export-der            Export DER format (enabled by default)
--verbose               Enable detailed logging
```

## Certificate Structure

The tool creates a Siemens-compatible directory structure:

```
opcua_certs/
├── own/
│   ├── certs/          # Your certificates (PEM/DER)
│   └── private/        # Your private keys (PEM, secure permissions)
├── trusted/
│   ├── certs/          # Trusted certificates
│   └── crl/            # Certificate Revocation Lists
└── rejected/           # Rejected certificates
```

## Examples

### Basic PLC Connection Certificate

```bash
python src/opcua_certificate_tui.py --non-interactive \
  --common-name "HMI-Station-01" \
  --primary-ip "192.168.100.10" \
  --organization "Manufacturing Corp" \
  --country "US"
```

### High-Security Certificate with Multiple SANs

```bash
python src/opcua_certificate_tui.py --non-interactive \
  --key-size 4096 \
  --common-name "CriticalSystem" \
  --primary-ip "10.1.1.100" \
  --extra-ip "10.1.1.101,10.1.1.102" \
  --extra-dns "critical.internal,backup.internal" \
  --app-uri "urn:company:critical-system:v2" \
  --validity-days 1095 \
  --password "secure-key-password"
```

### CSR for External CA Signing

```bash
python src/opcua_certificate_tui.py --non-interactive \
  --mode csr \
  --common-name "SCADA-Gateway" \
  --organization "Industrial Solutions Inc" \
  --primary-ip "172.16.0.50"
```

## S7-1500 PLC Integration

> [!NOTE]
> **For Siemens S7-1500 PLCs**, DER format is recommended and enabled by default.

### Steps for PLC Setup:

1. **Generate Certificate**: Use this tool to create your client certificate
2. **Import to PLC**: Upload the DER certificate to PLC via TIA Portal or Web UI
3. **Configure Trust**: Add certificate to PLC's trusted certificate store
4. **Update Client**: Configure your OPC UA client with the generated private key and certificate

### Compatibility Notes:

- **2048-bit keys**: Universally supported by all S7-1500 firmware versions
- **4096-bit keys**: Supported by newer firmware; verify compatibility for your specific PLC model
- **DER format**: Preferred by Siemens PLCs for import operations
- **File naming**: Follows Siemens conventions for easy integration

## Runtime Detection

The tool automatically detects your environment:

- **Native**: Standard host environment
- **WSL**: Windows Subsystem for Linux
- **Docker**: Containerized environment

This ensures proper IP address detection and SAN configuration for your specific setup.

## Security Features

- **Secure Key Generation**: Uses cryptographically secure random number generation
- **File Permissions**: Automatically sets restrictive permissions (600) on private keys
- **Modern Standards**: Implements SHA-256 signatures and proper certificate extensions
- **Password Protection**: Optional private key encryption with user-provided passwords

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Maxime Beretvas** - [GitHub Profile](https://github.com/mberetvas)

---

> **Tip**: For production environments, consider using CSR mode with your organization's Certificate Authority for enhanced security and compliance.