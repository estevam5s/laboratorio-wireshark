import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import plotly.express as px
import plotly.graph_objects as go
import base64
import os
import subprocess
import shutil
import time
import json
from PIL import Image
import requests
from io import BytesIO
import pyshark
from scapy.all import rdpcap, PacketList
import hashlib
import re
from datetime import datetime

# Configuração inicial da página
st.set_page_config(
    page_title="CyberLab Wireshark",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Estilos CSS personalizados
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #0066cc;
        text-align: center;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.8rem;
        color: #004d99;
        margin-top: 2rem;
        margin-bottom: 1rem;
    }
    .highlight {
        background-color: #f0f8ff;
        padding: 1rem;
        border-radius: 5px;
        border-left: 5px solid #0066cc;
    }
    .code-block {
        background-color: #f5f5f5;
        padding: 1rem;
        border-radius: 5px;
        font-family: monospace;
    }
    .success-box {
        background-color: #d4edda;
        color: #155724;
        padding: 1rem;
        border-radius: 5px;
        border-left: 5px solid #155724;
    }
    .warning-box {
        background-color: #fff3cd;
        color: #856404;
        padding: 1rem;
        border-radius: 5px;
        border-left: 5px solid #856404;
    }
    .danger-box {
        background-color: #f8d7da;
        color: #721c24;
        padding: 1rem;
        border-radius: 5px;
        border-left: 5px solid #721c24;
    }
    .terminal {
        background-color: #000;
        color: #00ff00;
        padding: 1rem;
        border-radius: 5px;
        font-family: monospace;
    }
    .challenge-card {
        background-color: #e6f7ff;
        padding: 1.5rem;
        border-radius: 10px;
        margin-bottom: 1rem;
        border: 1px solid #91d5ff;
    }
    .sidebar .sidebar-content {
        background-color: #f8f9fa;
    }
    .packet-row {
        cursor: pointer;
        transition: background-color 0.2s;
    }
    .packet-row:hover {
        background-color: #e6f7ff;
    }
    .packet-details {
        font-family: monospace;
        white-space: pre-wrap;
        background-color: #f5f5f5;
        padding: 10px;
        border-radius: 5px;
    }
    .nav-link {
        text-decoration: none;
        color: #0066cc;
        font-weight: bold;
        padding: 0.5rem;
        margin: 0.2rem;
        border-radius: 5px;
    }
    .nav-link:hover {
        background-color: #e6f7ff;
    }
    .progress-container {
        margin-top: 1rem;
        margin-bottom: 1rem;
    }
    .footer {
        text-align: center;
        margin-top: 3rem;
        padding: 1rem;
        background-color: #f8f9fa;
        border-radius: 5px;
    }
</style>
""", unsafe_allow_html=True)

# Função para converter arquivos PCAP para DataFrame
def pcap_to_dataframe(pcap_file):
    try:
        # Verifica se o arquivo existe
        if not os.path.isfile(pcap_file):
            return None
        
        # Usa pyshark para ler o arquivo PCAP
        cap = pyshark.FileCapture(pcap_file)
        
        # Inicializa listas para armazenar dados
        packets = []
        
        # Processa cada pacote
        for i, packet in enumerate(cap):
            try:
                # Obtém a camada mais alta do pacote
                highest_layer = packet.highest_layer if hasattr(packet, 'highest_layer') else 'Unknown'
                
                # Informações básicas do pacote
                packet_info = {
                    'No.': i + 1,
                    'Time': float(packet.sniff_time.timestamp()) if hasattr(packet, 'sniff_time') else 0,
                    'Source': packet.ip.src if hasattr(packet, 'ip') else 'Unknown',
                    'Destination': packet.ip.dst if hasattr(packet, 'ip') else 'Unknown',
                    'Protocol': highest_layer,
                    'Length': int(packet.length) if hasattr(packet, 'length') else 0,
                    'Info': get_packet_info(packet),
                    'Raw': str(packet)
                }
                
                # Adiciona à lista de pacotes
                packets.append(packet_info)
            except AttributeError as e:
                # Ignora pacotes que não podem ser processados
                continue
        
        # Cria um DataFrame com os dados
        df = pd.DataFrame(packets)
        
        # Converte a coluna Time para datetime
        if 'Time' in df.columns and not df.empty:
            df['Time'] = pd.to_datetime(df['Time'], unit='s')
        
        return df
    
    except Exception as e:
        st.error(f"Erro ao processar o arquivo PCAP: {str(e)}")
        return None

# Função para extrair informações relevantes de um pacote
def get_packet_info(packet):
    info = ""
    
    try:
        # Para pacotes HTTP
        if hasattr(packet, 'http'):
            if hasattr(packet.http, 'request_method'):
                info = f"{packet.http.request_method} {packet.http.request_uri}"
            elif hasattr(packet.http, 'response_code'):
                info = f"HTTP {packet.http.response_code} {packet.http.response_phrase}"
        
        # Para pacotes TCP
        elif hasattr(packet, 'tcp'):
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport
            flags = []
            
            if hasattr(packet.tcp, 'flags_syn') and int(packet.tcp.flags_syn) == 1:
                flags.append('SYN')
            if hasattr(packet.tcp, 'flags_ack') and int(packet.tcp.flags_ack) == 1:
                flags.append('ACK')
            if hasattr(packet.tcp, 'flags_fin') and int(packet.tcp.flags_fin) == 1:
                flags.append('FIN')
            if hasattr(packet.tcp, 'flags_rst') and int(packet.tcp.flags_rst) == 1:
                flags.append('RST')
            
            flags_str = ' '.join(flags)
            info = f"{src_port} → {dst_port} {flags_str}"
        
        # Para pacotes UDP
        elif hasattr(packet, 'udp'):
            src_port = packet.udp.srcport
            dst_port = packet.udp.dstport
            info = f"{src_port} → {dst_port}"
        
        # Para pacotes DNS
        elif hasattr(packet, 'dns'):
            if hasattr(packet.dns, 'qry_name'):
                info = f"Query: {packet.dns.qry_name}"
            elif hasattr(packet.dns, 'resp_name'):
                info = f"Response: {packet.dns.resp_name}"
        
        # Para pacotes ICMP
        elif hasattr(packet, 'icmp'):
            if hasattr(packet.icmp, 'type'):
                icmp_type = packet.icmp.type
                if icmp_type == '8':
                    info = "Echo (ping) request"
                elif icmp_type == '0':
                    info = "Echo (ping) reply"
                else:
                    info = f"Type: {icmp_type}"
        
        # Se não houver informações específicas, use a camada de transporte
        if not info and hasattr(packet, 'transport_layer'):
            info = f"{packet.transport_layer} packet"
    
    except Exception as e:
        info = "Error parsing packet"
    
    return info if info else "No detailed info"

# Função para simular a captura de pacotes
def simulate_packet_capture(protocol_type="http", duration=10):
    protocols = {
        "http": generate_http_traffic,
        "dns": generate_dns_traffic,
        "tcp": generate_tcp_traffic,
        "icmp": generate_icmp_traffic,
        "https": generate_https_traffic,
        "mixed": generate_mixed_traffic
    }
    
    generator_func = protocols.get(protocol_type.lower(), generate_mixed_traffic)
    
    return generator_func(duration)

# Geradores de tráfego simulado para diferentes protocolos
def generate_http_traffic(duration):
    num_packets = duration * 5  # 5 pacotes por segundo
    
    current_time = datetime.now()
    packets = []
    
    # IPs simulados
    client_ip = "192.168.1.100"
    server_ip = "203.0.113.10"
    
    # Métodos HTTP e URIs
    methods = ["GET", "POST", "PUT", "DELETE"]
    uris = ["/index.html", "/api/users", "/login", "/images/logo.png", "/css/style.css"]
    
    # Status codes
    status_codes = ["200 OK", "404 Not Found", "500 Internal Server Error", "302 Found", "401 Unauthorized"]
    
    for i in range(num_packets):
        if i % 2 == 0:  # Requisição
            method = np.random.choice(methods)
            uri = np.random.choice(uris)
            
            packet = {
                'No.': i + 1,
                'Time': current_time + pd.Timedelta(seconds=i/5),
                'Source': client_ip,
                'Destination': server_ip,
                'Protocol': 'HTTP',
                'Length': np.random.randint(100, 1500),
                'Info': f"{method} {uri} HTTP/1.1",
                'Raw': f"HTTP Request\nMethod: {method}\nURI: {uri}\nHost: example.com\nUser-Agent: Mozilla/5.0"
            }
        else:  # Resposta
            status = np.random.choice(status_codes)
            
            packet = {
                'No.': i + 1,
                'Time': current_time + pd.Timedelta(seconds=i/5 + 0.1),
                'Source': server_ip,
                'Destination': client_ip,
                'Protocol': 'HTTP',
                'Length': np.random.randint(200, 5000),
                'Info': f"HTTP/1.1 {status}",
                'Raw': f"HTTP Response\nStatus: {status}\nContent-Type: text/html\nContent-Length: 1024"
            }
        
        packets.append(packet)
    
    return pd.DataFrame(packets)

def generate_dns_traffic(duration):
    num_packets = duration * 3  # 3 pacotes por segundo
    
    current_time = datetime.now()
    packets = []
    
    # IPs simulados
    client_ip = "192.168.1.100"
    dns_server = "8.8.8.8"
    
    # Domínios para consulta
    domains = ["example.com", "google.com", "facebook.com", "amazon.com", "microsoft.com"]
    
    for i in range(num_packets):
        domain = np.random.choice(domains)
        
        if i % 2 == 0:  # Query
            packet = {
                'No.': i + 1,
                'Time': current_time + pd.Timedelta(seconds=i/3),
                'Source': client_ip,
                'Destination': dns_server,
                'Protocol': 'DNS',
                'Length': np.random.randint(60, 100),
                'Info': f"Query: {domain}",
                'Raw': f"DNS Query\nTransaction ID: 0x{np.random.randint(0, 65535):04x}\nQueries: {domain}"
            }
        else:  # Response
            packet = {
                'No.': i + 1,
                'Time': current_time + pd.Timedelta(seconds=i/3 + 0.05),
                'Source': dns_server,
                'Destination': client_ip,
                'Protocol': 'DNS',
                'Length': np.random.randint(100, 300),
                'Info': f"Response: {domain}",
                'Raw': f"DNS Response\nTransaction ID: 0x{np.random.randint(0, 65535):04x}\nQueries: {domain}\nAnswers: {domain} IN A {'.'.join(str(np.random.randint(0, 255)) for _ in range(4))}"
            }
        
        packets.append(packet)
    
    return pd.DataFrame(packets)

def generate_tcp_traffic(duration):
    num_packets = duration * 8  # 8 pacotes por segundo
    
    current_time = datetime.now()
    packets = []
    
    # IPs e portas simulados
    client_ip = "192.168.1.100"
    server_ip = "203.0.113.10"
    client_port = np.random.randint(49152, 65535)
    server_port = 80
    
    # Flag combinações para simulação de three-way handshake e outras interações TCP
    connections = []
    
    for i in range(num_packets):
        # A cada 10 pacotes, inicia uma nova conexão
        if i % 10 == 0:
            client_port = np.random.randint(49152, 65535)
            connections.append((client_port, server_port))
        
        # Escolhe uma conexão para o pacote atual
        client_port, server_port = np.random.choice(connections)
        
        # Decide o tipo de pacote
        packet_type = np.random.choice(["handshake", "data", "fin"])
        
        if packet_type == "handshake":
            # Simula um Three-Way Handshake
            handshake_step = np.random.randint(1, 4)
            
            if handshake_step == 1:  # SYN
                packet = {
                    'No.': i + 1,
                    'Time': current_time + pd.Timedelta(seconds=i/8),
                    'Source': client_ip,
                    'Destination': server_ip,
                    'Protocol': 'TCP',
                    'Length': 74,
                    'Info': f"{client_port} → {server_port} [SYN] Seq=0 Win=64240",
                    'Raw': f"TCP Packet\nSource Port: {client_port}\nDestination Port: {server_port}\nFlags: SYN\nSequence Number: 0\nWindow Size: 64240"
                }
            elif handshake_step == 2:  # SYN-ACK
                packet = {
                    'No.': i + 1,
                    'Time': current_time + pd.Timedelta(seconds=i/8),
                    'Source': server_ip,
                    'Destination': client_ip,
                    'Protocol': 'TCP',
                    'Length': 74,
                    'Info': f"{server_port} → {client_port} [SYN, ACK] Seq=0 Ack=1 Win=65535",
                    'Raw': f"TCP Packet\nSource Port: {server_port}\nDestination Port: {client_port}\nFlags: SYN, ACK\nSequence Number: 0\nAcknowledgment Number: 1\nWindow Size: 65535"
                }
            else:  # ACK
                packet = {
                    'No.': i + 1,
                    'Time': current_time + pd.Timedelta(seconds=i/8),
                    'Source': client_ip,
                    'Destination': server_ip,
                    'Protocol': 'TCP',
                    'Length': 66,
                    'Info': f"{client_port} → {server_port} [ACK] Seq=1 Ack=1 Win=64240",
                    'Raw': f"TCP Packet\nSource Port: {client_port}\nDestination Port: {server_port}\nFlags: ACK\nSequence Number: 1\nAcknowledgment Number: 1\nWindow Size: 64240"
                }
        
        elif packet_type == "data":
            # Simula transferência de dados
            direction = np.random.choice(["client_to_server", "server_to_client"])
            
            if direction == "client_to_server":
                packet = {
                    'No.': i + 1,
                    'Time': current_time + pd.Timedelta(seconds=i/8),
                    'Source': client_ip,
                    'Destination': server_ip,
                    'Protocol': 'TCP',
                    'Length': np.random.randint(100, 1500),
                    'Info': f"{client_port} → {server_port} [PSH, ACK] Seq={np.random.randint(1, 10000)} Ack={np.random.randint(1, 10000)} Len={np.random.randint(100, 1000)}",
                    'Raw': f"TCP Packet\nSource Port: {client_port}\nDestination Port: {server_port}\nFlags: PSH, ACK\nSequence Number: {np.random.randint(1, 10000)}\nAcknowledgment Number: {np.random.randint(1, 10000)}\nLength: {np.random.randint(100, 1000)}"
                }
            else:
                packet = {
                    'No.': i + 1,
                    'Time': current_time + pd.Timedelta(seconds=i/8),
                    'Source': server_ip,
                    'Destination': client_ip,
                    'Protocol': 'TCP',
                    'Length': np.random.randint(100, 1500),
                    'Info': f"{server_port} → {client_port} [PSH, ACK] Seq={np.random.randint(1, 10000)} Ack={np.random.randint(1, 10000)} Len={np.random.randint(100, 1000)}",
                    'Raw': f"TCP Packet\nSource Port: {server_port}\nDestination Port: {client_port}\nFlags: PSH, ACK\nSequence Number: {np.random.randint(1, 10000)}\nAcknowledgment Number: {np.random.randint(1, 10000)}\nLength: {np.random.randint(100, 1000)}"
                }
        
        else:  # fin
            # Simula encerramento de conexão
            fin_step = np.random.randint(1, 5)
            
            if fin_step == 1:  # FIN from client
                packet = {
                    'No.': i + 1,
                    'Time': current_time + pd.Timedelta(seconds=i/8),
                    'Source': client_ip,
                    'Destination': server_ip,
                    'Protocol': 'TCP',
                    'Length': 66,
                    'Info': f"{client_port} → {server_port} [FIN, ACK] Seq={np.random.randint(1, 10000)} Ack={np.random.randint(1, 10000)}",
                    'Raw': f"TCP Packet\nSource Port: {client_port}\nDestination Port: {server_port}\nFlags: FIN, ACK\nSequence Number: {np.random.randint(1, 10000)}\nAcknowledgment Number: {np.random.randint(1, 10000)}"
                }
            elif fin_step == 2:  # ACK from server
                packet = {
                    'No.': i + 1,
                    'Time': current_time + pd.Timedelta(seconds=i/8),
                    'Source': server_ip,
                    'Destination': client_ip,
                    'Protocol': 'TCP',
                    'Length': 66,
                    'Info': f"{server_port} → {client_port} [ACK] Seq={np.random.randint(1, 10000)} Ack={np.random.randint(1, 10000)}",
                    'Raw': f"TCP Packet\nSource Port: {server_port}\nDestination Port: {client_port}\nFlags: ACK\nSequence Number: {np.random.randint(1, 10000)}\nAcknowledgment Number: {np.random.randint(1, 10000)}"
                }
            elif fin_step == 3:  # FIN from server
                packet = {
                    'No.': i + 1,
                    'Time': current_time + pd.Timedelta(seconds=i/8),
                    'Source': server_ip,
                    'Destination': client_ip,
                    'Protocol': 'TCP',
                    'Length': 66,
                    'Info': f"{server_port} → {client_port} [FIN, ACK] Seq={np.random.randint(1, 10000)} Ack={np.random.randint(1, 10000)}",
                    'Raw': f"TCP Packet\nSource Port: {server_port}\nDestination Port: {client_port}\nFlags: FIN, ACK\nSequence Number: {np.random.randint(1, 10000)}\nAcknowledgment Number: {np.random.randint(1, 10000)}"
                }
            else:  # ACK from client
                packet = {
                    'No.': i + 1,
                    'Time': current_time + pd.Timedelta(seconds=i/8),
                    'Source': client_ip,
                    'Destination': server_ip,
                    'Protocol': 'TCP',
                    'Length': 66,
                    'Info': f"{client_port} → {server_port} [ACK] Seq={np.random.randint(1, 10000)} Ack={np.random.randint(1, 10000)}",
                    'Raw': f"TCP Packet\nSource Port: {client_port}\nDestination Port: {server_port}\nFlags: ACK\nSequence Number: {np.random.randint(1, 10000)}\nAcknowledgment Number: {np.random.randint(1, 10000)}"
                }
        
        packets.append(packet)
    
    return pd.DataFrame(packets)

def generate_icmp_traffic(duration):
    num_packets = duration * 2  # 2 pacotes por segundo
    
    current_time = datetime.now()
    packets = []
    
    # IPs simulados
    source_ip = "192.168.1.100"
    destination_ip = "8.8.8.8"
    
    for i in range(num_packets):
        # Alterna entre requisição e resposta
        if i % 2 == 0:  # Echo request
            packet = {
                'No.': i + 1,
                'Time': current_time + pd.Timedelta(seconds=i/2),
                'Source': source_ip,
                'Destination': destination_ip,
                'Protocol': 'ICMP',
                'Length': 98,
                'Info': f"Echo (ping) request, id={np.random.randint(1, 65535)}, seq={i//2}",
                'Raw': f"ICMP Packet\nType: 8 (Echo Request)\nCode: 0\nIdentifier: {np.random.randint(1, 65535)}\nSequence Number: {i//2}\nData: abcdefghijklmnopqrstuvwxyz"
            }
        else:  # Echo reply
            packet = {
                'No.': i + 1,
                'Time': current_time + pd.Timedelta(seconds=i/2 + 0.1),
                'Source': destination_ip,
                'Destination': source_ip,
                'Protocol': 'ICMP',
                'Length': 98,
                'Info': f"Echo (ping) reply, id={np.random.randint(1, 65535)}, seq={(i-1)//2}",
                'Raw': f"ICMP Packet\nType: 0 (Echo Reply)\nCode: 0\nIdentifier: {np.random.randint(1, 65535)}\nSequence Number: {(i-1)//2}\nData: abcdefghijklmnopqrstuvwxyz"
            }
        
        packets.append(packet)
    
    return pd.DataFrame(packets)

def generate_https_traffic(duration):
    num_packets = duration * 5  # 5 pacotes por segundo
    
    current_time = datetime.now()
    packets = []
    
    # IPs simulados
    client_ip = "192.168.1.100"
    server_ip = "203.0.113.10"
    client_port = np.random.randint(49152, 65535)
    server_port = 443
    
    # Estágios do TLS handshake
    tls_stages = [
        "Client Hello",
        "Server Hello",
        "Certificate",
        "Server Key Exchange",
        "Server Hello Done",
        "Client Key Exchange",
        "Change Cipher Spec (Client)",
        "Encrypted Handshake Message (Client)",
        "Change Cipher Spec (Server)",
        "Encrypted Handshake Message (Server)",
        "Application Data"
    ]
    
    # Índice inicial para o estágio TLS
    tls_index = 0
    
    for i in range(num_packets):
        # A cada 10 pacotes, reinicia uma nova sessão TLS
        if i % 10 == 0:
            client_port = np.random.randint(49152, 65535)
            tls_index = 0
        
        # Obtém o estágio TLS atual (com alguma variação)
        current_stage = tls_stages[min(tls_index, len(tls_stages) - 1)]
        tls_index = min(tls_index + np.random.randint(0, 2), len(tls_stages) - 1)
        
        # Determina a direção do pacote
        if current_stage in ["Client Hello", "Client Key Exchange", "Change Cipher Spec (Client)", "Encrypted Handshake Message (Client)"]:
            src_ip = client_ip
            dst_ip = server_ip
            src_port = client_port
            dst_port = server_port
        else:
            src_ip = server_ip
            dst_ip = client_ip
            src_port = server_port
            dst_port = client_port
        
        # Para pacotes de dados da aplicação, alterna direção
        if current_stage == "Application Data":
            if np.random.random() < 0.5:
                src_ip, dst_ip = dst_ip, src_ip
                src_port, dst_port = dst_port, src_port
        
        # Tamanho do pacote com base no estágio
        if current_stage == "Certificate":
            length = np.random.randint(1000, 5000)
        elif current_stage == "Application Data":
            length = np.random.randint(100, 3000)
        else:
            length = np.random.randint(100, 500)
        
        packet = {
            'No.': i + 1,
            'Time': current_time + pd.Timedelta(seconds=i/5),
            'Source': src_ip,
            'Destination': dst_ip,
            'Protocol': 'TLSv1.2' if np.random.random() < 0.7 else 'TLSv1.3',
            'Length': length,
            'Info': f"{src_port} → {dst_port} {current_stage}",
            'Raw': f"TLS Packet\nSource Port: {src_port}\nDestination Port: {dst_port}\nContent Type: {current_stage}\nVersion: TLS {'1.2' if np.random.random() < 0.7 else '1.3'}\nLength: {length}"
        }
        
        packets.append(packet)
    
    return pd.DataFrame(packets)

def generate_mixed_traffic(duration):
    # Combina diferentes tipos de tráfego
    num_http = int(duration * 2)
    num_dns = int(duration * 1)
    num_tcp = int(duration * 3)
    num_icmp = int(duration * 0.5)
    num_https = int(duration * 2)
    
    http_df = generate_http_traffic(num_http)
    dns_df = generate_dns_traffic(num_dns)
    tcp_df = generate_tcp_traffic(num_tcp)
    icmp_df = generate_icmp_traffic(num_icmp)
    https_df = generate_https_traffic(num_https)
    
    # Combina todos os DataFrames
    combined_df = pd.concat([http_df, dns_df, tcp_df, icmp_df, https_df], ignore_index=True)
    
    # Ordena por tempo
    combined_df = combined_df.sort_values('Time').reset_index(drop=True)
    
    # Atualiza o número sequencial
    combined_df['No.'] = np.arange(1, len(combined_df) + 1)
    
    return combined_df

# Função para extrair estatísticas dos pacotes
def extract_packet_statistics(df):
    if df is None or df.empty:
        return {
            "total_packets": 0,
            "protocols": {},
            "ip_sources": {},
            "ip_destinations": {},
            "avg_packet_size": 0,
            "time_range": {"start": None, "end": None},
            "packet_rate": 0
        }
    
    # Total de pacotes
    total_packets = len(df)
    
    # Contagem de protocolos
    protocol_counts = df['Protocol'].value_counts().to_dict()
    
    # Contagem de IPs fonte
    ip_source_counts = df['Source'].value_counts().to_dict()
    
    # Contagem de IPs destino
    ip_dest_counts = df['Destination'].value_counts().to_dict()
    
    # Tamanho médio dos pacotes
    avg_packet_size = df['Length'].mean()
    
    # Intervalo de tempo (primeiro e último pacote)
    if 'Time' in df.columns:
        time_range = {
            "start": df['Time'].min(),
            "end": df['Time'].max()
        }
        
        # Pacotes por segundo
        time_diff = (time_range["end"] - time_range["start"]).total_seconds()
        packet_rate = total_packets / time_diff if time_diff > 0 else 0
    else:
        time_range = {"start": None, "end": None}
        packet_rate = 0
    
    return {
        "total_packets": total_packets,
        "protocols": protocol_counts,
        "ip_sources": ip_source_counts,
        "ip_destinations": ip_dest_counts,
        "avg_packet_size": avg_packet_size,
        "time_range": time_range,
        "packet_rate": packet_rate
    }

# Função para aplicar filtros a um DataFrame de pacotes
def apply_filters(df, filters):
    if df is None or df.empty:
        return df
    
    filtered_df = df.copy()
    
    # Filtro por protocolo
    if filters.get('protocol'):
        filtered_df = filtered_df[filtered_df['Protocol'] == filters['protocol']]
    
    # Filtro por IP de origem
    if filters.get('source_ip'):
        filtered_df = filtered_df[filtered_df['Source'].str.contains(filters['source_ip'], regex=False)]
    
    # Filtro por IP de destino
    if filters.get('dest_ip'):
        filtered_df = filtered_df[filtered_df['Destination'].str.contains(filters['dest_ip'], regex=False)]
    
    # Filtro por conteúdo (texto em qualquer coluna)
    if filters.get('content'):
        content_filter = filters['content'].lower()
        mask = filtered_df.apply(lambda row: any(content_filter in str(val).lower() for val in row), axis=1)
        filtered_df = filtered_df[mask]
    
    # Filtro por tamanho mínimo de pacote
    if filters.get('min_length') is not None:
        filtered_df = filtered_df[filtered_df['Length'] >= filters['min_length']]
    
    # Filtro por tamanho máximo de pacote
    if filters.get('max_length') is not None:
        filtered_df = filtered_df[filtered_df['Length'] <= filters['max_length']]
    
    return filtered_df

# Função para detectar padrões de tráfego suspeito
def detect_suspicious_patterns(df):
    if df is None or df.empty:
        return []
    
    suspicious_activities = []
    
    # 1. Detectar possível port scanning (muitas conexões para portas diferentes de um mesmo IP)
    if 'Info' in df.columns:
        # Filtramos pacotes TCP/UDP para análise
        tcp_packets = df[df['Protocol'].isin(['TCP', 'UDP'])]
        
        # Extraímos origem, destino e informações de porta (simplificado)
        src_to_dst_ports = {}
        
        for idx, row in tcp_packets.iterrows():
            src = row['Source']
            dst = row['Destination']
            
            # Tentamos extrair informações de porta da coluna Info
            port_info = re.search(r'(\d+)\s*→\s*(\d+)', row['Info'])
            
            if port_info:
                src_port = int(port_info.group(1))
                dst_port = int(port_info.group(2))
                
                # Registramos a combinação IP fonte -> porta destino
                if src not in src_to_dst_ports:
                    src_to_dst_ports[src] = set()
                
                src_to_dst_ports[src].add(dst_port)
        
        # Verificamos se algum IP fonte se conectou a muitas portas diferentes
        port_scan_threshold = 15  # Limite arbitrário
        for src, ports in src_to_dst_ports.items():
            if len(ports) > port_scan_threshold:
                suspicious_activities.append({
                    'type': 'Port Scanning',
                    'source': src,
                    'details': f"Possível port scanning: {src} se conectou a {len(ports)} portas diferentes",
                    'severity': 'high'
                })
    
    # 2. Detectar flood de pacotes (muitos pacotes em um curto período de tempo)
    if 'Time' in df.columns:
        # Agrupamos por segundo e contamos pacotes
        df['TimeSecond'] = df['Time'].dt.floor('S')
        packets_per_second = df.groupby('TimeSecond').size()
        
        # Se tiver mais de X pacotes por segundo, pode ser flood
        flood_threshold = 100  # Limite arbitrário
        flood_seconds = packets_per_second[packets_per_second > flood_threshold]
        
        if not flood_seconds.empty:
            for time, count in flood_seconds.items():
                # Identificamos os IPs fonte mais comuns naquele segundo
                packets_in_second = df[df['TimeSecond'] == time]
                top_sources = packets_in_second['Source'].value_counts().head(3)
                
                sources_str = ", ".join([f"{ip} ({count} pacotes)" for ip, count in top_sources.items()])
                
                suspicious_activities.append({
                    'type': 'Packet Flood',
                    'time': time,
                    'details': f"Possível flood: {count} pacotes em 1 segundo. Principais fontes: {sources_str}",
                    'severity': 'medium'
                })
    
    # 3. Detectar tentativas de brute force (muitas conexões TCP falhas)
    if 'Info' in df.columns and 'Protocol' in df.columns:
        tcp_resets = df[(df['Protocol'] == 'TCP') & (df['Info'].str.contains('RST'))]
        
        # Agrupamos resets por combinação de origem e destino
        reset_counts = tcp_resets.groupby(['Source', 'Destination']).size()
        
        # Se tiver muitos resets para a mesma combinação, pode ser brute force
        brute_force_threshold = 10  # Limite arbitrário
        potential_brute_force = reset_counts[reset_counts > brute_force_threshold]
        
        if not potential_brute_force.empty:
            for (src, dst), count in potential_brute_force.items():
                suspicious_activities.append({
                    'type': 'Brute Force',
                    'source': src,
                    'destination': dst,
                    'details': f"Possível brute force: {count} conexões TCP resetadas entre {src} e {dst}",
                    'severity': 'high'
                })
    
    # 4. Detectar possíveis exfiltrações de dados (pacotes grandes para fora da rede)
    internal_networks = ['192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']
    
    outbound_packets = df.copy()
    
    # Filtramos pacotes que vão de rede interna para externa
    for idx, row in df.iterrows():
        src = row['Source']
        dst = row['Destination']
        
        src_is_internal = any(src.startswith(prefix) for prefix in internal_networks)
        dst_is_internal = any(dst.startswith(prefix) for prefix in internal_networks)
        
        if not (src_is_internal and not dst_is_internal):
            outbound_packets = outbound_packets.drop(idx)
    
    # Verificamos pacotes grandes saindo da rede
    large_packet_threshold = 1500  # Limite arbitrário em bytes
    large_outbound = outbound_packets[outbound_packets['Length'] > large_packet_threshold]
    
    if not large_outbound.empty:
        # Agrupamos por IP fonte
        large_by_source = large_outbound.groupby('Source')['Length'].sum()
        
        for src, total_size in large_by_source.items():
            if total_size > 50000:  # Limite arbitrário de volume total
                suspicious_activities.append({
                    'type': 'Data Exfiltration',
                    'source': src,
                    'details': f"Possível exfiltração de dados: {src} enviou {total_size/1024:.2f} KB para fora da rede",
                    'severity': 'high'
                })
    
    return suspicious_activities

# Função para extrair detalhes avançados de pacotes
def extract_advanced_packet_details(raw_packet):
    details = {}
    
    try:
        # Dividimos o pacote bruto por linhas
        lines = raw_packet.split('\n')
        
        # Processamos cada linha
        current_section = "General"
        details[current_section] = {}
        
        for line in lines:
            line = line.strip()
            
            # Se a linha estiver vazia, continuamos
            if not line:
                continue
            
            # Verificamos se é um novo cabeçalho de seção
            if line.endswith('Packet') or line.endswith('Header') or any(proto in line for proto in ['TCP', 'UDP', 'HTTP', 'DNS', 'ICMP', 'TLS', 'SSL']):
                current_section = line.strip(':')
                details[current_section] = {}
                continue
            
            # Procuramos pelo formato "chave: valor"
            parts = line.split(':', 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()
                details[current_section][key] = value
    
    except Exception as e:
        details["Error"] = str(e)
    
    return details

# Função para gerar relatório de análise
def generate_analysis_report(df, statistics, suspicious_activities):
    report = {}
    
    # Resumo geral
    report["summary"] = {
        "total_packets": statistics["total_packets"],
        "time_period": f"{statistics['time_range']['start']} até {statistics['time_range']['end']}" if statistics['time_range']['start'] else "N/A",
        "packet_rate": f"{statistics['packet_rate']:.2f} pacotes/segundo",
        "avg_packet_size": f"{statistics['avg_packet_size']:.2f} bytes",
        "protocol_distribution": statistics["protocols"],
    }
    
    # TOP IPs
    report["top_ips"] = {
        "sources": dict(sorted(statistics["ip_sources"].items(), key=lambda x: x[1], reverse=True)[:10]),
        "destinations": dict(sorted(statistics["ip_destinations"].items(), key=lambda x: x[1], reverse=True)[:10]),
    }
    
    # Fluxos de comunicação mais relevantes
    if not df.empty:
        flows = df.groupby(['Source', 'Destination']).size().reset_index(name='count')
        flows = flows.sort_values('count', ascending=False).head(10)
        
        report["top_flows"] = []
        for _, row in flows.iterrows():
            report["top_flows"].append({
                "source": row['Source'],
                "destination": row['Destination'],
                "packet_count": row['count'],
            })
    else:
        report["top_flows"] = []
    
    # Atividades suspeitas
    report["suspicious_activities"] = suspicious_activities
    
    # Recomendações (com base nas atividades suspeitas)
    report["recommendations"] = []
    
    for activity in suspicious_activities:
        if activity['type'] == 'Port Scanning':
            report["recommendations"].append({
                "title": "Implementar proteção contra port scanning",
                "description": "Configure seu firewall para limitar tentativas de conexão de um único IP em um curto período.",
                "severity": "high"
            })
        elif activity['type'] == 'Packet Flood':
            report["recommendations"].append({
                "title": "Configurar proteção contra DDoS",
                "description": "Implemente rate limiting e considere serviços de mitigação de DDoS para proteger contra floods.",
                "severity": "medium"
            })
        elif activity['type'] == 'Brute Force':
            report["recommendations"].append({
                "title": "Fortalecer autenticação",
                "description": "Implemente bloqueio de conta após múltiplas tentativas falhas e considere autenticação de dois fatores.",
                "severity": "high"
            })
        elif activity['type'] == 'Data Exfiltration':
            report["recommendations"].append({
                "title": "Monitorar transferências de dados",
                "description": "Implemente DLP (Data Loss Prevention) e monitore transferências de grandes volumes de dados para fora da rede.",
                "severity": "high"
            })
    
    return report

# Função para gerar gráficos de análise de pacotes
def generate_analysis_charts(df, statistics):
    charts = {}
    
    if df is None or df.empty:
        return charts
    
    # 1. Distribuição de protocolos (gráfico de pizza)
    if statistics["protocols"]:
        protocols_df = pd.DataFrame({
            'Protocol': list(statistics["protocols"].keys()),
            'Count': list(statistics["protocols"].values())
        })
        
        protocols_fig = px.pie(
            protocols_df, 
            values='Count', 
            names='Protocol', 
            title='Distribuição de Protocolos',
            color_discrete_sequence=px.colors.qualitative.Set3
        )
        
        charts["protocol_distribution"] = protocols_fig
    
    # 2. Top IPs de origem (gráfico de barras)
    if statistics["ip_sources"]:
        sources_df = pd.DataFrame({
            'IP': list(statistics["ip_sources"].keys()),
            'Count': list(statistics["ip_sources"].values())
        }).sort_values('Count', ascending=False).head(10)
        
        sources_fig = px.bar(
            sources_df, 
            x='IP', 
            y='Count', 
            title='Top 10 IPs de Origem',
            color='Count',
            color_continuous_scale='Viridis'
        )
        
        charts["top_sources"] = sources_fig
    
    # 3. Top IPs de destino (gráfico de barras)
    if statistics["ip_destinations"]:
        dests_df = pd.DataFrame({
            'IP': list(statistics["ip_destinations"].keys()),
            'Count': list(statistics["ip_destinations"].values())
        }).sort_values('Count', ascending=False).head(10)
        
        dests_fig = px.bar(
            dests_df, 
            x='IP', 
            y='Count', 
            title='Top 10 IPs de Destino',
            color='Count',
            color_continuous_scale='Viridis'
        )
        
        charts["top_destinations"] = dests_fig
    
    # 4. Pacotes ao longo do tempo (gráfico de linha)
    if 'Time' in df.columns:
        # Agrupamos por minuto para visualização mais clara
        df['TimeMinute'] = df['Time'].dt.floor('min')
        packets_per_minute = df.groupby('TimeMinute').size().reset_index(name='count')
        
        timeline_fig = px.line(
            packets_per_minute, 
            x='TimeMinute', 
            y='count', 
            title='Pacotes por Minuto',
            markers=True
        )
        
        charts["packets_timeline"] = timeline_fig
    
    # 5. Tamanho dos pacotes (histograma)
    packet_size_fig = px.histogram(
        df, 
        x='Length', 
        title='Distribuição de Tamanho de Pacotes',
        color_discrete_sequence=['#3498db']
    )
    
    charts["packet_size_distribution"] = packet_size_fig
    
    # 6. Grafo de comunicação (gráfico de rede)
    if len(df) > 0:
        # Criamos um DataFrame com pares origem-destino e contagem
        edges = df.groupby(['Source', 'Destination']).size().reset_index(name='weight')
        
        # Limitamos aos 30 fluxos mais significativos para não sobrecarregar o gráfico
        edges = edges.sort_values('weight', ascending=False).head(30)
        
        # Criamos nós únicos
        nodes = pd.DataFrame({
            'id': pd.unique(edges[['Source', 'Destination']].values.ravel('K'))
        })
        
        # Criamos o gráfico de rede
        network_fig = go.Figure()
        
        # Adicionamos as arestas (conexões)
        for _, edge in edges.iterrows():
            network_fig.add_trace(
                go.Scatter(
                    x=[edge['Source'], edge['Destination']],
                    y=[0, 0],
                    mode='lines',
                    line=dict(width=edge['weight'] / edges['weight'].max() * 10, color='#2c3e50'),
                    hoverinfo='text',
                    text=f"{edge['Source']} → {edge['Destination']} ({edge['weight']} pacotes)",
                    showlegend=False
                )
            )
        
        # Adicionamos os nós (IPs)
        for _, node in nodes.iterrows():
            network_fig.add_trace(
                go.Scatter(
                    x=[node['id']],
                    y=[0],
                    mode='markers',
                    marker=dict(
                        size=15,
                        color='#e74c3c',
                        line=dict(width=2, color='#c0392b')
                    ),
                    name=node['id'],
                    hoverinfo='text',
                    text=node['id']
                )
            )
        
        network_fig.update_layout(
            title='Grafo de Comunicação de Rede',
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            showlegend=False,
            hovermode='closest',
            plot_bgcolor='rgba(0,0,0,0)'
        )
        
        charts["network_graph"] = network_fig
    
    return charts

# Simulador de Wireshark Web
def wireshark_simulator():
    st.markdown("<h1 class='main-header'>Simulador Wireshark Web</h1>", unsafe_allow_html=True)
    
    # Sidebar para controles
    with st.sidebar:
        st.header("Controles")
        
        # Opções de captura
        st.subheader("Captura de Pacotes")
        
        upload_choice = st.radio(
            "Escolha o método de entrada:",
            ("Carregar arquivo PCAP", "Simulação de captura")
        )
        
        if upload_choice == "Carregar arquivo PCAP":
            uploaded_file = st.file_uploader("Escolha um arquivo PCAP", type=["pcap", "pcapng"])
            
            if uploaded_file is not None:
                # Salva o arquivo temporariamente
                temp_file_path = os.path.join("/tmp", uploaded_file.name)
                with open(temp_file_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                
                # Carrega o arquivo PCAP
                st.session_state.df = pcap_to_dataframe(temp_file_path)
                st.success(f"Arquivo carregado: {uploaded_file.name}")
                
                # Remove o arquivo temporário
                if os.path.exists(temp_file_path):
                    os.remove(temp_file_path)
        else:
            st.subheader("Simulação de Captura")
            protocol_type = st.selectbox(
                "Tipo de Tráfego:",
                ["HTTP", "DNS", "TCP", "ICMP", "HTTPS", "Mixed"]
            )
            
            duration = st.slider("Duração da Captura (segundos):", 5, 60, 10)
            
            if st.button("Iniciar Captura Simulada"):
                st.session_state.df = simulate_packet_capture(protocol_type.lower(), duration)
                st.success(f"Captura simulada de tráfego {protocol_type} por {duration} segundos.")
        
        # Filtros
        st.subheader("Filtros")
        
        # Verifica se já temos dados carregados
        if hasattr(st.session_state, 'df') and st.session_state.df is not None:
            # Extraímos protocolos únicos para o seletor
            protocols = [""] + sorted(st.session_state.df['Protocol'].unique().tolist())
            selected_protocol = st.selectbox("Protocolo:", protocols)
            
            source_ip = st.text_input("IP de Origem (contém):")
            dest_ip = st.text_input("IP de Destino (contém):")
            
            content_filter = st.text_input("Conteúdo (busca global):")
            
            min_length = st.number_input("Tamanho Mínimo:", value=0, min_value=0)
            max_length = st.number_input("Tamanho Máximo:", value=0, min_value=0)
            
            filters = {
                "protocol": selected_protocol if selected_protocol else None,
                "source_ip": source_ip if source_ip else None,
                "dest_ip": dest_ip if dest_ip else None,
                "content": content_filter if content_filter else None,
                "min_length": min_length if min_length > 0 else None,
                "max_length": max_length if max_length > 0 else None
            }
            
            # Aplicamos os filtros
            if any(v is not None for v in filters.values()):
                st.session_state.filtered_df = apply_filters(st.session_state.df, filters)
                st.write(f"Mostrando {len(st.session_state.filtered_df)} de {len(st.session_state.df)} pacotes.")
            else:
                st.session_state.filtered_df = st.session_state.df
        
        # Análises avançadas
        st.subheader("Análises Avançadas")
        
        if hasattr(st.session_state, 'df') and st.session_state.df is not None:
            if st.button("Detectar Atividades Suspeitas"):
                with st.spinner("Analisando pacotes..."):
                    suspicious_activities = detect_suspicious_patterns(st.session_state.filtered_df)
                    st.session_state.suspicious_activities = suspicious_activities
                    
                    if suspicious_activities:
                        st.warning(f"Encontradas {len(suspicious_activities)} atividades suspeitas!")
                    else:
                        st.success("Nenhuma atividade suspeita detectada.")
            
            if st.button("Gerar Relatório de Análise"):
                with st.spinner("Gerando relatório..."):
                    # Extraímos estatísticas
                    statistics = extract_packet_statistics(st.session_state.filtered_df)
                    
                    # Detectamos atividades suspeitas (se ainda não tiver feito)
                    if not hasattr(st.session_state, 'suspicious_activities'):
                        st.session_state.suspicious_activities = detect_suspicious_patterns(st.session_state.filtered_df)
                    
                    # Geramos o relatório
                    report = generate_analysis_report(
                        st.session_state.filtered_df,
                        statistics,
                        st.session_state.suspicious_activities
                    )
                    
                    # Salvamos o relatório na sessão
                    st.session_state.analysis_report = report
                    
                    st.success("Relatório gerado com sucesso!")
            
            if st.button("Visualizar Estatísticas"):
                with st.spinner("Gerando visualizações..."):
                    # Extraímos estatísticas
                    statistics = extract_packet_statistics(st.session_state.filtered_df)
                    
                    # Geramos os gráficos
                    charts = generate_analysis_charts(st.session_state.filtered_df, statistics)
                    
                    # Salvamos os gráficos na sessão
                    st.session_state.analysis_charts = charts
                    
                    st.success("Visualizações geradas com sucesso!")
    
    # Conteúdo principal
    # Verifica se temos dados para mostrar
    if hasattr(st.session_state, 'filtered_df') and st.session_state.filtered_df is not None:
        df_to_display = st.session_state.filtered_df
        
        # Abas para a interface principal
        tabs = st.tabs(["Pacotes", "Detalhes", "Análise", "Relatório", "Visualizações", "Atividades Suspeitas"])
        
        # Aba de Pacotes
        with tabs[0]:
            st.markdown("<h2 class='sub-header'>Lista de Pacotes</h2>", unsafe_allow_html=True)
            
            # Mostramos os pacotes em uma tabela
            st.dataframe(
                df_to_display.drop(columns=['Raw']),
                use_container_width=True,
                hide_index=True
            )
            
            # Seletor de pacote
            selected_packet_num = st.selectbox(
                "Selecione um pacote para ver detalhes:",
                df_to_display['No.'].tolist()
            )
            
            if selected_packet_num:
                # Armazenamos o pacote selecionado na sessão
                st.session_state.selected_packet = df_to_display[df_to_display['No.'] == selected_packet_num].iloc[0]
        
        # Aba de Detalhes
        with tabs[1]:
            if hasattr(st.session_state, 'selected_packet'):
                packet = st.session_state.selected_packet
                
                st.markdown(f"<h2 class='sub-header'>Pacote #{packet['No.']}</h2>", unsafe_allow_html=True)
                
                # Mostramos as informações básicas
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("<h3>Informações Básicas</h3>", unsafe_allow_html=True)
                    basic_info = {
                        "Número": packet['No.'],
                        "Tempo": packet['Time'],
                        "Origem": packet['Source'],
                        "Destino": packet['Destination'],
                        "Protocolo": packet['Protocol'],
                        "Tamanho": f"{packet['Length']} bytes",
                        "Info": packet['Info']
                    }
                    
                    for key, value in basic_info.items():
                        st.write(f"**{key}:** {value}")
                
                with col2:
                    st.markdown("<h3>Detalhes Avançados</h3>", unsafe_allow_html=True)
                    
                    # Extraímos detalhes avançados do pacote
                    advanced_details = extract_advanced_packet_details(packet['Raw'])
                    
                    # Mostramos as seções em expanders
                    for section, details in advanced_details.items():
                        with st.expander(section):
                            for key, value in details.items():
                                st.write(f"**{key}:** {value}")
                
                # Mostramos o pacote bruto
                with st.expander("Pacote Bruto"):
                    st.code(packet['Raw'], language='text')
        
        # Aba de Análise
        with tabs[2]:
            st.markdown("<h2 class='sub-header'>Análise de Tráfego</h2>", unsafe_allow_html=True)
            
            # Extraímos estatísticas
            statistics = extract_packet_statistics(df_to_display)
            
            # Mostramos estatísticas básicas
            st.markdown("<h3>Estatísticas Básicas</h3>", unsafe_allow_html=True)
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Total de Pacotes", statistics["total_packets"])
            
            with col2:
                st.metric("Tamanho Médio", f"{statistics['avg_packet_size']:.2f} bytes")
            
            with col3:
                st.metric("Taxa de Pacotes", f"{statistics['packet_rate']:.2f} pkt/s")
            
            # Mostramos distribuição de protocolos
            st.markdown("<h3>Distribuição de Protocolos</h3>", unsafe_allow_html=True)
            
            protocols_df = pd.DataFrame({
                'Protocolo': list(statistics["protocols"].keys()),
                'Quantidade': list(statistics["protocols"].values())
            })
            
            st.dataframe(protocols_df, use_container_width=True)
            
            # Mostramos TOP IPs
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("<h3>Top 10 IPs de Origem</h3>", unsafe_allow_html=True)
                
                sources_df = pd.DataFrame({
                    'IP': list(statistics["ip_sources"].keys()),
                    'Quantidade': list(statistics["ip_sources"].values())
                }).sort_values('Quantidade', ascending=False).head(10)
                
                st.dataframe(sources_df, use_container_width=True)
            
            with col2:
                st.markdown("<h3>Top 10 IPs de Destino</h3>", unsafe_allow_html=True)
                
                dests_df = pd.DataFrame({
                    'IP': list(statistics["ip_destinations"].keys()),
                    'Quantidade': list(statistics["ip_destinations"].values())
                }).sort_values('Quantidade', ascending=False).head(10)
                
                st.dataframe(dests_df, use_container_width=True)
            
            # Mostramos fluxos de comunicação
            st.markdown("<h3>Principais Fluxos de Comunicação</h3>", unsafe_allow_html=True)
            
            if not df_to_display.empty:
                flows = df_to_display.groupby(['Source', 'Destination']).size().reset_index(name='count')
                flows = flows.sort_values('count', ascending=False).head(10)
                flows.columns = ['Origem', 'Destino', 'Pacotes']
                
                st.dataframe(flows, use_container_width=True)
        
        # Aba de Relatório
        with tabs[3]:
            st.markdown("<h2 class='sub-header'>Relatório de Análise</h2>", unsafe_allow_html=True)
            
            if hasattr(st.session_state, 'analysis_report'):
                report = st.session_state.analysis_report
                
                # Resumo
                st.markdown("<h3>Resumo da Captura</h3>", unsafe_allow_html=True)
                
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric("Total de Pacotes", report["summary"]["total_packets"])
                
                with col2:
                    st.metric("Tamanho Médio", f"{report['summary']['avg_packet_size']}")
                
                with col3:
                    st.metric("Taxa de Pacotes", report["summary"]["packet_rate"])
                
                with col4:
                    if report["summary"]["protocol_distribution"]:
                        dominant_protocol = max(report["summary"]["protocol_distribution"].items(), key=lambda x: x[1])[0]
                        st.metric("Protocolo Dominante", dominant_protocol)
                
                # Período de tempo
                st.info(f"Período: {report['summary']['time_period']}")
                
                # Principais IPs
                st.markdown("<h3>Principais IPs</h3>", unsafe_allow_html=True)
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("<h4>Top Origens</h4>", unsafe_allow_html=True)
                    
                    for ip, count in list(report["top_ips"]["sources"].items())[:5]:
                        st.write(f"• **{ip}**: {count} pacotes")
                
                with col2:
                    st.markdown("<h4>Top Destinos</h4>", unsafe_allow_html=True)
                    
                    for ip, count in list(report["top_ips"]["destinations"].items())[:5]:
                        st.write(f"• **{ip}**: {count} pacotes")
                
                # Fluxos mais relevantes
                st.markdown("<h3>Principais Fluxos de Comunicação</h3>", unsafe_allow_html=True)
                
                for flow in report["top_flows"][:5]:
                    st.write(f"• **{flow['source']} → {flow['destination']}**: {flow['packet_count']} pacotes")
                
                # Atividades suspeitas
                st.markdown("<h3>Atividades Suspeitas</h3>", unsafe_allow_html=True)
                
                if report["suspicious_activities"]:
                    for activity in report["suspicious_activities"]:
                        severity_color = {
                            "high": "#ff4444",
                            "medium": "#ffbb33",
                            "low": "#33b5e5"
                        }.get(activity.get("severity", "low"), "#33b5e5")
                        
                        st.markdown(
                            f"<div style='background-color: {severity_color}22; border-left: 5px solid {severity_color}; padding: 10px; margin-bottom: 10px;'>"
                            f"<strong>{activity['type']}</strong><br/>{activity['details']}"
                            f"</div>",
                            unsafe_allow_html=True
                        )
                else:
                    st.success("Nenhuma atividade suspeita detectada.")
                
                # Recomendações
                st.markdown("<h3>Recomendações</h3>", unsafe_allow_html=True)
                
                if report["recommendations"]:
                    for rec in report["recommendations"]:
                        severity_color = {
                            "high": "#ff4444",
                            "medium": "#ffbb33",
                            "low": "#33b5e5"
                        }.get(rec.get("severity", "low"), "#33b5e5")
                        
                        st.markdown(
                            f"<div style='background-color: {severity_color}22; border-left: 5px solid {severity_color}; padding: 10px; margin-bottom: 10px;'>"
                            f"<strong>{rec['title']}</strong><br/>{rec['description']}"
                            f"</div>",
                            unsafe_allow_html=True
                        )
                else:
                    st.info("Nenhuma recomendação específica.")
                
                # Exportar relatório
                st.markdown("<h3>Exportar Relatório</h3>", unsafe_allow_html=True)
                
                col1, col2 = st.columns(2)
                
                with col1:
                    report_json = json.dumps(report, indent=2, default=str)
                    st.download_button(
                        "Baixar como JSON",
                        report_json,
                        "analise_wireshark.json",
                        "application/json"
                    )
                
                with col2:
                    # Criamos uma versão markdown do relatório
                    report_md = f"""# Relatório de Análise de Captura de Pacotes

## Resumo
- **Total de Pacotes**: {report["summary"]["total_packets"]}
- **Período**: {report['summary']['time_period']}
- **Taxa de Pacotes**: {report["summary"]["packet_rate"]}
- **Tamanho Médio**: {report['summary']['avg_packet_size']}

## Principais IPs

### Top Origens
{chr(10).join([f"- **{ip}**: {count} pacotes" for ip, count in list(report["top_ips"]["sources"].items())[:5]])}

### Top Destinos
{chr(10).join([f"- **{ip}**: {count} pacotes" for ip, count in list(report["top_ips"]["destinations"].items())[:5]])}

## Principais Fluxos de Comunicação
{chr(10).join([f"- **{flow['source']} → {flow['destination']}**: {flow['packet_count']} pacotes" for flow in report["top_flows"][:5]])}

## Atividades Suspeitas
{chr(10).join([f"- **{activity['type']}**: {activity['details']}" for activity in report["suspicious_activities"]]) if report["suspicious_activities"] else "Nenhuma atividade suspeita detectada."}

## Recomendações
{chr(10).join([f"- **{rec['title']}**: {rec['description']}" for rec in report["recommendations"]]) if report["recommendations"] else "Nenhuma recomendação específica."}
"""
                    
                    st.download_button(
                        "Baixar como Markdown",
                        report_md,
                        "analise_wireshark.md",
                        "text/markdown"
                    )
            else:
                st.info("Clique em 'Gerar Relatório de Análise' no painel lateral para ver o relatório completo.")
        
        # Aba de Visualizações
        with tabs[4]:
            st.markdown("<h2 class='sub-header'>Visualizações</h2>", unsafe_allow_html=True)
            
            if hasattr(st.session_state, 'analysis_charts'):
                charts = st.session_state.analysis_charts
                
                # Distribuição de protocolos
                if "protocol_distribution" in charts:
                    st.plotly_chart(charts["protocol_distribution"], use_container_width=True)
                
                # Top IPs
                col1, col2 = st.columns(2)
                
                with col1:
                    if "top_sources" in charts:
                        st.plotly_chart(charts["top_sources"], use_container_width=True)
                
                with col2:
                    if "top_destinations" in charts:
                        st.plotly_chart(charts["top_destinations"], use_container_width=True)
                
                # Pacotes ao longo do tempo
                if "packets_timeline" in charts:
                    st.plotly_chart(charts["packets_timeline"], use_container_width=True)
                
                # Tamanho dos pacotes
                if "packet_size_distribution" in charts:
                    st.plotly_chart(charts["packet_size_distribution"], use_container_width=True)
                
                # Grafo de comunicação
                if "network_graph" in charts:
                    st.markdown("<h3>Grafo de Comunicação de Rede</h3>", unsafe_allow_html=True)
                    st.plotly_chart(charts["network_graph"], use_container_width=True)
                    st.info("Este grafo mostra os principais fluxos de comunicação na rede. O tamanho das linhas representa o volume de pacotes trocados.")
            else:
                st.info("Clique em 'Visualizar Estatísticas' no painel lateral para gerar os gráficos.")
        
        # Aba de Atividades Suspeitas
        with tabs[5]:
            st.markdown("<h2 class='sub-header'>Atividades Suspeitas</h2>", unsafe_allow_html=True)
            
            if hasattr(st.session_state, 'suspicious_activities'):
                activities = st.session_state.suspicious_activities
                
                if activities:
                    for activity in activities:
                        severity_color = {
                            "high": "#ff4444",
                            "medium": "#ffbb33",
                            "low": "#33b5e5"
                        }.get(activity.get("severity", "low"), "#33b5e5")
                        
                        st.markdown(
                            f"<div style='background-color: {severity_color}22; border-left: 5px solid {severity_color}; padding: 15px; margin-bottom: 15px; border-radius: 5px;'>"
                            f"<h3 style='margin-top: 0; color: {severity_color};'>{activity['type']}</h3>"
                            f"<p><strong>Detalhes:</strong> {activity['details']}</p>"
                            f"<p><strong>Severidade:</strong> <span style='color: {severity_color};'>{activity.get('severity', 'baixa').upper()}</span></p>"
                            f"</div>",
                            unsafe_allow_html=True
                        )
                        
                        # Mostrar pacotes relacionados se possível
                        if 'source' in activity:
                            st.markdown(f"<h4>Pacotes relacionados a {activity['source']}</h4>", unsafe_allow_html=True)
                            related_packets = df_to_display[df_to_display['Source'] == activity['source']].head(10)
                            st.dataframe(related_packets.drop(columns=['Raw']), use_container_width=True)
                else:
                    st.success("Nenhuma atividade suspeita detectada na captura atual.")
                    
                    st.markdown("""
                    <div class="highlight">
                        <h3>Tipos de Atividades Suspeitas Detectáveis</h3>
                        <ul>
                            <li><strong>Port Scanning</strong>: Tentativas de conexão a múltiplas portas de um mesmo destino.</li>
                            <li><strong>Packet Flood</strong>: Volume anormalmente alto de pacotes em um curto período de tempo.</li>
                            <li><strong>Brute Force</strong>: Múltiplas tentativas de conexão TCP com resets.</li>
                            <li><strong>Data Exfiltration</strong>: Transferência de grandes volumes de dados para fora da rede.</li>
                        </ul>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.info("Clique em 'Detectar Atividades Suspeitas' no painel lateral para realizar a análise.")

# Componente de Tutorial Interativo
def interactive_tutorial():
    st.markdown("<h1 class='main-header'>Tutorial Interativo do Wireshark</h1>", unsafe_allow_html=True)
    
    # Seções do tutorial
    tutorial_sections = [
        {
            "title": "Introdução ao Wireshark",
            "content": """
            <div class="highlight">
                <h3>O que é o Wireshark?</h3>
                <p>O Wireshark é uma das ferramentas de análise de protocolo de rede mais poderosas e amplamente utilizadas no mundo. É um software livre e de código aberto que permite capturar e examinar interativamente o tráfego que circula em uma rede de computadores.</p>
                
                <h3>Para que serve?</h3>
                <p>O Wireshark é usado por profissionais de rede, administradores de sistemas, especialistas em segurança, desenvolvedores e educadores para:</p>
                <ul>
                    <li>Diagnosticar problemas de rede</li>
                    <li>Examinar questões de segurança</li>
                    <li>Depurar implementações de protocolos</li>
                    <li>Aprender protocolos de rede em detalhes</li>
                    <li>Analisar o desempenho da rede</li>
                </ul>
            </div>
            """
        },
        {
            "title": "Instalação do Wireshark",
            "content": """
            <div class="highlight">
                <h3>Como instalar o Wireshark?</h3>
                
                <h4>Windows:</h4>
                <ol>
                    <li>Acesse o site oficial: <a href="https://www.wireshark.org/download.html" target="_blank">wireshark.org/download.html</a></li>
                    <li>Baixe o instalador Windows (64-bit)</li>
                    <li>Execute o instalador e siga as instruções</li>
                    <li>Durante a instalação, você pode escolher instalar o WinPcap ou Npcap, que são necessários para a captura de pacotes</li>
                </ol>
                
                <h4>macOS:</h4>
                <ol>
                    <li>Acesse o site oficial: <a href="https://www.wireshark.org/download.html" target="_blank">wireshark.org/download.html</a></li>
                    <li>Baixe o instalador macOS Intel ou ARM</li>
                    <li>Abra o arquivo .dmg e arraste o Wireshark para a pasta Applications</li>
                </ol>
                
                <h4>Linux (Ubuntu/Debian):</h4>
                <div class="terminal">
                sudo apt update<br>
                sudo apt install wireshark<br>
                # Durante a instalação, você será perguntado se usuários não-root podem capturar pacotes
                </div>
                
                <h4>Linux (Fedora/RHEL):</h4>
                <div class="terminal">
                sudo dnf install wireshark<br>
                sudo usermod -a -G wireshark $USER  # Adiciona seu usuário ao grupo wireshark
                </div>
            </div>
            """
        },
        {
            "title": "Interface do Wireshark",
            "content": """
            <div class="highlight">
                <h3>Componentes principais da interface</h3>
                
                <h4>1. Barra de Ferramentas</h4>
                <p>Contém botões para iniciar/parar captura, abrir arquivos, aplicar filtros, etc.</p>
                
                <h4>2. Painel de Lista de Pacotes</h4>
                <p>Mostra cada pacote capturado, com informações como número sequencial, timestamp, origem, destino, protocolo e informações básicas.</p>
                
                <h4>3. Painel de Detalhes do Pacote</h4>
                <p>Apresenta os detalhes do pacote selecionado, organizados em uma árvore hierárquica que mostra cada camada do protocolo.</p>
                
                <h4>4. Painel de Bytes</h4>
                <p>Exibe os bytes brutos do pacote selecionado, tanto em formato hexadecimal quanto ASCII.</p>
                
                <h4>5. Barra de Status</h4>
                <p>Mostra informações sobre a captura atual, como o número de pacotes exibidos e capturados, e a interface de captura.</p>
                
                <h4>6. Campo de Filtro de Exibição</h4>
                <p>Permite aplicar filtros complexos para mostrar apenas os pacotes de interesse.</p>
            </div>
            """
        },
        {
            "title": "Capturando Pacotes",
            "content": """
            <div class="highlight">
                <h3>Como iniciar uma captura</h3>
                
                <h4>Passo 1: Selecionar a Interface</h4>
                <p>Clique em "Capture" > "Options" ou no ícone de engrenagem na barra de ferramentas.</p>
                <p>Selecione a interface de rede pela qual deseja capturar o tráfego:</p>
                <ul>
                    <li><strong>Ethernet</strong>: para tráfego de rede cabeada</li>
                    <li><strong>Wi-Fi</strong>: para tráfego de rede sem fio</li>
                    <li><strong>Loopback</strong>: para tráfego local (127.0.0.1)</li>
                </ul>
                
                <h4>Passo 2: Configurar Opções de Captura (opcional)</h4>
                <ul>
                    <li>Definir filtros de captura para limitar o que é capturado</li>
                    <li>Configurar limites de tamanho de arquivo ou duração</li>
                    <li>Habilitar resolução de nomes (DNS, portas, etc.)</li>
                </ul>
                
                <h4>Passo 3: Iniciar a Captura</h4>
                <p>Clique em "Start" ou no botão azul de tubarão na barra de ferramentas.</p>
                
                <h4>Passo 4: Parar a Captura</h4>
                <p>Clique no botão vermelho "Stop" quando terminar de capturar.</p>
                
                <h3>Salvando capturas</h3>
                <p>Para salvar uma captura para análise posterior:</p>
                <ol>
                    <li>Clique em "File" > "Save" ou "Save As"</li>
                    <li>Escolha o formato (geralmente .pcapng é o padrão)</li>
                    <li>Selecione local e nome do arquivo</li>
                </ol>
            </div>
            """
        },
        {
            "title": "Filtros do Wireshark",
            "content": """
            <div class="highlight">
                <h3>Tipos de Filtros</h3>
                
                <h4>1. Filtros de Captura</h4>
                <p>Aplicados <strong>antes</strong> da captura para limitar os pacotes que são capturados.</p>
                <p>Usa a sintaxe do BPF (Berkeley Packet Filter).</p>
                <p>Exemplos:</p>
                <div class="code-block">
                # Capturar apenas tráfego HTTP
                port 80
                
                # Capturar apenas tráfego de/para um IP específico
                host 192.168.1.100
                
                # Capturar tráfego DNS
                port 53
                </div>
                
                <h4>2. Filtros de Exibição</h4>
                <p>Aplicados <strong>após</strong> a captura para mostrar apenas os pacotes de interesse.</p>
                <p>Usa a sintaxe própria do Wireshark, mais rica que os filtros de captura.</p>
                <p>Exemplos:</p>
                <div class="code-block">
                # Mostrar apenas pacotes HTTP
                http
                
                # Mostrar pacotes de um IP específico
                ip.addr == 192.168.1.100
                
                # Mostrar pacotes com requisições GET do HTTP
                http.request.method == "GET"
                
                # Mostrar pacotes TCP com a flag SYN ativa
                tcp.flags.syn == 1
                
                # Combinando filtros (operadores lógicos)
                http and ip.addr == 192.168.1.100
                
                # Excluindo pacotes
                !(arp or dns)
                </div>
            </div>
            """
        },
        {
            "title": "Análise de Protocolos Comuns",
            "content": """
            <div class="highlight">
                <h3>HTTP/HTTPS</h3>
                <p>Filtros úteis:</p>
                <div class="code-block">
                http                  # Todos os pacotes HTTP
                http.request          # Apenas requisições
                http.response         # Apenas respostas
                http.request.method   # Filtrar por método (GET, POST, etc.)
                http.response.code    # Filtrar por código de status (200, 404, etc.)
                http.host contains "example.com"  # Filtrar por host
                </div>
                
                <h3>DNS</h3>
                <p>Filtros úteis:</p>
                <div class="code-block">
                dns                   # Todos os pacotes DNS
                dns.qry.name contains "google"  # Consultas com "google" no nome
                dns.flags.rcode != 0  # Respostas com erro
                dns.resp.name         # Filtrar por nome nas respostas
                </div>
                
                <h3>TCP</h3>
                <p>Filtros úteis:</p>
                <div class="code-block">
                tcp.port == 80        # Tráfego TCP na porta 80
                tcp.flags.syn == 1    # Pacotes com flag SYN (início de conexão)
                tcp.flags.reset == 1  # Pacotes com flag RST (reset de conexão)
                tcp.analysis.retransmission  # Retransmissões TCP
                tcp.window_size < 1000  # Tamanho de janela pequeno
                </div>
                
                <h3>ICMP</h3>
                <p>Filtros úteis:</p>
                <div class="code-block">
                icmp                   # Todos os pacotes ICMP
                icmp.type == 8         # Echo request (ping)
                icmp.type == 0         # Echo reply (resposta de ping)
                icmp.type == 3         # Destination unreachable
                </div>
            </div>
            """
        },
        {
            "title": "Análise de Segurança com Wireshark",
            "content": """
            <div class="highlight">
                <h3>Detectando atividades suspeitas</h3>
                
                <h4>1. Port Scanning</h4>
                <p>Sinais típicos:</p>
                <ul>
                    <li>Múltiplas tentativas de conexão de um único IP para várias portas</li>
                    <li>Muitos pacotes SYN sem completar o three-way handshake</li>
                    <li>Sequência de portas em ordem numérica</li>
                </ul>
                <p>Filtro útil:</p>
                <div class="code-block">
                tcp.flags.syn == 1 and tcp.flags.ack == 0
                </div>
                
                <h4>2. Ataques de Força Bruta</h4>
                <p>Sinais típicos:</p>
                <ul>
                    <li>Múltiplas tentativas de login (ex: muitas requisições POST para páginas de login)</li>
                    <li>Muitas conexões curtas para serviços como SSH, FTP, etc.</li>
                </ul>
                <p>Filtro útil (SSH):</p>
                <div class="code-block">
                tcp.port == 22 and tcp.flags.syn == 1
                </div>
                
                <h4>3. ARP Poisoning</h4>
                <p>Sinais típicos:</p>
                <ul>
                    <li>Muitas mensagens ARP sem solicitação</li>
                    <li>Alterações constantes de mapeamento MAC-IP</li>
                </ul>
                <p>Filtro útil:</p>
                <div class="code-block">
                arp.duplicate-address-detected or arp.duplicate-address-frame
                </div>
                
                <h4>4. DDoS Attacks</h4>
                <p>Sinais típicos:</p>
                <ul>
                    <li>Volume anormalmente alto de tráfego</li>
                    <li>Muitas requisições similares de muitas fontes diferentes</li>
                </ul>
                <p>Filtro útil (SYN Flood):</p>
                <div class="code-block">
                tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.dst == [target_ip]
                </div>
                
                <h4>5. Exfiltração de Dados</h4>
                <p>Sinais típicos:</p>
                <ul>
                    <li>Grandes volumes de dados enviados para fora da rede</li>
                    <li>Transferências para domínios ou IPs incomuns</li>
                    <li>Dados codificados ou cifrados em protocolos normalmente não cifrados</li>
                </ul>
                <p>Filtro útil:</p>
                <div class="code-block">
                (ip.dst != 192.168.0.0/16) and (ip.dst != 10.0.0.0/8) and (frame.len > 1000)
                </div>
            </div>
            """
        },
        {
            "title": "Análise Forense com Wireshark",
            "content": """
            <div class="highlight">
                <h3>Técnicas de Análise Forense de Rede</h3>
                
                <h4>1. Reconstrução de Conversações</h4>
                <p>O Wireshark permite reconstruir conversações completas de protocolos como HTTP, SMTP e outros.</p>
                <p>Para reconstruir:</p>
                <ol>
                    <li>Selecione um pacote da conversação</li>
                    <li>Clique com o botão direito e escolha "Follow" (ex: "Follow TCP Stream")</li>
                    <li>Analise a conversação completa na janela que aparecer</li>
                </ol>
                
                <h4>2. Extração de Arquivos</h4>
                <p>Você pode extrair arquivos transferidos por protocolos como HTTP, FTP ou SMB:</p>
                <ol>
                    <li>Vá para "File" > "Export Objects"</li>
                    <li>Selecione o protocolo (HTTP, SMB, etc.)</li>
                    <li>Escolha os arquivos que deseja salvar</li>
                </ol>
                
                <h4>3. Linha do Tempo de Eventos</h4>
                <p>Para criar uma linha do tempo de atividades:</p>
                <ol>
                    <li>Use o campo "Time" para ordenar cronologicamente</li>
                    <li>Aplique filtros relevantes para eventos específicos</li>
                    <li>Use "Statistics" > "I/O Graph" para visualizar padrões de tráfego ao longo do tempo</li>
                </ol>
                
                <h4>4. Análise de Anomalias</h4>
                <p>Identifique comportamentos anômalos:</p>
                <ul>
                    <li>Picos repentinos de tráfego (use "Statistics" > "I/O Graph")</li>
                    <li>Protocolos em portas não padrão (ex: "tcp.port == 80 and !http")</li>
                    <li>Erros frequentes ou retransmissões (use "tcp.analysis.flags")</li>
                </ul>
                
                <h4>5. Documentação</h4>
                <p>Dicas para documentar descobertas:</p>
                <ul>
                    <li>Use "File" > "Print" para documentar pacotes importantes</li>
                    <li>Faça capturas de tela de análises e gráficos relevantes</li>
                    <li>Exporte estatísticas via "Statistics" > "Summary" ou outros relatórios</li>
                    <li>Crie anotações detalhadas com timestamps, IPs e portas relevantes</li>
                    <li>Documente a cadeia de eventos em ordem cronológica</li>
                </ul>
            </div>
            """
        },
        {
            "title": "Exercícios Práticos",
            "content": """
            <div class="highlight">
                <h3>Exercícios para Iniciantes</h3>
                
                <div class="challenge-card">
                    <h4>Exercício 1: Análise de Tráfego HTTP</h4>
                    <p><strong>Objetivo:</strong> Capturar e analisar uma sessão HTTP simples.</p>
                    <p><strong>Instruções:</strong></p>
                    <ol>
                        <li>Inicie uma captura no Wireshark</li>
                        <li>Acesse um site que use HTTP (não HTTPS) em seu navegador</li>
                        <li>Pare a captura após carregar a página</li>
                        <li>Use o filtro "http" para ver apenas o tráfego HTTP</li>
                        <li>Identifique as requisições GET e as respostas do servidor</li>
                        <li>Reconstrua a comunicação usando "Follow HTTP Stream"</li>
                    </ol>
                    <p><strong>Perguntas:</strong></p>
                    <ol>
                        <li>Quais cabeçalhos HTTP são enviados pelo navegador?</li>
                        <li>Qual o código de status das respostas do servidor?</li>
                        <li>Consegue identificar o conteúdo HTML da página?</li>
                    </ol>
                </div>
                
                <div class="challenge-card">
                    <h4>Exercício 2: Análise de DNS</h4>
                    <p><strong>Objetivo:</strong> Entender como funcionam as consultas DNS.</p>
                    <p><strong>Instruções:</strong></p>
                    <ol>
                        <li>Inicie uma captura no Wireshark</li>
                        <li>Abra um terminal/prompt de comando</li>
                        <li>Execute comandos nslookup ou dig para consultar domínios (ex: nslookup google.com)</li>
                        <li>Pare a captura após algumas consultas</li>
                        <li>Use o filtro "dns" para isolar o tráfego DNS</li>
                    </ol>
                    <p><strong>Perguntas:</strong></p>
                    <ol>
                        <li>Quais são os componentes de uma consulta DNS?</li>
                        <li>Como identificar perguntas e respostas DNS?</li>
                        <li>Quais tipos de registros DNS você consegue identificar?</li>
                    </ol>
                </div>
                
                <h3>Exercícios Intermediários</h3>
                
                <div class="challenge-card">
                    <h4>Exercício 3: Análise de Three-way Handshake</h4>
                    <p><strong>Objetivo:</strong> Entender o estabelecimento de conexões TCP.</p>
                    <p><strong>Instruções:</strong></p>
                    <ol>
                        <li>Inicie uma captura no Wireshark</li>
                        <li>Conecte-se a um servidor (acesse um site ou use telnet/nc para conectar a uma porta)</li>
                        <li>Pare a captura após estabelecer a conexão</li>
                        <li>Use filtros para isolar a comunicação TCP com o servidor</li>
                    </ol>
                    <p><strong>Perguntas:</strong></p>
                    <ol>
                        <li>Identifique os pacotes SYN, SYN-ACK e ACK que formam o three-way handshake</li>
                        <li>Quais números de sequência e reconhecimento são usados?</li>
                        <li>Quais opções TCP estão presentes nos pacotes?</li>
                    </ol>
                </div>
                
                <div class="challenge-card">
                    <h4>Exercício 4: Detecção de Port Scanning</h4>
                    <p><strong>Objetivo:</strong> Reconhecer padrões de port scanning em capturas.</p>
                    <p><strong>Instruções:</strong></p>
                    <ol>
                        <li>Baixe e abra no Wireshark uma captura pré-configurada contendo um port scan</li>
                        <li>Alternativamente, use uma VM ou ambiente de laboratório controlado para simular um port scan com ferramentas como nmap</li>
                        <li>Analise o tráfego para identificar o padrão de port scanning</li>
                    </ol>
                    <p><strong>Perguntas:</strong></p>
                    <ol>
                        <li>Qual tipo de port scan foi realizado (SYN scan, connect scan, etc.)?</li>
                        <li>Quais portas foram escaneadas?</li>
                        <li>Como você pode detectar port scans usando filtros do Wireshark?</li>
                    </ol>
                </div>
                
                <h3>Exercícios Avançados</h3>
                
                <div class="challenge-card">
                    <h4>Exercício 5: Análise de Tráfego Malicioso</h4>
                    <p><strong>Objetivo:</strong> Identificar indicadores de comprometimento em capturas de rede.</p>
                    <p><strong>Instruções:</strong></p>
                    <ol>
                        <li>Baixe uma captura PCAP de exemplo contendo tráfego malicioso (disponíveis em repositórios educacionais)</li>
                        <li>Analise a captura para identificar comportamentos anômalos</li>
                        <li>Documente suas descobertas como se estivesse realizando uma investigação forense</li>
                    </ol>
                    <p><strong>Perguntas:</strong></p>
                    <ol>
                        <li>Quais indicadores de comprometimento você consegue identificar?</li>
                        <li>Existe comunicação com IPs ou domínios conhecidamente maliciosos?</li>
                        <li>Há padrões de comunicação suspeitos (como beaconing ou exfiltração de dados)?</li>
                    </ol>
                </div>
                
                <div class="challenge-card">
                    <h4>Exercício 6: Decodificação e Análise de Protocolos Cifrados</h4>
                    <p><strong>Objetivo:</strong> Aprender a decodificar tráfego TLS/SSL quando as chaves estão disponíveis.</p>
                    <p><strong>Instruções:</strong></p>
                    <ol>
                        <li>Configure um ambiente controlado com um servidor web que use HTTPS</li>
                        <li>Configure o navegador para exportar as chaves de sessão (SSLKEYLOGFILE)</li>
                        <li>Capture o tráfego HTTPS</li>
                        <li>Configure o Wireshark para usar o arquivo de log de chaves para decodificar o tráfego</li>
                    </ol>
                    <p><strong>Perguntas:</strong></p>
                    <ol>
                        <li>Como o TLS protege a comunicação? Identifique as fases do handshake TLS</li>
                        <li>Que informações você consegue obter após decodificar o tráfego?</li>
                        <li>Quais aplicações forenses tem esta técnica de decodificação?</li>
                    </ol>
                </div>
            </div>
            """
        },
        {
            "title": "Casos de Estudo",
            "content": """
            <div class="highlight">
                <h3>Caso de Estudo 1: Análise de Ataque DDoS</h3>
                
                <h4>Cenário:</h4>
                <p>Um servidor web apresentou lentidão severa durante 30 minutos. A equipe de TI suspeita de um ataque DDoS e capturou o tráfego durante o incidente.</p>
                
                <h4>Objetivos:</h4>
                <ol>
                    <li>Confirmar se houve um ataque DDoS</li>
                    <li>Identificar o tipo de ataque (SYN flood, HTTP flood, etc.)</li>
                    <li>Determinar a origem do ataque</li>
                    <li>Recomendar medidas de mitigação</li>
                </ol>
                
                <h4>Abordagem de Análise:</h4>
                <ol>
                    <li>Analisar o volume de tráfego ao longo do tempo usando "Statistics" > "I/O Graph"</li>
                    <li>Identificar os IPs que geraram mais tráfego usando "Statistics" > "Endpoints"</li>
                    <li>Examinar padrões nos pacotes para identificar o tipo de ataque</li>
                    <li>Usar filtros específicos para isolar o tráfego malicioso</li>
                </ol>
                
                <h4>Resultados Esperados:</h4>
                <p>Um relatório detalhando a natureza do ataque, evidências coletadas, e recomendações de mitigação.</p>
                
                <h3>Caso de Estudo 2: Investigação de Vazamento de Dados</h3>
                
                <h4>Cenário:</h4>
                <p>Uma empresa suspeita que informações confidenciais estão sendo exfiltradas da rede corporativa. Capturas de rede foram coletadas durante um período de uma semana.</p>
                
                <h4>Objetivos:</h4>
                <ol>
                    <li>Identificar transferências suspeitas de dados</li>
                    <li>Determinar quais estações de trabalho estão envolvidas</li>
                    <li>Avaliar que tipo de dados podem ter sido exfiltrados</li>
                    <li>Documentar a linha do tempo da atividade suspeita</li>
                </ol>
                
                <h4>Abordagem de Análise:</h4>
                <ol>
                    <li>Filtrar transferências grandes de dados para destinos externos à rede</li>
                    <li>Examinar o uso de serviços não autorizados ou canais de comunicação não padrão</li>
                    <li>Analisar comunicações em horários incomuns</li>
                    <li>Procurar por padrões de comunicação regulares com servidores externos não reconhecidos</li>
                </ol>
                
                <h4>Resultados Esperados:</h4>
                <p>Um relatório forense detalhando as evidências de exfiltração, métodos utilizados, dados comprometidos, e cronologia dos eventos.</p>
                
                <h3>Caso de Estudo 3: Troubleshooting de Problemas de Rede</h3>
                
                <h4>Cenário:</h4>
                <p>Usuários de uma aplicação web interna relatam conexões lentas e timeouts intermitentes. A equipe de TI precisa identificar a causa raiz do problema.</p>
                
                <h4>Objetivos:</h4>
                <ol>
                    <li>Identificar se o problema está na rede, no servidor, ou na aplicação</li>
                    <li>Determinar padrões de ocorrência dos problemas</li>
                    <li>Quantificar o impacto (latência, perda de pacotes, etc.)</li>
                    <li>Recomendar soluções</li>
                </ol>
                
                <h4>Abordagem de Análise:</h4>
                <ol>
                    <li>Analisar tempos de resposta usando "Statistics" > "TCP Stream Graph" > "Round Trip Time"</li>
                    <li>Verificar retransmissões e timeouts usando filtros como "tcp.analysis.retransmission"</li>
                    <li>Examinar os tamanhos de janela TCP e ajustes de congestionamento</li>
                    <li>Analisar correlações entre problemas e períodos específicos</li>
                </ol>
                
                <h4>Resultados Esperados:</h4>
                <p>Um diagnóstico técnico identificando a causa raiz do problema e recomendações específicas para resolver o problema.</p>
            </div>
            """
        },
        {
            "title": "Recursos e Videoaulas",
            "content": """
            <div class="highlight">
                <h3>Videoaulas Recomendadas</h3>
                
                <h4>Introdução ao Wireshark:</h4>
                <ul>
                    <li><a href="https://www.youtube.com/watch?v=lb1Dw0elw0Q" target="_blank">Wireshark Tutorial for Beginners</a></li>
                    <li><a href="https://www.youtube.com/watch?v=4_gustyM9Gs" target="_blank">Wireshark Essentials: Capturando e Analisando Tráfego</a> (Em Português)</li>
                    <li><a href="https://www.youtube.com/watch?v=TkCSr30UojM" target="_blank">Wireshark 101: Instalação e Interface</a></li>
                </ul>
                
                <h4>Análise de Protocolos:</h4>
                <ul>
                    <li><a href="https://www.youtube.com/watch?v=0S-ZUUyZhSg" target="_blank">Análise de Protocolos HTTP com Wireshark</a></li>
                    <li><a href="https://www.youtube.com/watch?v=yDDcYRSlrp8" target="_blank">Entendendo o TCP Handshake com Wireshark</a></li>
                    <li><a href="https://www.youtube.com/watch?v=Gdj_D6_P4HQ" target="_blank">DNS em Detalhes com Wireshark</a></li>
                </ul>
                
                <h4>Segurança e Forense:</h4>
                <ul>
                    <li><a href="https://www.youtube.com/watch?v=jU_V4i4TX2g" target="_blank">Detectando Ataques com Wireshark</a></li>
                    <li><a href="https://www.youtube.com/watch?v=5K2mnjNnV7A" target="_blank">Forense de Rede com Wireshark</a></li>
                    <li><a href="https://www.youtube.com/watch?v=Kp5XQbz3IIg" target="_blank">Análise de Malware com Wireshark</a></li>
                </ul>
                
                <h4>Avançado:</h4>
                <ul>
                    <li><a href="https://www.youtube.com/watch?v=gRcJBCdNbVo" target="_blank">Decodificando Tráfego TLS/SSL no Wireshark</a></li>
                    <li><a href="https://www.youtube.com/watch?v=UXAHvwouk6Q" target="_blank">Filtros Avançados no Wireshark</a></li>
                    <li><a href="https://www.youtube.com/watch?v=UeAKTjx_eKA" target="_blank">Análise de Performance com Wireshark</a></li>
                </ul>
                
                <h3>Recursos Adicionais</h3>
                
                <h4>Livros Recomendados:</h4>
                <ul>
                    <li>"Wireshark Network Analysis" por Laura Chappell</li>
                    <li>"Practical Packet Analysis" por Chris Sanders</li>
                    <li>"Network Forensics: Tracking Hackers through Cyberspace" por Sherri Davidoff e Jonathan Ham</li>
                </ul>
                
                <h4>Websites e Documentação:</h4>
                <ul>
                    <li><a href="https://www.wireshark.org/docs/" target="_blank">Documentação Oficial do Wireshark</a></li>
                    <li><a href="https://wiki.wireshark.org/" target="_blank">Wiki do Wireshark</a></li>
                    <li><a href="https://packetlife.net/library/cheat-sheets/" target="_blank">Cheat Sheets de Protocolos (Packet Life)</a></li>
                </ul>
                
                <h4>Capturas de Exemplo:</h4>
                <ul>
                    <li><a href="https://wiki.wireshark.org/SampleCaptures" target="_blank">Capturas de Exemplo do Wireshark</a></li>
                    <li><a href="https://www.malware-traffic-analysis.net/" target="_blank">Malware Traffic Analysis</a></li>
                </ul>
                
                <h4>Cursos Online:</h4>
                <ul>
                    <li><a href="https://www.coursera.org" target="_blank">Coursera - Network Security & Database Vulnerabilities</a></li>
                    <li><a href="https://www.udemy.com" target="_blank">Udemy - Wireshark: Packet Analysis and Ethical Hacking</a></li>
                </ul>
            </div>
            """
        }
    ]
    
    # Seleção de seção
    st.markdown("<h2 class='sub-header'>Escolha um tópico:</h2>", unsafe_allow_html=True)
    
    section_titles = [section["title"] for section in tutorial_sections]
    selected_section = st.selectbox("", section_titles)
    
    # Exibe a seção selecionada
    selected_index = section_titles.index(selected_section)
    st.markdown(tutorial_sections[selected_index]["content"], unsafe_allow_html=True)
    
    # Controles de navegação
    st.markdown("<div style='margin-top: 30px;'></div>", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 3, 1])
    
    with col1:
        if selected_index > 0:
            if st.button("← Anterior"):
                st.session_state.selected_section = section_titles[selected_index - 1]
                st.rerun()
    
    with col3:
        if selected_index < len(section_titles) - 1:
            if st.button("Próximo →"):
                st.session_state.selected_section = section_titles[selected_index + 1]
                st.rerun()

# Componente de Roadmap de Estudos
def study_roadmap():
    st.markdown("<h1 class='main-header'>Roadmap de Estudos em Análise de Tráfego com Wireshark</h1>", unsafe_allow_html=True)
    
    # Introdução
    st.markdown("""
    <div class="highlight">
        <p>Este roadmap de estudos fornece um caminho estruturado para dominar a análise de tráfego de rede com o Wireshark, desde o nível iniciante até o especialista. Cada nível inclui conceitos, habilidades, ferramentas complementares e projetos práticos.</p>
        
        <p>Recomendamos que você siga o roadmap sequencialmente, mas sinta-se à vontade para adaptar conforme seu conhecimento prévio e objetivos específicos.</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Níveis do Roadmap
    levels = [
        {
            "title": "Nível 1: Fundamentos (2-4 semanas)",
            "concepts": [
                "Conceitos básicos de redes (modelos OSI e TCP/IP)",
                "Estrutura de pacotes e quadros",
                "Endereçamento IP e portas TCP/UDP",
                "Protocolos fundamentais (Ethernet, IP, TCP, UDP)",
                "Instalação e configuração do Wireshark"
            ],
            "skills": [
                "Iniciar e parar capturas",
                "Navegar pela interface do Wireshark",
                "Aplicar filtros básicos",
                "Examinar pacotes individuais",
                "Interpretar campos básicos de pacotes"
            ],
            "tools": [
                "Wireshark",
                "Ping",
                "Traceroute/tracert",
                "Nslookup/dig"
            ],
            "projects": [
                "Analisar tráfego de navegação web básica",
                "Capturar e examinar pings e consultas DNS",
                "Identificar o three-way handshake do TCP",
                "Monitorar tráfego de aplicativo específico"
            ]
        },
        {
            "title": "Nível 2: Análise de Protocolos (4-6 semanas)",
            "concepts": [
                "Protocolos de aplicação (HTTP, DNS, DHCP, SMTP)",
                "Encapsulamento de protocolos",
                "Resolução de nomes e serviços",
                "Cabeçalhos e opções TCP/IP detalhados",
                "Análise de conversação e stream"
            ],
            "skills": [
                "Filtros de exibição avançados",
                "Seguir streams TCP/UDP",
                "Análise estatística básica",
                "Exportar objetos de protocolos",
                "Usar perfis e coloração de pacotes"
            ],
            "tools": [
                "Filtros de expressão do Wireshark",
                "Tcpdump (básico)",
                "Netcat/nc",
                "Ferramentas web de teste como curl"
            ],
            "projects": [
                "Analisar uma autenticação HTTP completa",
                "Capturar e interpretar tráfego DHCP completo",
                "Examinar negociação TLS/SSL",
                "Documentar o fluxo completo de transações de aplicações"
            ]
        },
        {
            "title": "Nível 3: Troubleshooting e Performance (4-6 semanas)",
            "concepts": [
                "Análise de latência e throughput",
                "Diagnóstico de problemas de conectividade",
                "Reconhecimento de padrões de tráfego",
                "Retransmissões TCP e controle de fluxo",
                "Fragmentação e MTU"
            ],
            "skills": [
                "Interpretar gráficos e estatísticas",
                "Identificar gargalos de performance",
                "Detectar perda de pacotes e latência",
                "Usar ferramentas de análise Expert Info",
                "Personalizar a interface para troubleshooting"
            ],
            "tools": [
                "Ferramentas de análise estatística do Wireshark",
                "Iperf/jperf",
                "MTR/WinMTR",
                "Tcpdump (avançado)"
            ],
            "projects": [
                "Diagnosticar um problema de latência em rede",
                "Analisar impacto de diferentes tamanhos de MTU",
                "Comparar performance entre diferentes serviços",
                "Criar um relatório de troubleshooting completo"
            ]
        },
        {
            "title": "Nível 4: Segurança e Forense (6-8 semanas)",
            "concepts": [
                "Reconhecimento de padrões de ataque",
                "Técnicas de evasão e tunelamento",
                "Análise de malware baseada em rede",
                "Exfiltração de dados",
                "Protocolos cifrados e técnicas de decodificação"
            ],
            "skills": [
                "Detectar scans e varreduras",
                "Identificar anomalias de tráfego",
                "Reconstruir sessões e artefatos",
                "Extrair indicadores de comprometimento (IOCs)",
                "Decodificar tráfego TLS/SSL com chaves disponíveis"
            ],
            "tools": [
                "Ferramentas de análise de segurança do Wireshark",
                "Tshark",
                "NetworkMiner",
                "Suricata/Snort (básico)",
                "Pacotes PCAP de malware"
            ],
            "projects": [
                "Análise de um ataque de força bruta ou DDoS",
                "Detecção de exfiltração de dados",
                "Reconstrução de arquivos transferidos",
                "Análise forense completa de um incidente"
            ]
        },
        {
            "title": "Nível 5: Especialização e Automação (8+ semanas)",
            "concepts": [
                "Análise programática de pacotes",
                "Integração com outras ferramentas",
                "Análise de protocolos proprietários",
                "Dissectores personalizados",
                "Ambientes de captura distribuída"
            ],
            "skills": [
                "Scripting com tshark e ferramentas de linha de comando",
                "Desenvolver filtros e dissectores personalizados",
                "Automação de análise com Python/Lua",
                "Integração com sistemas de monitoramento",
                "Técnicas de visualização avançada"
            ],
            "tools": [
                "Tshark (avançado)",
                "Python com pyshark/scapy",
                "Lua para dissectores",
                "Elasticsearch/Kibana para visualização",
                "Ambientes de rede virtualizada"
            ],
            "projects": [
                "Desenvolver um dissector para protocolo personalizado",
                "Criar sistema automatizado de detecção de anomalias",
                "Construir dashboard de visualização de tráfego",
                "Implementar sistema de captura e análise distribuída"
            ]
        }
    ]
    
    # Exibição do Roadmap
    for level in levels:
        with st.expander(level["title"], expanded=True):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("<h3>Conceitos-chave</h3>", unsafe_allow_html=True)
                for concept in level["concepts"]:
                    st.markdown(f"• {concept}")
                
                st.markdown("<h3>Ferramentas</h3>", unsafe_allow_html=True)
                for tool in level["tools"]:
                    st.markdown(f"• {tool}")
            
            with col2:
                st.markdown("<h3>Habilidades a desenvolver</h3>", unsafe_allow_html=True)
                for skill in level["skills"]:
                    st.markdown(f"• {skill}")
                
                st.markdown("<h3>Projetos práticos</h3>", unsafe_allow_html=True)
                for project in level["projects"]:
                    st.markdown(f"• {project}")
    
    # Certificações Relevantes
    st.markdown("<h2 class='sub-header'>Certificações Relevantes</h2>", unsafe_allow_html=True)
    
    certifications = [
        {
            "name": "Wireshark Certified Network Analyst (WCNA)",
            "description": "Certificação oficial do Wireshark que valida conhecimentos avançados em análise de protocolos e troubleshooting."
        },
        {
            "name": "CompTIA Network+",
            "description": "Fornece fundamentos sólidos de redes que são essenciais para análise eficaz com Wireshark."
        },
        {
            "name": "Cisco CCNA",
            "description": "Oferece conhecimento aprofundado de redes Cisco e troubleshooting que complementa a análise com Wireshark."
        },
        {
            "name": "SANS GIAC Certified Forensic Analyst (GCFA)",
            "description": "Foco em análise forense digital, incluindo componentes significativos de análise de tráfego de rede."
        },
        {
            "name": "Offensive Security Certified Professional (OSCP)",
            "description": "Inclui componentes de análise de tráfego de rede do ponto de vista ofensivo."
        }
    ]
    
    for cert in certifications:
        st.markdown(f"""
        <div style='background-color: #f5f5f5; padding: 10px; border-radius: 5px; margin-bottom: 10px;'>
            <strong>{cert['name']}</strong><br/>
            {cert['description']}
        </div>
        """, unsafe_allow_html=True)
    
    # Dicas de Estudo
    st.markdown("<h2 class='sub-header'>Dicas de Estudo Efetivo</h2>", unsafe_allow_html=True)
    
    st.markdown("""
    <div class="highlight">
        <ol>
            <li><strong>Pratique regularmente</strong>: Análise de pacotes é uma habilidade prática. Dedique tempo regular para capturar e analisar tráfego.</li>
            <li><strong>Crie um laboratório</strong>: Configure um ambiente controlado usando VMs ou containers para gerar e capturar diferentes tipos de tráfego.</li>
            <li><strong>Estude capturas reais</strong>: Baixe e analise capturas PCAP de repositórios online para ver tráfego real diversificado.</li>
            <li><strong>Participe de comunidades</strong>: Junte-se a fóruns como o da Wireshark, o Stack Exchange Network Engineering ou grupos no Reddit.</li>
            <li><strong>Desafios práticos</strong>: Participe de CTFs (Capture The Flag) com componentes de análise de rede ou desafios PCAP.</li>
            <li><strong>Documente seu aprendizado</strong>: Mantenha anotações detalhadas, bibliotecas de filtros úteis, e capturas interessantes para referência futura.</li>
            <li><strong>Ensine outros</strong>: Explicar conceitos para outras pessoas solidifica seu próprio conhecimento. Considere criar tutoriais ou participar de mentorias.</li>
            <li><strong>Aplique em cenários reais</strong>: Se possível, utilize o Wireshark em situações reais de trabalho ou projetos pessoais.</li>
            <li><strong>Estude além do Wireshark</strong>: Aprofunde-se em redes, protocolos e segurança para contextualizar o que você vê nas capturas.</li>
            <li><strong>Tenha consistência</strong>: É melhor estudar 30 minutos diariamente do que 5 horas em um único dia por semana.</li>
        </ol>
    </div>
    """, unsafe_allow_html=True)

# Componente de Desafios Práticos
def practical_challenges():
    st.markdown("<h1 class='main-header'>Desafios Práticos de Análise com Wireshark</h1>", unsafe_allow_html=True)
    
    # Categorias de desafios
    challenge_categories = ["Fundamentos", "Análise de Protocolos", "Segurança", "Forense", "Troubleshooting", "Avançado"]
    selected_category = st.selectbox("Selecione uma categoria:", challenge_categories)
    
    # Lista de desafios por categoria
    challenges = {
        "Fundamentos": [
            {
                "title": "Desafio 1: TCP Handshake Explorer",
                "description": "Neste desafio, você analisará um arquivo PCAP contendo múltiplas conexões TCP. Sua tarefa é identificar todos os three-way handshakes e documentar os números de sequência iniciais utilizados.",
                "difficulty": "Iniciante",
                "instructions": [
                    "Abra o arquivo PCAP fornecido",
                    "Identifique todos os pacotes SYN para encontrar tentativas de conexão",
                    "Para cada conexão, localize os pacotes SYN, SYN-ACK e ACK que formam o handshake",
                    "Documente os endereços IP, portas, e números de sequência iniciais",
                    "Verifique se há conexões que não seguem o padrão normal"
                ],
                "hints": [
                    "Use o filtro 'tcp.flags.syn==1' para encontrar todos os pacotes SYN",
                    "Utilize a coluna 'Info' para identificar os flags TCP",
                    "Observe a coluna 'Seq' para os números de sequência"
                ],
                "questions": [
                    "Quantas conexões TCP completas existem na captura?",
                    "Todas as tentativas de conexão foram bem-sucedidas?",
                    "Quais são os padrões nos números de sequência iniciais?"
                ],
                "downloadable_files": ["tcp_handshakes.pcap"]
            },
            {
                "title": "Desafio 2: Análise de Consultas DNS",
                "description": "Este desafio foca na compreensão do protocolo DNS. Você analisará uma captura contendo diversas consultas e respostas DNS, identificando diferentes tipos de registros e padrões de consulta.",
                "difficulty": "Iniciante",
                "instructions": [
                    "Abra o arquivo PCAP fornecido",
                    "Use filtros para isolar apenas o tráfego DNS",
                    "Identifique diferentes tipos de consultas (A, AAAA, MX, NS, etc.)",
                    "Analise as respostas e os tempos de resposta",
                    "Identifique consultas recursivas vs. iterativas"
                ],
                "hints": [
                    "Use o filtro 'dns' para isolar tráfego DNS",
                    "Examine os campos 'Info' para ver tipos de consulta",
                    "Observe a hierarquia de consultas DNS para identificar padrões"
                ],
                "questions": [
                    "Quais são os tipos de registros DNS solicitados na captura?",
                    "Há consultas que não receberam respostas? Por quê?",
                    "Qual é o TTL médio das respostas recebidas?"
                ],
                "downloadable_files": ["dns_queries.pcap"]
            }
        ],
        "Análise de Protocolos": [
            {
                "title": "Desafio 3: Decodificação de Sessão HTTP",
                "description": "Neste desafio, você analisará uma sessão HTTP completa, incluindo requisições, respostas, redirecionamentos e transferência de arquivos. O objetivo é reconstruir a navegação do usuário e o conteúdo acessado.",
                "difficulty": "Intermediário",
                "instructions": [
                    "Abra o arquivo PCAP fornecido",
                    "Isole o tráfego HTTP",
                    "Reconstrua a sequência de navegação do usuário",
                    "Extraia os objetos HTTP (imagens, documentos, etc.)",
                    "Analise os cabeçalhos HTTP para obter informações sobre o cliente e servidor"
                ],
                "hints": [
                    "Use 'http' como filtro básico",
                    "Utilize 'Follow HTTP Stream' para visualizar conversações completas",
                    "Verifique File > Export Objects > HTTP para extrair arquivos"
                ],
                "questions": [
                    "Qual navegador o usuário estava utilizando?",
                    "Quais websites foram visitados, em ordem?",
                    "Houve algum upload de arquivo? Se sim, o que foi enviado?",
                    "Algum cookie foi definido durante a navegação?"
                ],
                "downloadable_files": ["http_session.pcap"]
            },
            {
                "title": "Desafio 4: Análise de Protocolo DHCP",
                "description": "Este desafio foca no protocolo DHCP. Você analisará uma captura que contém múltiplas solicitações e renovações DHCP, identificando as fases do processo e configurações fornecidas.",
                "difficulty": "Intermediário",
                "instructions": [
                    "Abra o arquivo PCAP fornecido",
                    "Isole o tráfego DHCP",
                    "Identifique o processo DORA (Discover, Offer, Request, Acknowledge)",
                    "Documente os endereços IP atribuídos, servidores DNS, e outros parâmetros",
                    "Observe os tempos de lease e renovações"
                ],
                "hints": [
                    "Use 'dhcp' como filtro básico",
                    "Observe o campo 'Info' para identificar os diferentes tipos de mensagens",
                    "Examine o conteúdo detalhado de cada pacote para ver as opções DHCP"
                ],
                "questions": [
                    "Quantos clientes solicitaram endereços IP?",
                    "Qual é o tempo de lease configurado?",
                    "Que informações adicionais são fornecidas pelo servidor DHCP?",
                    "Houve alguma tentativa de renovação de lease?"
                ],
                "downloadable_files": ["dhcp_process.pcap"]
            }
        ],
        "Segurança": [
            {
                "title": "Desafio 5: Detecção de Port Scanning",
                "description": "Neste desafio, você analisará tráfego contendo diferentes tipos de port scans (SYN scan, TCP connect scan, FIN scan). O objetivo é identificar os diferentes tipos de scan, o alvo, e as portas examinadas.",
                "difficulty": "Intermediário",
                "instructions": [
                    "Abra o arquivo PCAP fornecido",
                    "Procure por padrões de tráfego indicativos de port scanning",
                    "Identifique os diferentes tipos de scans utilizados",
                    "Determine as portas-alvo e resultados (abertas/fechadas)",
                    "Documente a timeline da atividade de scanning"
                ],
                "hints": [
                    "Procure por muitos pacotes SYN para portas diferentes",
                    "Observe pacotes com combinações incomuns de flags TCP",
                    "Use estatísticas para identificar padrões de comunicação"
                ],
                "questions": [
                    "Quais tipos de port scan foram realizados?",
                    "Qual foi o intervalo de portas escaneado?",
                    "Quais portas foram identificadas como abertas?",
                    "Como você poderia detectar este tipo de atividade em tempo real?"
                ],
                "downloadable_files": ["port_scanning.pcap"]
            },
            {
                "title": "Desafio 6: Análise de Ataque de Brute Force",
                "description": "Neste desafio, você analisará uma tentativa de ataque de força bruta contra um serviço SSH. O objetivo é identificar o padrão de ataque, as credenciais testadas, e determinar se o ataque foi bem-sucedido.",
                "difficulty": "Avançado",
                "instructions": [
                    "Abra o arquivo PCAP fornecido",
                    "Isole o tráfego relacionado ao serviço SSH",
                    "Identifique o padrão de tentativas de login",
                    "Observe os tempos de conexão e desconexão",
                    "Determine se houve uma tentativa bem-sucedida"
                ],
                "hints": [
                    "Use 'tcp.port == 22' para isolar tráfego SSH",
                    "Observe o tamanho dos pacotes e duração das conexões",
                    "Analise os padrões de estabelecimento de conexão e fechamento"
                ],
                "questions": [
                    "Quantas tentativas de login foram realizadas?",
                    "Qual foi a taxa de tentativas (tentativas por minuto)?",
                    "Houve uma pausa ou mudança no padrão durante o ataque?",
                    "O ataque foi bem-sucedido? Como você pode determinar isso?"
                ],
                "downloadable_files": ["ssh_brute_force.pcap"]
            }
        ],
        "Forense": [
            {
                "title": "Desafio 7: Reconstrução de Comunicação por Email",
                "description": "Neste desafio forense, você analisará uma captura contendo comunicação de email via SMTP e POP3/IMAP. O objetivo é reconstruir o conteúdo dos emails, identificar remetentes e destinatários, e recuperar anexos.",
                "difficulty": "Avançado",
                "instructions": [
                    "Abra o arquivo PCAP fornecido",
                    "Isole o tráfego de email (SMTP, POP3, IMAP)",
                    "Reconstrua as mensagens de email completas",
                    "Extraia metadados como remetentes, destinatários, assuntos",
                    "Recupere quaisquer anexos presentes"
                ],
                "hints": [
                    "Use filtros como 'smtp or pop or imap'",
                    "Utilize 'Follow TCP Stream' para visualizar sessões completas",
                    "Preste atenção a codificações como Base64 para anexos"
                ],
                "questions": [
                    "Quantos emails foram enviados/recebidos?",
                    "Quais eram os assuntos e conteúdos principais?",
                    "Havia anexos? Se sim, o que continham?",
                    "Há algum conteúdo suspeito ou indicativo de atividade maliciosa?"
                ],
                "downloadable_files": ["email_traffic.pcap"]
            },
            {
                "title": "Desafio 8: Análise de Malware C2",
                "description": "Neste desafio, você analisará tráfego de rede contendo comunicação entre um host infectado e um servidor de comando e controle (C2). O objetivo é identificar o malware, seus métodos de comunicação e dados exfiltrados.",
                "difficulty": "Especialista",
                "instructions": [
                    "Abra o arquivo PCAP fornecido",
                    "Identifique padrões de comunicação anormais",
                    "Isole o tráfego entre o host infectado e servidores externos",
                    "Analise os protocolos utilizados e possíveis técnicas de ofuscação",
                    "Tente extrair comandos ou dados exfiltrados"
                ],
                "hints": [
                    "Procure por conexões persistentes a IPs ou domínios incomuns",
                    "Observe tráfego em intervalos regulares (beaconing)",
                    "Verifique conteúdo codificado ou cifrado em protocolos comuns"
                ],
                "questions": [
                    "Qual host foi comprometido na rede?",
                    "Qual é o endereço do servidor C2?",
                    "Que tipo de dados foram exfiltrados?",
                    "Que técnicas o malware usou para evitar detecção?",
                    "Como você poderia bloquear este tipo de comunicação no futuro?"
                ],
                "downloadable_files": ["malware_c2.pcap"]
            }
        ],
        "Troubleshooting": [
            {
                "title": "Desafio 9: Diagnóstico de Problemas de Performance",
                "description": "Neste desafio, você analisará uma rede com problemas de performance. O objetivo é identificar os gargalos, latência anormal, retransmissões, e outros problemas que afetam o desempenho da rede.",
                "difficulty": "Intermediário",
                "instructions": [
                    "Abra o arquivo PCAP fornecido",
                    "Analise os tempos de resposta para diferentes protocolos",
                    "Identifique retransmissões TCP e outros sinais de problemas",
                    "Verifique os tamanhos de janela TCP e ajustes de congestionamento",
                    "Localize possíveis causas de lentidão"
                ],
                "hints": [
                    "Use filtros como 'tcp.analysis.retransmission' para encontrar problemas",
                    "Utilize os gráficos em Statistics > TCP Stream Graphs",
                    "Verifique estatísticas de Round-Trip Time"
                ],
                "questions": [
                    "Quais hosts/conexões apresentam problemas de performance?",
                    "Qual é a taxa de retransmissão média observada?",
                    "Há problemas de fragmentação de pacotes?",
                    "Quais recomendações você faria para resolver os problemas identificados?"
                ],
                "downloadable_files": ["network_performance.pcap"]
            },
            {
                "title": "Desafio 10: Resolução de Problemas de Conectividade",
                "description": "Neste desafio, você analisará uma rede com problemas de conectividade intermitente. O objetivo é identificar falhas de conexão, configurações incorretas, e outros problemas que impedem a comunicação efetiva.",
                "difficulty": "Intermediário",
                "instructions": [
                    "Abra o arquivo PCAP fornecido",
                    "Examine os padrões de falha de conexão",
                    "Analise configurações de rede (ARP, DNS, gateway)",
                    "Identifique respostas de erro e timeouts",
                    "Determine a causa raiz dos problemas"
                ],
                "hints": [
                    "Verifique erros ICMP como 'host unreachable' ou 'port unreachable'",
                    "Observe problemas de resolução DNS",
                    "Procure por inconsistências nas tabelas ARP"
                ],
                "questions": [
                    "Quais hosts apresentam problemas de conectividade?",
                    "Qual a natureza principal do problema (DNS, roteamento, firewall, etc.)?",
                    "Os problemas são consistentes ou intermitentes?",
                    "Que solução você recomendaria para resolver o problema?"
                ],
                "downloadable_files": ["connectivity_issues.pcap"]
            }
        ],
        "Avançado": [
            {
                "title": "Desafio 11: Análise de Tráfego Cifrado",
                "description": "Neste desafio avançado, você trabalhará com tráfego TLS/SSL, incluindo as chaves de sessão para permitir a decodificação. O objetivo é analisar o conteúdo de comunicações cifradas e identificar potenciais problemas ou atividades maliciosas.",
                "difficulty": "Especialista",
                "instructions": [
                    "Abra o arquivo PCAP fornecido e o arquivo de log de chaves",
                    "Configure o Wireshark para usar as chaves de sessão (Edit > Preferences > Protocols > TLS)",
                    "Analise o handshake TLS e parâmetros de criptografia",
                    "Examine o conteúdo decodificado",
                    "Identifique qualquer atividade suspeita"
                ],
                "hints": [
                    "Verifique se o Wireshark está corretamente configurado para usar o arquivo de chaves",
                    "Utilize 'Follow TLS Stream' para ver o conteúdo decodificado",
                    "Analise os certificados e parâmetros de criptografia"
                ],
                "questions": [
                    "Quais suítes de criptografia foram negociadas?",
                    "Os certificados envolvidos são válidos e confiáveis?",
                    "Após decodificação, há algum conteúdo ou padrão suspeito?",
                    "Como você poderia detectar anomalias em tráfego cifrado sem ter as chaves?"
                ],
                "downloadable_files": ["encrypted_traffic.pcap", "sslkeys.log"]
            },
            {
                "title": "Desafio 12: Análise de Protocolo Personalizado",
                "description": "Neste desafio de nível especialista, você analisará tráfego contendo um protocolo proprietário/personalizado desconhecido. O objetivo é fazer engenharia reversa do protocolo, identificar seu formato, comandos, e funcionalidades.",
                "difficulty": "Especialista",
                "instructions": [
                    "Abra o arquivo PCAP fornecido",
                    "Identifique padrões no tráfego desconhecido",
                    "Tente determinar o formato do cabeçalho e campos do protocolo",
                    "Deduza comandos, respostas e funcionalidades do protocolo",
                    "Crie um 'dissector' básico ou documentação sobre o protocolo"
                ],
                "hints": [
                    "Procure por padrões como bytes mágicos ou estruturas recorrentes",
                    "Verifique se o protocolo segue estruturas comuns (TLV, JSON, etc.)",
                    "Observe a relação entre solicitações e respostas"
                ],
                "questions": [
                    "Qual é a estrutura básica do protocolo?",
                    "Quais comandos ou operações você conseguiu identificar?",
                    "O protocolo tem algum mecanismo de autenticação ou segurança?",
                    "Como você implementaria um dissector para este protocolo no Wireshark?"
                ],
                "downloadable_files": ["custom_protocol.pcap"]
            }
        ]
    }
    
    # Mostrar desafios da categoria selecionada
    for challenge in challenges[selected_category]:
        with st.expander(f"{challenge['title']} ({challenge['difficulty']})", expanded=True):
            st.markdown(f"<p>{challenge['description']}</p>", unsafe_allow_html=True)
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("<h4>Instruções</h4>", unsafe_allow_html=True)
                for i, instruction in enumerate(challenge["instructions"], 1):
                    st.markdown(f"{i}. {instruction}")
                
                st.markdown("<h4>Dicas</h4>", unsafe_allow_html=True)
                for hint in challenge["hints"]:
                    st.markdown(f"• {hint}")
            
            with col2:
                st.markdown("<h4>Perguntas para Resolver</h4>", unsafe_allow_html=True)
                for i, question in enumerate(challenge["questions"], 1):
                    st.markdown(f"{i}. {question}")
                
                st.markdown("<h4>Arquivos Necessários</h4>", unsafe_allow_html=True)
                for file in challenge["downloadable_files"]:
                    st.download_button(
                        f"Baixar {file}",
                        data=f"Este é um placeholder para o arquivo {file}. Em um ambiente real, este botão faria download do arquivo PCAP real.",
                        file_name=file,
                        mime="application/octet-stream"
                    )
    
    # Botão para verificar soluções
    if st.button("Verificar Soluções (apenas para fins educacionais)"):
        st.info("As soluções para os desafios estariam disponíveis após enviar suas respostas em um ambiente real. Isso permite que você possa aprender com erros e verificar sua compreensão.")
        
        # Exemplo de solução
        st.markdown("""
        <div class="highlight">
            <h3>Exemplo de Solução - Desafio 1: TCP Handshake Explorer</h3>
            
            <h4>Respostas:</h4>
            <ol>
                <li>A captura contém 5 conexões TCP completas.</li>
                <li>Nem todas as tentativas foram bem-sucedidas. Duas tentativas foram rejeitadas com RST.</li>
                <li>Os números de sequência iniciais parecem seguir um padrão incremental, sugerindo que podem ser previsíveis.</li>
            </ol>
            
            <h4>Método de Análise:</h4>
            <ol>
                <li>Utilizei o filtro <code>tcp.flags.syn==1 and tcp.flags.ack==0</code> para identificar todos os pacotes SYN iniciais</li>
                <li>Para cada pacote SYN, segui o stream correspondente para localizar o handshake completo</li>
                <li>Documentei cada conexão em uma tabela, incluindo IPs, portas e números de sequência</li>
                <li>Identifiquei as conexões rejeitadas procurando por pacotes RST logo após os SYNs</li>
            </ol>
        </div>
        """, unsafe_allow_html=True)

# Componente de Laboratório Prático
def practical_lab():
    st.markdown("<h1 class='main-header'>Laboratório Prático de Wireshark</h1>", unsafe_allow_html=True)
    
    # Modos do laboratório
    lab_modes = ["Simulador Wireshark", "Exercícios Práticos", "Análise de Capturas", "Ferramenta de Captura"]
    selected_mode = st.radio("Selecione o modo do laboratório:", lab_modes)
    
    if selected_mode == "Simulador Wireshark":
        wireshark_simulator()
    elif selected_mode == "Exercícios Práticos":
        practical_challenges()
    elif selected_mode == "Análise de Capturas":
        st.markdown("<h2 class='sub-header'>Análise de Capturas PCAP</h2>", unsafe_allow_html=True)
        
        # Upload de arquivo PCAP
        uploaded_file = st.file_uploader("Faça upload de um arquivo PCAP para análise", type=["pcap", "pcapng"])
        
        if uploaded_file is not None:
            # Salva o arquivo temporariamente
            temp_file_path = os.path.join("/tmp", uploaded_file.name)
            with open(temp_file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            
            st.success(f"Arquivo carregado: {uploaded_file.name}")
            
            # Opções de análise
            analysis_options = ["Análise Geral", "Estatísticas", "Extração de Objetos", "Análise de Segurança"]
            selected_analysis = st.selectbox("Selecione o tipo de análise:", analysis_options)
            
            if st.button("Iniciar Análise"):
                with st.spinner("Analisando arquivo PCAP..."):
                    # Carrega o arquivo PCAP
                    df = pcap_to_dataframe(temp_file_path)
                    
                    if df is not None:
                        st.session_state.df = df
                        st.session_state.filtered_df = df
                        
                        # Extrai estatísticas
                        statistics = extract_packet_statistics(df)
                        
                        # Detecta atividades suspeitas
                        suspicious_activities = detect_suspicious_patterns(df)
                        st.session_state.suspicious_activities = suspicious_activities
                        
                        # Exibe resultados conforme o tipo de análise selecionado
                        if selected_analysis == "Análise Geral":
                            st.markdown("<h3>Visão Geral da Captura</h3>", unsafe_allow_html=True)
                            
                            col1, col2, col3 = st.columns(3)
                            
                            with col1:
                                st.metric("Total de Pacotes", statistics["total_packets"])
                            
                            with col2:
                                st.metric("Tamanho Médio", f"{statistics['avg_packet_size']:.2f} bytes")
                            
                            with col3:
                                st.metric("Taxa de Pacotes", f"{statistics['packet_rate']:.2f} pkt/s")
                            
                            # Tabela de pacotes
                            st.markdown("<h3>Lista de Pacotes</h3>", unsafe_allow_html=True)
                            st.dataframe(df.drop(columns=['Raw']), use_container_width=True)
                        
                        elif selected_analysis == "Estatísticas":
                            st.markdown("<h3>Estatísticas da Captura</h3>", unsafe_allow_html=True)
                            
                            # Gera gráficos
                            charts = generate_analysis_charts(df, statistics)
                            
                            # Mostra os gráficos
                            if "protocol_distribution" in charts:
                                st.plotly_chart(charts["protocol_distribution"], use_container_width=True)
                            
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                if "top_sources" in charts:
                                    st.plotly_chart(charts["top_sources"], use_container_width=True)
                            
                            with col2:
                                if "top_destinations" in charts:
                                    st.plotly_chart(charts["top_destinations"], use_container_width=True)
                            
                            if "packets_timeline" in charts:
                                st.plotly_chart(charts["packets_timeline"], use_container_width=True)
                            
                            if "packet_size_distribution" in charts:
                                st.plotly_chart(charts["packet_size_distribution"], use_container_width=True)
                        
                        elif selected_analysis == "Extração de Objetos":
                            st.markdown("<h3>Extração de Objetos</h3>", unsafe_allow_html=True)
                            
                            # Simula extração de objetos
                            st.info("Esta funcionalidade simularia a extração de arquivos e objetos da captura PCAP, como imagens, documentos, etc.")
                            
                            # Exemplo de objetos encontrados
                            example_objects = [
                                {"tipo": "Imagem", "nome": "logo.png", "tamanho": "24KB", "protocolo": "HTTP"},
                                {"tipo": "Documento", "nome": "relatorio.pdf", "tamanho": "156KB", "protocolo": "HTTP"},
                                {"tipo": "Script", "nome": "analytics.js", "tamanho": "45KB", "protocolo": "HTTP"}
                            ]
                            
                            objects_df = pd.DataFrame(example_objects)
                            st.dataframe(objects_df, use_container_width=True)
                            
                            for obj in example_objects:
                                st.download_button(
                                    f"Extrair {obj['nome']}",
                                    data=f"Conteúdo simulado do arquivo {obj['nome']}",
                                    file_name=obj["nome"],
                                    mime="application/octet-stream"
                                )
                        
                        elif selected_analysis == "Análise de Segurança":
                            st.markdown("<h3>Análise de Segurança</h3>", unsafe_allow_html=True)
                            
                            if suspicious_activities:
                                st.warning(f"Encontradas {len(suspicious_activities)} atividades suspeitas!")
                                
                                for activity in suspicious_activities:
                                    severity_color = {
                                        "high": "#ff4444",
                                        "medium": "#ffbb33",
                                        "low": "#33b5e5"
                                    }.get(activity.get("severity", "low"), "#33b5e5")
                                    
                                    st.markdown(
                                        f"<div style='background-color: {severity_color}22; border-left: 5px solid {severity_color}; padding: 15px; margin-bottom: 15px; border-radius: 5px;'>"
                                        f"<h3 style='margin-top: 0; color: {severity_color};'>{activity['type']}</h3>"
                                        f"<p><strong>Detalhes:</strong> {activity['details']}</p>"
                                        f"<p><strong>Severidade:</strong> <span style='color: {severity_color};'>{activity.get('severity', 'baixa').upper()}</span></p>"
                                        f"</div>",
                                        unsafe_allow_html=True
                                    )
                            else:
                                st.success("Nenhuma atividade suspeita detectada na captura atual.")
                    else:
                        st.error("Não foi possível analisar o arquivo PCAP. Verifique se é um arquivo válido.")
            
            # Limpa o arquivo temporário após o uso
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)
    
    elif selected_mode == "Ferramenta de Captura":
        st.markdown("<h2 class='sub-header'>Ferramenta de Captura de Pacotes</h2>", unsafe_allow_html=True)
        
        st.markdown("""
        <div class="highlight">
            <p>Esta seção simula uma ferramenta de captura de pacotes ao vivo. Em um ambiente real, esta ferramenta permitiria capturar pacotes diretamente da interface de rede.</p>
            <p>Por motivos de segurança e limitações técnicas, esta simulação não realiza capturas reais, mas demonstra como seria a interface e o fluxo de trabalho.</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Interface de captura simulada
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("<h3>Configurações de Captura</h3>", unsafe_allow_html=True)
            
            # Seleção de interface (simulada)
            interface = st.selectbox(
                "Interface de Rede:",
                ["eth0 (Ethernet)", "wlan0 (Wi-Fi)", "lo (Loopback)"]
            )
            
            # Filtros de captura
            capture_filter = st.text_input("Filtro de Captura (sintaxe BPF):", 
                                          placeholder="Ex: port 80 or port 443")
            
            # Opções adicionais
            st.checkbox("Resolução de nomes (DNS, portas, etc.)")
            st.checkbox("Capturar em modo promíscuo")
            
            # Limites
            col1_1, col1_2 = st.columns(2)
            
            with col1_1:
                st.number_input("Limite de pacotes:", min_value=0, value=0, 
                               help="0 = sem limite")
            
            with col1_2:
                st.number_input("Limite de tempo (s):", min_value=0, value=0,
                               help="0 = sem limite")
            
            # Botões de controle
            if st.button("Iniciar Captura Simulada"):
                with st.spinner("Capturando pacotes..."):
                    # Simulamos a captura gerando dados aleatórios
                    time.sleep(2)  # Simula um atraso de captura
                    
                    # Gera uma captura simulada
                    simulated_capture = simulate_packet_capture("mixed", 10)
                    st.session_state.df = simulated_capture
                    st.session_state.filtered_df = simulated_capture
                    
                    st.success(f"Captura simulada concluída! {len(simulated_capture)} pacotes capturados.")
        
        with col2:
            st.markdown("<h3>Status da Captura</h3>", unsafe_allow_html=True)
            
            # Estatísticas em tempo real (simuladas)
            if hasattr(st.session_state, 'df') and st.session_state.df is not None:
                statistics = extract_packet_statistics(st.session_state.df)
                
                st.metric("Pacotes Capturados", statistics["total_packets"])
                st.metric("Taxa Média", f"{statistics['packet_rate']:.2f} pkt/s")
                
                # Protocolos capturados
                st.markdown("<h4>Protocolos Capturados</h4>", unsafe_allow_html=True)
                
                protocols_df = pd.DataFrame({
                    'Protocolo': list(statistics["protocols"].keys()),
                    'Quantidade': list(statistics["protocols"].values())
                })
                
                st.dataframe(protocols_df, use_container_width=True)
                
                # Opção para salvar
                if st.button("Salvar Captura"):
                    st.download_button(
                        "Baixar como PCAP",
                        data="Conteúdo simulado do arquivo PCAP",
                        file_name="captura_simulada.pcap",
                        mime="application/octet-stream"
                    )
            else:
                st.info("Nenhuma captura em andamento.")
                
                # Estatísticas simuladas
                st.metric("Pacotes Capturados", 0)
                st.metric("Taxa Média", "0.00 pkt/s")
        
        # Mostra os pacotes capturados (se houver)
        if hasattr(st.session_state, 'df') and st.session_state.df is not None:
            st.markdown("<h3>Pacotes Capturados</h3>", unsafe_allow_html=True)
            
            # Opções de filtro
            display_filter = st.text_input("Filtro de Exibição:", 
                                          placeholder="Ex: http or dns")
            
            # Aplica filtro se fornecido
            if display_filter:
                # Simula a aplicação de filtros (simplificado)
                filtered_df = st.session_state.df[st.session_state.df['Protocol'].str.contains(display_filter, case=False)]
                
                if filtered_df.empty:
                    st.warning(f"Nenhum pacote corresponde ao filtro: {display_filter}")
                else:
                    st.dataframe(filtered_df.drop(columns=['Raw']), use_container_width=True)
            else:
                st.dataframe(st.session_state.df.drop(columns=['Raw']), use_container_width=True)

# Componente de Recursos Educacionais
def educational_resources():
    st.markdown("<h1 class='main-header'>Recursos Educacionais</h1>", unsafe_allow_html=True)
    
    # Abas para diferentes tipos de recursos
    tabs = st.tabs(["Tutoriais em Vídeo", "Artigos", "Ferramentas Complementares", "Glossário", "Perguntas Frequentes"])
    
    # Aba de Tutoriais em Vídeo
    with tabs[0]:
        st.markdown("<h2 class='sub-header'>Tutoriais em Vídeo</h2>", unsafe_allow_html=True)
        
        video_categories = [
            {
                "title": "Fundamentos do Wireshark",
                "videos": [
                    {
                        "title": "Introdução ao Wireshark",
                        "description": "Conceitos básicos, instalação e primeiro uso do Wireshark",
                        "url": "https://www.youtube.com/watch?v=lb1Dw0elw0Q",
                        "duration": "15:22",
                        "level": "Iniciante"
                    },
                    {
                        "title": "Interface do Wireshark em Detalhes",
                        "description": "Explorando todos os componentes da interface do Wireshark",
                        "url": "https://www.youtube.com/watch?v=TkCSr30UojM",
                        "duration": "12:45",
                        "level": "Iniciante"
                    },
                    {
                        "title": "Capturando seu Primeiro Tráfego",
                        "description": "Como iniciar capturas e configurar opções básicas",
                        "url": "https://www.youtube.com/watch?v=4_gustyM9Gs",
                        "duration": "18:10",
                        "level": "Iniciante"
                    }
                ]
            },
            {
                "title": "Análise de Protocolos",
                "videos": [
                    {
                        "title": "Análise de Tráfego HTTP",
                        "description": "Como analisar requisições e respostas HTTP no Wireshark",
                        "url": "https://www.youtube.com/watch?v=0S-ZUUyZhSg",
                        "duration": "22:35",
                        "level": "Intermediário"
                    },
                    {
                        "title": "Entendendo o TCP Handshake",
                        "description": "Análise detalhada do processo de three-way handshake do TCP",
                        "url": "https://www.youtube.com/watch?v=yDDcYRSlrp8",
                        "duration": "16:40",
                        "level": "Intermediário"
                    },
                    {
                        "title": "DNS em Detalhes",
                        "description": "Como funcionam as consultas e respostas DNS",
                        "url": "https://www.youtube.com/watch?v=Gdj_D6_P4HQ",
                        "duration": "19:55",
                        "level": "Intermediário"
                    }
                ]
            },
            {
                "title": "Análise de Segurança",
                "videos": [
                    {
                        "title": "Detectando Port Scanning",
                        "description": "Como identificar diferentes tipos de port scanning com Wireshark",
                        "url": "https://www.youtube.com/watch?v=jU_V4i4TX2g",
                        "duration": "28:15",
                        "level": "Avançado"
                    },
                    {
                        "title": "Analisando Ataques DDoS",
                        "description": "Identificação e análise de diferentes tipos de ataques DDoS",
                        "url": "https://www.youtube.com/watch?v=5K2mnjNnV7A",
                        "duration": "35:22",
                        "level": "Avançado"
                    },
                    {
                        "title": "Detecção de Malware em Tráfego",
                        "description": "Como identificar padrões de comunicação de malware",
                        "url": "https://www.youtube.com/watch?v=Kp5XQbz3IIg",
                        "duration": "42:10",
                        "level": "Especialista"
                    }
                ]
            },
            {
                "title": "Técnicas Avançadas",
                "videos": [
                    {
                        "title": "Filtros Avançados no Wireshark",
                        "description": "Técnicas e sintaxes avançadas para filtros de exibição",
                        "url": "https://www.youtube.com/watch?v=UXAHvwouk6Q",
                        "duration": "25:30",
                        "level": "Avançado"
                    },
                    {
                        "title": "Decodificando Tráfego TLS/SSL",
                        "description": "Como configurar o Wireshark para decodificar tráfego cifrado",
                        "url": "https://www.youtube.com/watch?v=gRcJBCdNbVo",
                        "duration": "31:45",
                        "level": "Especialista"
                    },
                    {
                        "title": "Criando Dissectores Personalizados",
                        "description": "Como criar dissectores para protocolos personalizados usando Lua",
                        "url": "https://www.youtube.com/watch?v=UeAKTjx_eKA",
                        "duration": "48:20",
                        "level": "Especialista"
                    }
                ]
            }
        ]
        
        # Exibição dos vídeos por categoria
        for category in video_categories:
            st.markdown(f"<h3>{category['title']}</h3>", unsafe_allow_html=True)
            
            for video in category['videos']:
                col1, col2, col3 = st.columns([1, 3, 1])
                
                with col1:
                    st.image("https://via.placeholder.com/120x80?text=Video", width=120)
                
                with col2:
                    st.markdown(f"<h4>{video['title']}</h4>", unsafe_allow_html=True)
                    st.markdown(f"{video['description']}")
                    st.markdown(f"<span style='color: #666;'>Duração: {video['duration']} | Nível: {video['level']}</span>", unsafe_allow_html=True)
                
                with col3:
                    st.markdown(f"<div style='margin-top: 20px;'></div>", unsafe_allow_html=True)
                    st.link_button("Assistir", video['url'], use_container_width=True)
            
            st.markdown("<hr>", unsafe_allow_html=True)
    
    # Aba de Artigos
    with tabs[1]:
        st.markdown("<h2 class='sub-header'>Artigos e Guias</h2>", unsafe_allow_html=True)
        
        article_categories = [
            {
                "title": "Fundamentos",
                "articles": [
                    {
                        "title": "Guia Completo do Iniciante em Wireshark",
                        "description": "Um guia completo para quem está começando com análise de pacotes usando Wireshark.",
                        "reading_time": "15 min",
                        "level": "Iniciante"
                    },
                    {
                        "title": "Entendendo Protocolos de Rede com Wireshark",
                        "description": "Aprenda os conceitos básicos de protocolos de rede analisando capturas reais.",
                        "reading_time": "20 min",
                        "level": "Iniciante"
                    },
                    {
                        "title": "Filtros Essenciais para o Dia a Dia",
                        "description": "Uma coleção dos filtros mais úteis para análise de tráfego cotidiana.",
                        "reading_time": "10 min",
                        "level": "Iniciante"
                    }
                ]
            },
            {
                "title": "Análise de Problemas",
                "articles": [
                    {
                        "title": "Troubleshooting de Redes com Wireshark",
                        "description": "Como utilizar o Wireshark para diagnosticar problemas comuns de rede.",
                        "reading_time": "25 min",
                        "level": "Intermediário"
                    },
                    {
                        "title": "Análise de Performance de Aplicações Web",
                        "description": "Técnicas para identificar gargalos de performance em aplicações web.",
                        "reading_time": "30 min",
                        "level": "Intermediário"
                    },
                    {
                        "title": "Resolução de Problemas de VoIP",
                        "description": "Como analisar qualidade e problemas em tráfego de voz sobre IP.",
                        "reading_time": "22 min",
                        "level": "Avançado"
                    }
                ]
            },
            {
                "title": "Segurança",
                "articles": [
                    {
                        "title": "Detecção de Intrusão com Wireshark",
                        "description": "Como identificar sinais de intrusão e atividade maliciosa em sua rede.",
                        "reading_time": "35 min",
                        "level": "Avançado"
                    },
                    {
                        "title": "Análise Forense de Tráfego",
                        "description": "Técnicas forenses para investigação de incidentes de segurança.",
                        "reading_time": "40 min",
                        "level": "Avançado"
                    },
                    {
                        "title": "Reconhecimento de Padrões de Malware",
                        "description": "Como identificar comportamentos típicos de malware em tráfego de rede.",
                        "reading_time": "45 min",
                        "level": "Especialista"
                    }
                ]
            },
            {
                "title": "Técnicas Avançadas",
                "articles": [
                    {
                        "title": "Automação de Análise com Tshark e Python",
                        "description": "Como automatizar tarefas de análise usando Tshark e bibliotecas Python.",
                        "reading_time": "50 min",
                        "level": "Especialista"
                    },
                    {
                        "title": "Desenvolvimento de Dissectores Personalizados",
                        "description": "Guia completo para criar dissectores para protocolos proprietários.",
                        "reading_time": "60 min",
                        "level": "Especialista"
                    },
                    {
                        "title": "Integração do Wireshark com Sistemas de Monitoramento",
                        "description": "Como incorporar análise de pacotes em sistemas de monitoramento contínuo.",
                        "reading_time": "45 min",
                        "level": "Especialista"
                    }
                ]
            }
        ]
        
        # Exibição dos artigos por categoria
        for category in article_categories:
            st.markdown(f"<h3>{category['title']}</h3>", unsafe_allow_html=True)
            
            for article in category['articles']:
                st.markdown(f"""
                <div style='background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 10px;'>
                    <h4 style='margin-top: 0;'>{article['title']}</h4>
                    <p>{article['description']}</p>
                    <p style='color: #666; margin-bottom: 0;'>Tempo de leitura: {article['reading_time']} | Nível: {article['level']}</p>
                    <button style='background-color: #0066cc; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer;'>Ler Artigo</button>
                </div>
                """, unsafe_allow_html=True)
            
            st.markdown("<hr>", unsafe_allow_html=True)
    
    # Aba de Ferramentas Complementares
    with tabs[2]:
        st.markdown("<h2 class='sub-header'>Ferramentas Complementares</h2>", unsafe_allow_html=True)
        
        st.markdown("""
        <p>Além do Wireshark, existem várias ferramentas que podem complementar sua análise de tráfego e segurança de rede. Aqui estão algumas das mais úteis:</p>
        """, unsafe_allow_html=True)
        
        tools = [
            {
                "name": "Tcpdump",
                "description": "Ferramenta de linha de comando para captura e análise de pacotes. Ideal para servidores sem interface gráfica.",
                "category": "Captura de Pacotes",
                "link": "https://www.tcpdump.org/",
                "platform": "Linux, macOS, Unix"
            },
            {
                "name": "TShark",
                "description": "Versão de linha de comando do Wireshark, permitindo captura e análise via scripts e automação.",
                "category": "Captura de Pacotes",
                "link": "https://www.wireshark.org/docs/man-pages/tshark.html",
                "platform": "Windows, Linux, macOS"
            },
            {
                "name": "NetworkMiner",
                "description": "Analisador forense de rede que extrai arquivos, imagens, e-mails e outras informações de capturas PCAP.",
                "category": "Análise Forense",
                "link": "https://www.netresec.com/?page=NetworkMiner",
                "platform": "Windows (.NET)"
            },
            {
                "name": "Zeek (anteriormente Bro)",
                "description": "Sistema de detecção de intrusão baseado em análise de tráfego, focado em segurança e monitoramento.",
                "category": "Segurança",
                "link": "https://zeek.org/",
                "platform": "Linux, macOS, FreeBSD"
            },
            {
                "name": "Suricata",
                "description": "Engine de detecção de ameaças de alta performance, capaz de detecção de intrusão em tempo real.",
                "category": "Segurança",
                "link": "https://suricata.io/",
                "platform": "Multiplataforma"
            },
            {
                "name": "PcapXray",
                "description": "Ferramenta para visualização de tráfego de rede a partir de arquivos PCAP, criando gráficos de interações.",
                "category": "Visualização",
                "link": "https://github.com/Srinivas11789/PcapXray",
                "platform": "Multiplataforma (Python)"
            },
            {
                "name": "Scapy",
                "description": "Biblioteca Python para manipulação de pacotes, permitindo criação, análise e injeção de pacotes.",
                "category": "Desenvolvimento",
                "link": "https://scapy.net/",
                "platform": "Multiplataforma (Python)"
            },
            {
                "name": "Pyshark",
                "description": "Wrapper Python para Tshark, permitindo análise programática de capturas usando Python.",
                "category": "Desenvolvimento",
                "link": "https://github.com/KimiNewt/pyshark",
                "platform": "Multiplataforma (Python)"
            },
            {
                "name": "Moloch (Arkime)",
                "description": "Plataforma de captura e indexação de pacotes em larga escala para análise histórica.",
                "category": "Enterprise",
                "link": "https://arkime.com/",
                "platform": "Linux"
            },
            {
                "name": "ngrep",
                "description": "Ferramenta similar ao grep para padrões de rede, permitindo buscas em conteúdo de pacotes.",
                "category": "Análise",
                "link": "https://github.com/jpr5/ngrep",
                "platform": "Linux, macOS, Windows (Cygwin)"
            }
        ]
        
        # Agrupamento por categoria
        categories = {}
        for tool in tools:
            if tool["category"] not in categories:
                categories[tool["category"]] = []
            categories[tool["category"]].append(tool)
        
        # Exibição das ferramentas por categoria
        for category, tool_list in categories.items():
            st.markdown(f"<h3>{category}</h3>", unsafe_allow_html=True)
            
            for tool in tool_list:
                st.markdown(f"""
                <div style='background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 10px;'>
                    <h4 style='margin-top: 0;'>{tool['name']}</h4>
                    <p>{tool['description']}</p>
                    <p style='color: #666; margin-bottom: 5px;'>Plataforma: {tool['platform']}</p>
                    <a href="{tool['link']}" target="_blank" style='color: #0066cc;'>Site Oficial</a>
                </div>
                """, unsafe_allow_html=True)
            
            st.markdown("<hr>", unsafe_allow_html=True)
    
    # Aba de Glossário
    with tabs[3]:
        st.markdown("<h2 class='sub-header'>Glossário de Termos</h2>", unsafe_allow_html=True)
        
        st.markdown("""
        <p>Este glossário contém termos técnicos relacionados à análise de rede, segurança e Wireshark.</p>
        """, unsafe_allow_html=True)
        
        glossary_items = [
            {
                "term": "ARP (Address Resolution Protocol)",
                "definition": "Protocolo usado para descobrir o endereço MAC (camada 2) associado a um endereço IP (camada 3) dentro de uma rede local."
            },
            {
                "term": "BPF (Berkeley Packet Filter)",
                "definition": "Linguagem de filtros usada para selecionar pacotes para captura. É utilizada nos filtros de captura do Wireshark e tcpdump."
            },
            {
                "term": "DHCP (Dynamic Host Configuration Protocol)",
                "definition": "Protocolo que atribui automaticamente endereços IP e outras configurações de rede a dispositivos em uma rede."
            },
            {
                "term": "DNS (Domain Name System)",
                "definition": "Sistema que traduz nomes de domínio legíveis (como example.com) em endereços IP numéricos usados pelos computadores."
            },
            {
                "term": "Dissector",
                "definition": "No Wireshark, é o componente que analisa e interpreta um protocolo específico, extraindo informações dos pacotes."
            },
            {
                "term": "Encapsulamento",
                "definition": "Processo de incluir os dados de um protocolo dentro de outro, seguindo o modelo de camadas OSI ou TCP/IP."
            },
            {
                "term": "Filtro de Captura",
                "definition": "Expressão usada para limitar quais pacotes são capturados pelo Wireshark, aplicada antes da captura."
            },
            {
                "term": "Filtro de Exibição",
                "definition": "Expressão usada para filtrar quais pacotes já capturados são exibidos na interface do Wireshark."
            },
            {
                "term": "Handshake",
                "definition": "Processo de estabelecimento de conexão entre dois dispositivos, tipicamente envolvendo troca de parâmetros e sincronização."
            },
            {
                "term": "HTTP (Hypertext Transfer Protocol)",
                "definition": "Protocolo de aplicação usado para transferência de hipertexto na web, base para comunicação de dados na WWW."
            },
            {
                "term": "ICMP (Internet Control Message Protocol)",
                "definition": "Protocolo usado para enviar mensagens de erro e operacionais, como o comando ping."
            },
            {
                "term": "IP (Internet Protocol)",
                "definition": "Protocolo principal da camada de rede, responsável pelo endereçamento e roteamento de pacotes entre redes."
            },
            {
                "term": "Jitter",
                "definition": "Variação no tempo de chegada dos pacotes, importante em aplicações de tempo real como VoIP e streaming."
            },
            {
                "term": "MAC Address (Media Access Control)",
                "definition": "Identificador único de hardware atribuído a interfaces de rede, usado na camada de enlace de dados."
            },
            {
                "term": "MTU (Maximum Transmission Unit)",
                "definition": "Tamanho máximo (em bytes) de um pacote que pode ser transmitido em uma rede sem fragmentação."
            },
            {
                "term": "PCAP (Packet Capture)",
                "definition": "Formato de arquivo usado para armazenar dados de pacotes capturados, utilizado pelo Wireshark e outras ferramentas."
            },
            {
                "term": "Promiscuous Mode",
                "definition": "Modo de operação que permite a uma interface de rede capturar todos os pacotes, mesmo aqueles não destinados a ela."
            },
            {
                "term": "Port Scanning",
                "definition": "Técnica usada para identificar portas abertas em um sistema, frequentemente como precursor de ataques."
            },
            {
                "term": "Retransmissão",
                "definition": "Reenvio de pacotes TCP que não foram reconhecidos pelo destinatário, indicando possível perda ou corrupção."
            },
            {
                "term": "RTT (Round-Trip Time)",
                "definition": "Tempo necessário para um pacote ir do remetente para o destinatário e voltar, medida importante de latência."
            },
            {
                "term": "SYN Flood",
                "definition": "Tipo de ataque DoS que envia grande número de pacotes TCP SYN sem completar o handshake, esgotando recursos do servidor."
            },
            {
                "term": "TCP (Transmission Control Protocol)",
                "definition": "Protocolo de transporte orientado a conexão que garante entrega confiável e ordenada de dados."
            },
            {
                "term": "Three-Way Handshake",
                "definition": "Processo de três etapas (SYN, SYN-ACK, ACK) usado pelo TCP para estabelecer uma conexão."
            },
            {
                "term": "TLS/SSL (Transport Layer Security)",
                "definition": "Protocolos criptográficos que proporcionam comunicações seguras em uma rede de computadores."
            },
            {
                "term": "TTL (Time To Live)",
                "definition": "Campo em pacotes IP que limita seu tempo de vida na rede, decrementado a cada roteador por onde passa."
            },
            {
                "term": "UDP (User Datagram Protocol)",
                "definition": "Protocolo de transporte sem conexão que não garante entrega, sequência ou proteção contra duplicação."
            },
            {
                "term": "VLAN (Virtual Local Area Network)",
                "definition": "Tecnologia que segmenta logicamente uma rede física em múltiplas redes virtuais isoladas."
            }
        ]
        
        # Ordenação alfabética
        glossary_items.sort(key=lambda x: x["term"])
        
        # Criação de um índice alfabético
        letters = sorted(set(item["term"][0].upper() for item in glossary_items))
        letter_index = " | ".join([f"<a href='#{letter}' style='text-decoration: none;'>{letter}</a>" for letter in letters])
        
        st.markdown(f"<div style='text-align: center; font-size: 1.2em; margin-bottom: 20px;'>{letter_index}</div>", unsafe_allow_html=True)
        
        # Exibição dos termos agrupados por letra inicial
        current_letter = None
        for item in glossary_items:
            first_letter = item["term"][0].upper()
            
            if first_letter != current_letter:
                current_letter = first_letter
                st.markdown(f"<h3 id='{current_letter}'>{current_letter}</h3>", unsafe_allow_html=True)
            
            st.markdown(f"""
            <div style='margin-bottom: 15px;'>
                <strong>{item['term']}</strong>: {item['definition']}
            </div>
            """, unsafe_allow_html=True)
    
    # Aba de Perguntas Frequentes
    with tabs[4]:
        st.markdown("<h2 class='sub-header'>Perguntas Frequentes</h2>", unsafe_allow_html=True)
        
        faqs = [
            {
                "question": "O que é o Wireshark e para que serve?",
                "answer": "O Wireshark é um analisador de protocolo de rede gratuito e de código aberto, utilizado para capturar, examinar e analisar pacotes de dados em uma rede. É uma ferramenta essencial para profissionais de rede, administradores de sistemas, engenheiros de segurança e desenvolvedores que precisam diagnosticar problemas de rede, analisar comportamentos de aplicações, identificar problemas de segurança ou simplesmente aprender sobre protocolos de rede."
            },
            {
                "question": "Quais são os requisitos para instalar o Wireshark?",
                "answer": "O Wireshark está disponível para Windows, macOS e Linux. Os requisitos básicos incluem:\n\n- Windows: Windows 10 ou posterior (32 ou 64 bits)\n- macOS: macOS 10.13 ou posterior\n- Linux: Distribuição moderna com bibliotecas Qt\n\nPara capturar pacotes, você precisará de privilégios administrativos e, no caso do Windows, do driver Npcap ou WinPcap instalado. No Linux e macOS, às vezes é necessário configurar permissões específicas para usuários sem privilégios de root."
            },
            {
                "question": "Por que não consigo ver tráfego HTTP no Wireshark ao visitar sites HTTPS?",
                "answer": "A maioria dos sites hoje utiliza HTTPS (HTTP sobre TLS/SSL), que criptografa o tráfego entre o navegador e o servidor web. No Wireshark, você verá este tráfego como TLS ou SSL, não como HTTP. O conteúdo dos pacotes aparecerá cifrado.\n\nPara decifrar este tráfego, você precisaria de uma das seguintes opções:\n\n1. Configurar seu navegador para exportar as chaves de sessão TLS e configurar o Wireshark para usá-las\n2. Se você controla o servidor, exportar as chaves privadas RSA (apenas para versões antigas de TLS)\n3. Configurar um proxy HTTPS intermediário para realizar MITM (man-in-the-middle) legal em sua própria rede"
            },
            {
                "question": "Quais são os filtros mais úteis no Wireshark?",
                "answer": "Alguns dos filtros mais comumente utilizados incluem:\n\n- `ip.addr == 192.168.1.1` - Tráfego de/para um IP específico\n- `http` ou `dns` ou `tcp` - Filtrar por protocolo\n- `tcp.port == 80` - Tráfego TCP em uma porta específica\n- `http.request.method == \"GET\"` - Requisições HTTP GET\n- `tcp.flags.syn == 1` - Pacotes SYN do TCP\n- `icmp` - Todos os pacotes ICMP (ping)\n- `!(arp or dns)` - Exclui tráfego ARP e DNS\n\nVocê pode combinar filtros com operadores lógicos como `and`, `or` e `not`."
            },
            {
                "question": "É legal usar o Wireshark em qualquer rede?",
                "answer": "Não. Embora o Wireshark seja uma ferramenta legítima para análise de rede, seu uso deve respeitar questões legais e éticas:\n\n1. É geralmente permitido capturar tráfego em sua própria rede ou em redes em que você tenha autorização explícita\n2. É ilegal em muitos países capturar tráfego em redes públicas ou privadas sem autorização\n3. Muitas empresas têm políticas que proíbem o uso de ferramentas de captura de pacotes sem aprovação prévia\n4. Capturar comunicações de terceiros pode violar leis de privacidade e interceptação\n\nConsulte sempre as leis locais e obtenha as autorizações necessárias antes de usar o Wireshark em qualquer ambiente."
            },
            {
                "question": "Como posso identificar problemas de performance de rede com o Wireshark?",
                "answer": "Para diagnosticar problemas de performance, procure por:\n\n1. Retransmissões TCP - Use o filtro `tcp.analysis.retransmission` para identificar pacotes perdidos\n2. Latência alta - Analise tempos de resposta usando os gráficos de Round-Trip Time (Statistics > TCP Stream Graph > Round Trip Time)\n3. Fragmentação - Procure por pacotes IP fragmentados com `ip.flags.mf == 1 or ip.frag_offset > 0`\n4. Janelas de congestionamento - Observe reduções nos tamanhos de janela TCP\n5. Timeouts - Procure por longos intervalos entre solicitações e respostas\n\nTambém é útil analisar estatísticas com Statistics > I/O Graph para visualizar variações no volume de tráfego ao longo do tempo."
            },
            {
                "question": "O Wireshark consome muitos recursos do sistema?",
                "answer": "O Wireshark pode consumir recursos significativos do sistema, especialmente em redes de alto volume ou ao abrir capturas muito grandes. Para otimizar o desempenho:\n\n1. Use filtros de captura para limitar o que é capturado inicialmente\n2. Evite capturar em interfaces de alto tráfego por longos períodos\n3. Divida capturas grandes em arquivos menores (File > Export Specified Packets)\n4. Desative a resolução de nomes (nome de hosts, portas, etc.) para captura mais rápida\n5. Em sistemas com recursos limitados, considere usar tshark (versão de linha de comando) em vez da interface gráfica\n\nPara capturas muito grandes, ferramentas complementares como mergecap (para dividir/mesclar capturas) podem ser úteis."
            },
            {
                "question": "Como posso aprender mais sobre análise de protocolos específicos?",
                "answer": "Para aprofundar seu conhecimento em protocolos específicos:\n\n1. Consulte a documentação oficial do Wireshark para o protocolo em questão\n2. Estude as RFCs (Request for Comments) que definem o protocolo\n3. Crie capturas controladas focadas no protocolo específico\n4. Examine os campos do protocolo em detalhes no painel do Wireshark\n5. Procure por webinars e cursos especializados no protocolo\n6. Participe de comunidades como o fórum do Wireshark ou StackExchange\n\nUma técnica eficaz é gerar tráfego do protocolo em um ambiente de teste e analisá-lo pacote por pacote para entender seu funcionamento."
            },
            {
                "question": "O Wireshark pode detectar invasões ou malware?",
                "answer": "O Wireshark por si só não é uma ferramenta de detecção de intrusão, mas pode ser utilizado para analisar evidências de atividades maliciosas:\n\n1. Pode identificar padrões de tráfego anômalos, como port scanning ou comunicações não autorizadas\n2. Permite verificar comunicações com IPs ou domínios conhecidamente maliciosos\n3. Pode revelar padrões de beaconing (comunicações regulares com servidores C2)\n4. Possibilita a inspeção de payloads suspeitos em pacotes\n\nPara detecção de intrusão em tempo real, ferramentas como IDS/IPS (Snort, Suricata) são mais apropriadas. O Wireshark é melhor para análise forense pós-evento ou investigação de comportamentos suspeitos específicos."
            },
            {
                "question": "Como posso compartilhar capturas PCAP de forma segura?",
                "answer": "Ao compartilhar capturas PCAP, considere:\n\n1. Privacidade - As capturas podem conter dados sensíveis como credenciais, cookies, endereços IP internos, etc.\n2. Sanitização - Use ferramentas como TraceWrangler ou editcap para anonimizar IPs e outras informações sensíveis\n3. Redação - Utilize funcionalidades como File > Export Specified Packets para incluir apenas pacotes relevantes\n4. Segurança - Compartilhe arquivos por canais seguros, considere criptografá-los\n\nPara fins educacionais, você pode usar capturas públicas disponíveis em sites como packetlife.net ou wireshark.org, que já foram sanitizadas para remoção de informações sensíveis."
            },
            {
                "question": "Qual é a diferença entre Wireshark e outras ferramentas de captura como tcpdump?",
                "answer": "As principais diferenças incluem:\n\n1. Interface - Wireshark oferece uma GUI completa, enquanto tcpdump é uma ferramenta de linha de comando\n2. Análise em tempo real - Wireshark possui recursos de decodificação e visualização em tempo real mais ricos\n3. Plataformas - tcpdump é nativo em sistemas Unix/Linux, enquanto Wireshark é multiplataforma\n4. Recursos - Wireshark oferece recursos avançados como gráficos, estatísticas, extração de objetos, etc.\n5. Performance - tcpdump geralmente consome menos recursos, sendo ideal para sistemas com limitações\n\nO Wireshark e tcpdump são complementares: tcpdump é excelente para captura rápida em servidores remotos ou sistemas com recursos limitados, enquanto Wireshark é superior para análise detalhada e visualização."
            }
        ]
        
        # Exibição das perguntas e respostas
        for i, faq in enumerate(faqs):
            with st.expander(faq["question"]):
                st.markdown(faq["answer"])

# Componente principal
def main():
    # Configuração inicial
    st.set_page_config(
        page_title="CyberLab Wireshark",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Carrega CSS personalizado
    st.markdown("""
    <style>
        .main-header {
            font-size: 2.5rem;
            color: #0066cc;
            text-align: center;
            margin-bottom: 1rem;
        }
        .sub-header {
            font-size: 1.8rem;
            color: #004d99;
            margin-top: 2rem;
            margin-bottom: 1rem;
        }
        .highlight {
            background-color: #f0f8ff;
            padding: 1rem;
            border-radius: 5px;
            border-left: 5px solid #0066cc;
        }
        .code-block {
            background-color: #f5f5f5;
            padding: 1rem;
            border-radius: 5px;
            font-family: monospace;
        }
        .success-box {
            background-color: #d4edda;
            color: #155724;
            padding: 1rem;
            border-radius: 5px;
            border-left: 5px solid #155724;
        }
        .warning-box {
            background-color: #fff3cd;
            color: #856404;
            padding: 1rem;
            border-radius: 5px;
            border-left: 5px solid #856404;
        }
        .danger-box {
            background-color: #f8d7da;
            color: #721c24;
            padding: 1rem;
            border-radius: 5px;
            border-left: 5px solid #721c24;
        }
        .terminal {
            background-color: #000;
            color: #00ff00;
            padding: 1rem;
            border-radius: 5px;
            font-family: monospace;
        }
        .challenge-card {
            background-color: #e6f7ff;
            padding: 1.5rem;
            border-radius: 10px;
            margin-bottom: 1rem;
            border: 1px solid #91d5ff;
        }
        .sidebar .sidebar-content {
            background-color: #f8f9fa;
        }
        .packet-row {
            cursor: pointer;
            transition: background-color 0.2s;
        }
        .packet-row:hover {
            background-color: #e6f7ff;
        }
        .packet-details {
            font-family: monospace;
            white-space: pre-wrap;
            background-color: #f5f5f5;
            padding: 10px;
            border-radius: 5px;
        }
        .nav-link {
            text-decoration: none;
            color: #0066cc;
            font-weight: bold;
            padding: 0.5rem;
            margin: 0.2rem;
            border-radius: 5px;
        }
        .nav-link:hover {
            background-color: #e6f7ff;
        }
        .progress-container {
            margin-top: 1rem;
            margin-bottom: 1rem;
        }
        .footer {
            text-align: center;
            margin-top: 3rem;
            padding: 1rem;
            background-color: #f8f9fa;
            border-radius: 5px;
        }
    </style>
    """, unsafe_allow_html=True)
    
    # Sidebar para navegação
    with st.sidebar:
        st.image("https://www.wireshark.org/assets/images/wireshark-logo.png", width=200)
        st.markdown("<h1 style='text-align: center;'>CyberLab Wireshark</h1>", unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Opções de navegação
        menu_options = [
            "Início",
            "Laboratório Prático",
            "Tutorial Interativo",
            "Roadmap de Estudos",
            "Desafios Práticos",
            "Recursos Educacionais"
        ]
        
        selection = st.radio("Navegação", menu_options)
        
        st.markdown("---")
        
        # Acompanhamento de progresso
        if st.checkbox("Habilitar acompanhamento de progresso"):
            st.markdown("<h3>Seu Progresso</h3>", unsafe_allow_html=True)
            
            # Simulação de progresso
            progress_areas = {
                "Fundamentos": 75,
                "Análise de Protocolos": 50,
                "Troubleshooting": 30,
                "Segurança": 25,
                "Técnicas Avançadas": 10
            }
            
            for area, progress in progress_areas.items():
                st.markdown(f"**{area}**")
                st.progress(progress / 100)
        
        st.markdown("---")
        
        # Links úteis
        st.markdown("<h3>Links Úteis</h3>", unsafe_allow_html=True)
        st.markdown("[Site Oficial do Wireshark](https://www.wireshark.org/)")
        st.markdown("[Documentação](https://www.wireshark.org/docs/)")
        st.markdown("[Wiki do Wireshark](https://wiki.wireshark.org/)")
        st.markdown("[Comunidade](https://ask.wireshark.org/)")
    
    # Conteúdo principal
    if selection == "Início":
        st.markdown("<h1 class='main-header'>Laboratório Web de Cibersegurança com Wireshark</h1>", unsafe_allow_html=True)
        
        st.markdown("""
        <div class="highlight">
            <p>Bem-vindo ao CyberLab Wireshark, sua plataforma completa para aprender análise de tráfego de rede e segurança com Wireshark. Este laboratório interativo foi projetado para estudantes e profissionais de segurança da informação, combinando teoria e prática.</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Visão geral das funcionalidades
        st.markdown("<h2 class='sub-header'>O que você encontrará neste laboratório:</h2>", unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            <h3>🔬 Laboratório Prático</h3>
            <ul>
                <li>Simulador interativo do Wireshark</li>
                <li>Análise de capturas PCAP reais</li>
                <li>Detecção de atividades suspeitas</li>
                <li>Geração de relatórios de análise</li>
            </ul>
            
            <h3>📚 Tutorial Interativo</h3>
            <ul>
                <li>Guia passo a passo sobre o Wireshark</li>
                <li>Explicações detalhadas de cada recurso</li>
                <li>Exemplos práticos e casos de uso</li>
                <li>Material adaptado a diferentes níveis</li>
            </ul>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <h3>🏆 Desafios Práticos</h3>
            <ul>
                <li>Desafios de análise de tráfego</li>
                <li>Investigações de segurança simuladas</li>
                <li>Exercícios de troubleshooting</li>
                <li>Cenários de forense digital</li>
            </ul>
            
            <h3>🛣️ Roadmap de Estudos</h3>
            <ul>
                <li>Caminho de aprendizado estruturado</li>
                <li>Progressão do básico ao avançado</li>
                <li>Certificações recomendadas</li>
                <li>Recursos de aprendizado complementares</li>
            </ul>
            """, unsafe_allow_html=True)
        
        # Benefícios do laboratório
        st.markdown("<h2 class='sub-header'>Benefícios deste Laboratório Web:</h2>", unsafe_allow_html=True)
        
        st.markdown("""
        <div class="highlight">
            <ul>
                <li><strong>Aprendizado Prático</strong>: Experimente com pacotes reais sem necessidade de configurar um ambiente complexo</li>
                <li><strong>Acessibilidade</strong>: Estude e pratique em qualquer dispositivo com acesso à web</li>
                <li><strong>Conteúdo Abrangente</strong>: Desde conceitos básicos até técnicas avançadas de análise</li>
                <li><strong>Foco em Segurança</strong>: Aprenda a detectar ameaças, investigar incidentes e proteger redes</li>
                <li><strong>Atualização Constante</strong>: Conteúdo renovado regularmente para refletir novas ameaças e técnicas</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        
        # Para quem se destina
        st.markdown("<h2 class='sub-header'>Para quem é este laboratório?</h2>", unsafe_allow_html=True)
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            <div class="success-box">
                <h3>Estudantes</h3>
                <p>Complemento ideal para cursos de segurança da informação, redes de computadores e sistemas de informação.</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="warning-box">
                <h3>Profissionais de TI</h3>
                <p>Aperfeiçoe suas habilidades de análise de rede, troubleshooting e detecção de ameaças.</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown("""
            <div class="danger-box">
                <h3>Especialistas em Segurança</h3>
                <p>Refine suas técnicas de investigação forense digital e análise de ameaças.</p>
            </div>
            """, unsafe_allow_html=True)
        
        # Como começar
        st.markdown("<h2 class='sub-header'>Como começar:</h2>", unsafe_allow_html=True)
        
        st.markdown("""
        <ol>
            <li>Explore o <strong>Tutorial Interativo</strong> para aprender os fundamentos do Wireshark</li>
            <li>Siga o <strong>Roadmap de Estudos</strong> para um aprendizado estruturado</li>
            <li>Pratique no <strong>Laboratório</strong> com exemplos reais de tráfego</li>
            <li>Teste suas habilidades com os <strong>Desafios Práticos</strong></li>
            <li>Consulte os <strong>Recursos Educacionais</strong> para aprofundar seus conhecimentos</li>
        </ol>
        """, unsafe_allow_html=True)
        
        # Rodapé
        st.markdown("""
        <div class="footer">
            <p>CyberLab Wireshark - Laboratório Web de Cibersegurança</p>
            <p><small>Desenvolvido para fins educacionais</small></p>
        </div>
        """, unsafe_allow_html=True)
    
    elif selection == "Laboratório Prático":
        practical_lab()
    
    elif selection == "Tutorial Interativo":
        interactive_tutorial()
    
    elif selection == "Roadmap de Estudos":
        study_roadmap()
    
    elif selection == "Desafios Práticos":
        practical_challenges()
    
    elif selection == "Recursos Educacionais":
        educational_resources()

if __name__ == "__main__":
    main()