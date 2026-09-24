import socket


def resolve_hostname_ips(hostname):
    try:
        _, _, ip_list = socket.gethostbyname_ex(hostname)
        return sorted(set(ip_list))
    except socket.gaierror:
        return []
