import socket

def get_local_ip():
    try:
        # Create a socket to get the local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Connect to Google DNS
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "Unable to determine local IP"

if __name__ == "__main__":
    ip = get_local_ip()
    print(f"Your local IP address is: {ip}")
    print(f"Share this URL with friends on your network: http://{ip}:5000")