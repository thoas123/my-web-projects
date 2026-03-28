import requests

def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        data = response.json()
        return data['ip']
    except Exception as e:
        print(f"Error getting public IP: {e}")
        return None

if __name__ == "__main__":
    ip = get_public_ip()
    if ip:
        print(f"Your public IP address is: {ip}")
        print(f"For global access, set up port forwarding and share: http://{ip}:5000")
        print("⚠️  WARNING: This will expose your app to the internet!")
        print("   Make sure to add authentication and use HTTPS in production.")
    else:
        print("Could not retrieve public IP. Check your internet connection.")