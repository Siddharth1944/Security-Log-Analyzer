import ipaddress

def validate_ip(ip):

    try:
        ipaddress.ip_address(ip)
        return True

    except ValueError:
        return False


user_ip = input("Enter IP address: ")

if validate_ip(user_ip):
    print("Valid IP address")
else:
    print("Invalid IP address")