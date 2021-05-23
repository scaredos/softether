import softetherapi

# Define client with IP, port, username (hubname), and password
client = softetherapi.SoftEtherAPI(
    ip='0.0.0.0', port=443, hubname="VPN", password='Password')

# authenticate() returns boolean based on status of authorization
if client.authenticate():
    print("Successful Login")

    # Example functions
    print(client.get_server_cert())
    print(client.get_server_info())

else:
    # Exit if not authenticated
    print("Login Failed!")
    exit(-1)
