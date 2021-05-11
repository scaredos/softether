import softetherapi

# Define client with IP, port, username (hubname), and password
client = softetherapi.SoftEtherAPI(ip='0.0.0.0', port=443, hubname="VPN", password='Password')

if client.authenticate():
    print("Successful Login")

    print(client.getServerCert())
    print(client.getServerInfo())

else:
    print("Login Failed!")
    exit(-1)
