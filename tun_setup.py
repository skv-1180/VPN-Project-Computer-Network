from pyroute2 import IPRoute

def create_tun_interface(name='tun0', ip_address='10.0.0.1'):
    ip = IPRoute()
    
    # Create a TUN interface
    ip.link('add', ifname=name, kind='tun')
    # Bring the interface up
    ip.link('set', index=ip.link_lookup(ifname=name)[0], state='up')
    print(f"{name} interface created and brought up.")
    
    # Set an IP address for the TUN interface
    ip.addr('add', index=ip.link_lookup(ifname=name)[0], address=ip_address, prefixlen=24)
    print(f"IP address {ip_address} set for {name}")

def add_route(vpn_ip, tun_interface):
    ip = IPRoute()
    # Add a route for the VPN IP
    ip.route('add', dst=vpn_ip, oif=ip.link_lookup(ifname=tun_interface)[0])
    print(f"Route added for {vpn_ip} through {tun_interface}")

if __name__ == "__main__":
    create_tun_interface()
    add_route('0.0.0.0/0', 'tun0')  # Route all traffic through the VPN
