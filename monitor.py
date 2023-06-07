import os, re, time, netifaces, fcntl, socket, struct, sys

arp_table = {}
blacklist = []

def get_mac(interface):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytes(interface, 'utf-8')[:15]))
		return ':'.join('%02x' % b for b in info[18:24])
	except:
		return 'error'
		
def block_host(mac):
	cmd = "sudo iptables -A INPUT -m mac --mac-source "+mac+" -j DROP"
	os.system(cmd)
	cmd = "sudo service iptables start"
	os.system(cmd)
	blacklist.append(mac)
	print("The host with MAC "+mac+" has blocked!")
	
def calc_time(interface, mac_attacker):
	mac = get_mac(interface)
	total_times_interval = 0.0
	previous_time = 0.0
	interval = 0.0
	qt_interval = -1
	if mac != 'error':
		cmd = "sudo tshark -i 1 -c 10 -f \"arp and ether src "+mac_attacker+" and ether dst "+mac+"\" -Y \"arp.opcode==2\" > packages.txt"
		os.system(cmd)
		with open('packages.txt') as arq:
			l = arq.readlines()
		time = re.compile(r'(\d+\.\d{1,9})')
		for line in l:
			if time.search(line)[0]:
				interval = float(time.search(line)[0]) - previous_time
				previous_time = float(time.search(line)[0])
				total_times_interval += interval
				qt_interval +=1
		return (total_times_interval/qt_interval)
	else:
		print("Erro, interface Inválida!")
		

def mac_changed(interface):
    cmd = "arp -an > arp_table.txt"    
    os.system(cmd)
    gws = netifaces.gateways()
    gateway = gws['default'][netifaces.AF_INET][0]
    
    with open('arp_table.txt') as arq:
    	l = arq.readlines()
    ip = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    mac = re.compile('(([0-9a-fA-F]{2}[:]){5}([0-9a-fA-F]{2})|([0-9a-fA-F]{2}[-]){5}([0-9a-fA-F]{2})|[0-9a-fA-F]{12})')

    for line in l:
    	if ip.search(line)[0] not in arp_table:
    		if ip.search(line)[0] == gateway:
    			arp_table[ip.search(line)[0]] = [mac.search(line)[0], 10]
    		else:
    			arp_table[ip.search(line)[0]] = [mac.search(line)[0], 1]
    	else:
    		if (arp_table[ip.search(line)[0]][0] != mac.search(line)[0]) and (mac.search(line)[0] not in blacklist):
    			time = calc_time(interface, mac.search(line)[0])
    			if arp_table[ip.search(line)[0]][1] == 1:
    				if time <= 1.0:
    					print("The IP " + ip.search(line)[0] + " changed from MAC " + arp_table[ip.search(line)[0]][0] + " to " + mac.search(line)[0] + " using Websploit Framework")
    					block_host(mac.search(line)[0])
    				elif time > 1.0 and time <= 11.0:
    					print("The IP " + ip.search(line)[0] + " changed from MAC " + arp_table[ip.search(line)[0]][0] + " to " + mac.search(line)[0] + " using Ettercap")
    					block_host(mac.search(line)[0])
    			else:
    				if time <= 1.0:
    					print("The GATEWAY MAC changed from " + arp_table[ip.search(line)[0]][0] + " to " + mac.search(line)[0] + " using Websploit Framework")
    					block_host(mac.search(line)[0])
    				elif time > 1.0 and time <= 11.0:
    					print("The GATEWAY MAC changed from " + arp_table[ip.search(line)[0]][0] + " to " + mac.search(line)[0] + " using Ettercap")
    					block_host(mac.search(line)[0])
    			

def main():
	argc = len(sys.argv)
	if(argc != 2):
		print("Erro, informe a interface de rede a ser monitorada via linha de comando!")
	else:	
		if(get_mac(sys.argv[1]) == 'error'):
			print("Por favor, informe uma interface de rede válida!")
		else:	    			
			while True:
				mac_changed(sys.argv[1])
				time.sleep(1)
			
if __name__ == "__main__":
	main()
