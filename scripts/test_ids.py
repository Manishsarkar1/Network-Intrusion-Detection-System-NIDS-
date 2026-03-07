#!/usr/bin/env python3
"""
IDS Testing Script
Generates various types of network traffic to test detection capabilities
⚠️ USE ONLY ON NETWORKS YOU OWN OR HAVE PERMISSION TO TEST
"""

import sys
import time
from scapy.all import *

def print_banner():
    print("=" * 60)
    print("          NIDS Testing Script")
    print("=" * 60)
    print("⚠️  WARNING: Use only on authorized networks!")
    print("=" * 60)
    print()

def get_target():
    target = input("Enter target IP address (e.g., 192.168.1.1): ").strip()
    if not target:
        print("❌ No target specified!")
        sys.exit(1)
    return target

def test_syn_scan(target, num_ports=15):
    """Test SYN port scan detection"""
    print(f"\n[1] Testing SYN Scan Detection")
    print(f"   Scanning {num_ports} ports on {target}...")
    
    ports = random.sample(range(1, 1000), num_ports)
    
    for port in ports:
        # Send SYN packet
        ip = IP(dst=target)
        syn = TCP(dport=port, flags='S')
        send(ip/syn, verbose=0)
        time.sleep(0.1)
    
    print(f"   ✓ Sent SYN packets to {num_ports} ports")
    print(f"   Expected: SYN port scan alert")

def test_icmp_flood(target, num_packets=60):
    """Test ICMP flood detection"""
    print(f"\n[2] Testing ICMP Flood Detection")
    print(f"   Sending {num_packets} ICMP packets to {target}...")
    
    for i in range(num_packets):
        send(IP(dst=target)/ICMP(), verbose=0)
    
    print(f"   ✓ Sent {num_packets} ICMP packets")
    print(f"   Expected: ICMP flood alert")

def test_udp_flood(target, num_packets=250):
    """Test UDP flood detection"""
    print(f"\n[3] Testing UDP Flood Detection")
    print(f"   Sending {num_packets} UDP packets to {target}...")
    
    for i in range(num_packets):
        port = random.randint(1000, 9999)
        send(IP(dst=target)/UDP(dport=port), verbose=0)
    
    print(f"   ✓ Sent {num_packets} UDP packets")
    print(f"   Expected: UDP flood alert")

def test_ssh_bruteforce(target, num_attempts=8):
    """Test SSH brute force detection"""
    print(f"\n[4] Testing SSH Brute Force Detection")
    print(f"   Simulating {num_attempts} SSH connection attempts to {target}...")
    
    for i in range(num_attempts):
        # Send SYN to SSH port
        send(IP(dst=target)/TCP(dport=22, flags='S'), verbose=0)
        time.sleep(0.5)
    
    print(f"   ✓ Sent {num_attempts} SSH connection attempts")
    print(f"   Expected: SSH brute force alert")

def test_vnc_bruteforce(target, num_attempts=8):
    """Test VNC brute force detection"""
    print(f"\n[5] Testing VNC Brute Force Detection")
    print(f"   Simulating {num_attempts} VNC connection attempts to {target}...")
    
    for i in range(num_attempts):
        # Send SYN to VNC port
        send(IP(dst=target)/TCP(dport=5900, flags='S'), verbose=0)
        time.sleep(0.5)
    
    print(f"   ✓ Sent {num_attempts} VNC connection attempts")
    print(f"   Expected: VNC brute force alert")

def test_arp_scan(interface=None):
    """Test ARP scanning (not poisoning, but generates ARP traffic)"""
    print(f"\n[6] Testing ARP Traffic Generation")
    print(f"   Note: ARP poisoning requires spoofing, which is more complex")
    print(f"   This test only generates legitimate ARP requests")
    
    if interface:
        print(f"   Sending ARP requests on {interface}...")
        # Send ARP who-has requests
        for i in range(10):
            fake_ip = f"192.168.1.{random.randint(1, 254)}"
            send(ARP(pdst=fake_ip), iface=interface, verbose=0)
            time.sleep(0.1)
        print(f"   ✓ Sent ARP requests")
    else:
        print(f"   ⚠️  Skipping (requires interface specification)")

def run_all_tests(target, interface=None):
    """Run all IDS tests"""
    print("\n" + "=" * 60)
    print("Running all tests...")
    print("=" * 60)
    
    try:
        test_syn_scan(target)
        time.sleep(2)
        
        test_icmp_flood(target)
        time.sleep(2)
        
        test_udp_flood(target)
        time.sleep(2)
        
        test_ssh_bruteforce(target)
        time.sleep(2)
        
        test_vnc_bruteforce(target)
        time.sleep(2)
        
        test_arp_scan(interface)
        
        print("\n" + "=" * 60)
        print("✓ All tests completed!")
        print("=" * 60)
        print("\nCheck your NIDS interface for alerts.")
        print("You should see multiple security alerts for each test.")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrupted by user")
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")

def main():
    print_banner()
    
    # Check for root/admin privileges
    if os.geteuid() != 0:
        print("❌ This script requires root/administrator privileges!")
        print("   Linux/macOS: sudo python3 test_ids.py")
        print("   Windows: Run as Administrator")
        sys.exit(1)
    
    print("Select test mode:")
    print("1. Run all tests")
    print("2. SYN scan test")
    print("3. ICMP flood test")
    print("4. UDP flood test")
    print("5. SSH brute force test")
    print("6. VNC brute force test")
    print("7. ARP traffic test")
    print()
    
    choice = input("Enter choice (1-7): ").strip()
    
    if choice not in ['1', '2', '3', '4', '5', '6', '7']:
        print("❌ Invalid choice!")
        sys.exit(1)
    
    target = get_target()
    
    # Confirm before proceeding
    print(f"\n⚠️  You are about to generate test traffic to {target}")
    confirm = input("Do you have permission to test this target? (yes/no): ").strip().lower()
    
    if confirm != 'yes':
        print("❌ Test cancelled. Always get permission before testing!")
        sys.exit(0)
    
    print("\n🚀 Starting tests in 3 seconds...")
    time.sleep(3)
    
    if choice == '1':
        interface = input("Enter interface for ARP test (or press Enter to skip): ").strip()
        run_all_tests(target, interface if interface else None)
    elif choice == '2':
        test_syn_scan(target)
    elif choice == '3':
        test_icmp_flood(target)
    elif choice == '4':
        test_udp_flood(target)
    elif choice == '5':
        test_ssh_bruteforce(target)
    elif choice == '6':
        test_vnc_bruteforce(target)
    elif choice == '7':
        interface = input("Enter interface name: ").strip()
        test_arp_scan(interface)
    
    print("\n✓ Done! Check your NIDS for alerts.\n")

if __name__ == "__main__":
    main()