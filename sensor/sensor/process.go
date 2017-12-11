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

package sensor

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"xsec-traffic/sensor/misc"
	"xsec-traffic/sensor/models"
	"xsec-traffic/sensor/settings"

	"encoding/json"
	"time"
	"net/url"
	"net/http"

	"fmt"
	"strings"
)

func processPacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, ok := ipLayer.(*layers.IPv4)
		if ok {
			switch ip.Protocol {
			case layers.IPProtocolTCP:
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)

					srcPort := tcp.SrcPort.String()
					dstPort := tcp.DstPort.String()
					connInfo := models.NewConnectionInfo("tcp", ip.SrcIP.String(), srcPort, ip.DstIP.String(), dstPort)

					go func(u string, info *models.ConnectionInfo) {
						if !CheckSelfPacker(u, info) {
							misc.Log.Debugf("[TCP] %v:%v -> %v:%v", ip.SrcIP, tcp.SrcPort.String(), ip.DstIP, tcp.DstPort.String())
							SendPacker(info)
						}
					}(ApiUrl, connInfo)

				}

			case layers.IPProtocolUDP:
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				if udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)

					srcPort := udp.SrcPort.String()
					dstPort := udp.DstPort.String()
					connInfo := models.NewConnectionInfo("tcp", ip.SrcIP.String(), srcPort, ip.DstIP.String(), dstPort)

					go func(u string, info *models.ConnectionInfo) {
						if !CheckSelfPacker(u, info) {
							misc.Log.Debugf("[UDP] %v:%v -> %v:%v", ip.SrcIP, udp.SrcPort.String(), ip.DstIP, udp.DstPort.String())
							SendPacker(info)
						}
					}(ApiUrl, connInfo)

				}

			}
		}
	}

}

func SendPacker(connInfo *models.ConnectionInfo) (err error) {
	infoJson, err := json.Marshal(connInfo)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	urlApi := fmt.Sprintf("%v%v", ApiUrl, "/api/packet/")
	secureKey := misc.MakeSign(timestamp, SecureKey)

	http.PostForm(urlApi, url.Values{"timestamp": {timestamp}, "secureKey": {secureKey}, "data": {string(infoJson)}})
	return err
}

func CheckSelfPacker(ApiUrl string, p *models.ConnectionInfo) (ret bool) {
	urlParsed, err := url.Parse(ApiUrl)
	if err == nil {
		apiHost := urlParsed.Host
		apiIp := strings.Split(apiHost, ":")[0]
		sensorIp := settings.Ips[0]

		if p.SrcIp == sensorIp && p.DstIp == apiIp || p.SrcIp == apiIp && p.DstIp == sensorIp {

			ret = true
		}
		// misc.Log.Errorf("srcIp:%v, sensorIp: %v, DstIp: %v, ApiSeverIp: %v, ret: %v", p.SrcIp, sensorIp, p.DstIp, apiIp, ret)
	}
	return ret
}
