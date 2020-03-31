package main

import (
	"encoding/json"
	"io/ioutil"
	"log"

	"github.com/ValentinoUberti/dhcpchecker/macsniffer"
)

type ClusterNetData struct {
	DNSData []struct {
		Fqdn       string `json:"fqdn"`
		MacAddress string `json:"mac_address"`
		PrimaryIP  string `json:"primary_ip"`
		ReverseDNS string `json:"reverse_dns"`
	} `json:"dns_data"`
	DNSServer  string `json:"dns_server"`
	DomainData string `json:"domain_data"`
}

func main() {

	jsonDataFile, _ := ioutil.ReadFile("/tmp/dns-test.json")
	jsonDataStruct := ClusterNetData{}
	_ = json.Unmarshal([]byte(jsonDataFile), &jsonDataStruct)

	ifname := "eth1"
	hostname := "lb.example.com"
	macs := []string{}
	dataReceivedFromDhcp := []macsniffer.SingleTest{}

	for _, mac := range jsonDataStruct.DNSData {
		macs = append(macs, mac.MacAddress)
	}

	singleTestChan := make(chan macsniffer.SingleTest) // Ingress channel
	status := make(chan int)                           // Test Status

	dhcpClient, err := macsniffer.NewClient(macs, ifname, hostname)
	if err != nil {
		log.Fatalln(err)
	}
	go dhcpClient.Start(singleTestChan, status)

dhcploop:
	for {
		select {
		case msg := <-singleTestChan:

			dataReceivedFromDhcp = append(dataReceivedFromDhcp, macsniffer.SingleTest(msg))

		case status := <-status:

			if status > 0 {
				log.Println("Timeout reached")
			} else {
				log.Println("Mac test finished")
			}

			break dhcploop
		}
	}

	log.Println("Closing channels")
	close(singleTestChan)
	close(status)

	for _, singleMacTest := range dataReceivedFromDhcp {
		log.Printf("%+v\n", singleMacTest)

	}

}