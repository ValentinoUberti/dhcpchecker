package main

import (
	"encoding/json"
	"io/ioutil"
	"log"

	dhcpchecker "./dhcp"
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

	ifname := "enp0s31f6"
	hostname := "vale-laptop"
	macs := []string{}
	dataReceivedFromDhcp := []dhcpchecker.SingleTest{}

	for _, mac := range jsonDataStruct.DNSData {
		macs = append(macs, mac.MacAddress)
	}

	singleTestChan := make(chan dhcpchecker.SingleTest) // Ingress channel
	status := make(chan int)                            // Test Status

	dhcpClient, err := dhcpchecker.NewClient(macs, ifname, hostname)
	if err != nil {
		log.Fatalln(err)
	}
	go dhcpClient.Start(singleTestChan, status)

dhcploop:
	for {
		select {
		case msg := <-singleTestChan:

			dataReceivedFromDhcp = append(dataReceivedFromDhcp, dhcpchecker.SingleTest(msg))

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
