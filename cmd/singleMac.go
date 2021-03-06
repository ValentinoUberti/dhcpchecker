/*
Copyright © 2020 Valentino Uberti vuberti@redhat.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"errors"
	"fmt"

	"log"

	"github.com/spf13/cobra"

	"github.com/ValentinoUberti/dhcpchecker/macsniffer"
)

// mactestCmd represents the mactest command
var mactestCmd = &cobra.Command{
	Use:   "single-mac --ifname <interface-name> --mac <mac-address>",
	Short: "Test for dhcp server ip response from single mac addresses",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		err := mactest(cmd)
		if err != nil {
			fmt.Println(err)
			fmt.Println(cmd.Usage())
		}
	},
}

func mactest(cmd *cobra.Command) error {

	interfaceName, err := cmd.Flags().GetString("ifname")

	if err != nil {
		return errors.New("Error parsing arguments")
	}

	if interfaceName == "" {
		return errors.New("An interface name is required")
	}

	singleMac, err := cmd.Flags().GetString("mac")

	if err != nil {
		return errors.New("Error parsing arguments")
	}

	if singleMac == "" {
		return errors.New("A single mac address is required")
	}

	expectedIp, err := cmd.Flags().GetString("expected-ip")

	if err != nil {
		return errors.New("Error parsing arguments")
	}

	if expectedIp == "" {
		return errors.New("An expected ip address is required")
	}

	jsonDataStruct := macsniffer.ClusterNetData{}

	data := macsniffer.DNSDataStruct{
		MacAddress: singleMac,
	}
	jsonDataStruct.DNSData = append(jsonDataStruct.DNSData, data)

	ifname := interfaceName
	hostname := ""
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

	macsniffer.SingleIpTest(dataReceivedFromDhcp[0].OfferedIp, expectedIp, singleMac)

	return nil
}

func init() {
	rootCmd.AddCommand(mactestCmd)
	mactestCmd.PersistentFlags().StringP("mac", "", "", "Single mac address to test")
	mactestCmd.PersistentFlags().StringP("expected-ip", "", "", "Ip expected")
}
