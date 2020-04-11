package macsniffer

import (
	"fmt"
)

func ipTest(offeredIp string, expectedIp string) bool {
	if offeredIp == expectedIp {
		return true
	}
	return false
}

func MultipleIpTest(testResults []SingleTest, expectedResults ClusterNetData) {

	for _, singleTest := range testResults {

		for _, expected := range expectedResults.DNSData {
			if singleTest.SrcMac == expected.MacAddress {
				if ipTest(singleTest.OfferedIp, expected.PrimaryIP) {
					fmt.Printf("Test passed for mac %s\n", singleTest.SrcMac)
				} else {
					fmt.Printf("Test failed for mac %s\nOffered ip: %s\tExpected %s\n", singleTest.SrcMac, singleTest.OfferedIp, expected.PrimaryIP)
				}

			}
		}

	}

}

func SingleIpTest(offeredIp string, expectedIp string, mac string) {

	if ipTest(offeredIp, expectedIp) {
		fmt.Printf("Test passed for mac %s\n", mac)
	} else {
		fmt.Printf("Test failed for mac %s\nOffered ip: %s\tExpected %s\n", mac, offeredIp, expectedIp)
	}
}
