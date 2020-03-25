package main

import (
	"log"

	dhcpchecker "./dhcp"
)

func main() {
	ifname := "enp0s31f6"
	hostname := "vale-laptop"
	macs := []string{"11:22:33:44:55:66", "84:7b:eb:27:0c:a4", "84:7b:eb:27:0c:10", "84:7b:eb:27:0c:a9"}

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

			log.Println(msg)

		case status := <-status:

			if status > 0 {
				log.Panicln("Timeout reached")
			} else {
				log.Println("Test finished")
			}

			break dhcploop
		}
	}

	log.Println("Closing channels")
	close(singleTestChan)
	close(status)

}
