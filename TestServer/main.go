package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
)

func echoHandler(conn net.Conn) {
	fmt.Println("Handling Clinet ...")
	buf := make([]byte, 0x1000)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			conn.Close()
			return
		}
		fmt.Println("Received: ")
		fmt.Println(hex.Dump(buf[:n]))
		conn.Write(buf[:n])
	}
}

func main() {
	ln, err := net.Listen("tcp", ":1337")
	if err != nil {
		log.Fatal(err)
	}

	defer ln.Close()

	log.Println("Listening on port: ", ln.Addr().String())
	for {
		conn, _ := ln.Accept()
		go echoHandler(conn)
	}
}
