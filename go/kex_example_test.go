package confidentiality

import (
	"fmt"
	"io"
	"net"
)

func ExampleExchange() {
	server, _ := net.Listen("tcp", "localhost:0")
	defer server.Close()

	go func(listener net.Listener) {
		connection, _ := listener.Accept()
		defer connection.Close()

		var (
			sharedKey, _ = Exchange(connection)
			decrypter    = Decrypter(connection, sharedKey)
			encrypter    = Encrypter(connection, sharedKey)
			message      = make([]byte, 14)
		)
		io.ReadFull(decrypter, message)
		fmt.Fprint(encrypter, "hello, client!") // 14 bytes
	}(server)

	client, _ := net.Dial("tcp", server.Addr().String())
	defer client.Close()
	var (
		sharedKey, _ = Exchange(client)
		encrypter    = Encrypter(client, sharedKey)
		decrypter    = Decrypter(client, sharedKey)
		message      = make([]byte, 14)
	)
	fmt.Fprint(encrypter, "hello, server!") // 14 bytes
	io.ReadFull(decrypter, message)
	fmt.Println(string(message)) // Shall print "hello, client!"
}
