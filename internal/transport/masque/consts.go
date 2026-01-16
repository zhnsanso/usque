package masque

const (
	// ConnectSNI is the SNI used to connect to the Cloudflare MASQUE server.
	ConnectSNI = "consumer-masque.cloudflareclient.com"
	// ConnectURI is the URI template for the MASQUE server.
	ConnectURI = "https://{host}/.well-known/masque/udp/{port}/"
)
