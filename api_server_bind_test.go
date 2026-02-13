package main

import "testing"

func TestIsInsecureAPIBindAddress(t *testing.T) {
	tests := []struct {
		addr     string
		insecure bool
	}{
		{addr: "127.0.0.1:8332", insecure: false},
		{addr: "localhost:8332", insecure: false},
		{addr: "[::1]:8332", insecure: false},
		{addr: "0.0.0.0:8332", insecure: true},
		{addr: ":8332", insecure: true},
		{addr: "[::]:8332", insecure: true},
		{addr: "1.2.3.4:8332", insecure: true},
	}

	for _, tt := range tests {
		if got := isInsecureAPIBindAddress(tt.addr); got != tt.insecure {
			t.Fatalf("isInsecureAPIBindAddress(%q) = %v, want %v", tt.addr, got, tt.insecure)
		}
	}
}
