package pkg

import (
	"testing"
)

func TestEncrypt(t *testing.T) {
	type args struct {
		plaintext string
		key       string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Valid encryption",
			args: args{
				plaintext: "Hello, World!",
				key:       "thisis32byteslongpassphrase!!!##", // 32 bytes
			},
			wantErr: false,
		},
		{
			name: "Empty plaintext",
			args: args{
				plaintext: "",
				key:       "thisis32byteslongpassphrase!!!##", // 32 bytes
			},
			wantErr: false,
		},
		{
			name: "Invalid key length",
			args: args{
				plaintext: "Hello, World!",
				key:       "shortkey", // Invalid key size
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Encrypt(tt.args.plaintext, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == "" {
				t.Errorf("Encrypt() got empty ciphertext, expected valid result")
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	type args struct {
		ciphertext string
		key        string
	}
	tests := []struct {
		name    string
		encrypt args
		want    string
		wantErr bool
	}{
		{
			name: "Valid round-trip",
			encrypt: args{
				ciphertext: "",
				key:        "thisis32byteslongpassphrase!!!##", // 32 bytes key
			},
			want:    "Hello, Golang!",
			wantErr: false,
		},
		{
			name: "Tampered ciphertext",
			encrypt: args{
				ciphertext: "invalidbase64==",
				key:        "thisis32byteslongpassphrase!!!##", // 32 bytes key
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Wrong key",
			encrypt: args{
				ciphertext: "",
				key:        "wrongpassphrase!@#$%^&*()long!!", // 32 bytes key
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// If valid ciphertext is needed, encrypt it first
			if tt.encrypt.ciphertext == "" && !tt.wantErr {
				encrypted, err := Encrypt(tt.want, tt.encrypt.key)
				if err != nil {
					t.Fatalf("Failed to encrypt during setup: %v", err)
				}
				tt.encrypt.ciphertext = encrypted
			}

			got, err := Decrypt(tt.encrypt.ciphertext, tt.encrypt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Decrypt() got = %v, want %v", got, tt.want)
			}
		})
	}
}
