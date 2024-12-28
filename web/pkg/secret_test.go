package pkg

import (
	"testing"
)

func TestGenerateSecretString(t *testing.T) {
	type args struct {
		i int
	}
	tests := []struct {
		name    string
		args    args
		wantLen int
		wantErr bool
	}{
		{
			name:    "Valid length 10",
			args:    args{i: 10},
			wantLen: 10,
			wantErr: false,
		},
		{
			name:    "Valid length 32",
			args:    args{i: 32},
			wantLen: 32,
			wantErr: false,
		},
		{
			name:    "Zero length",
			args:    args{i: 0},
			wantLen: 0,
			wantErr: true,
		},
		{
			name:    "Negative length",
			args:    args{i: -5},
			wantLen: 0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateSecret(tt.args.i)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && len(got) != tt.wantLen {
				t.Errorf("GenerateSecret() length = %v, want %v", len(got), tt.wantLen)
			}
		})
	}
}
