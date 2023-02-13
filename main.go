package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func main() {
	ds := &btf.Datasec{
		Name: "a",
		Size: 2,
		Vars: []btf.VarSecinfo{
			{
				Size:   1,
				Offset: 0,
				Type:   &btf.Var{Name: "a", Type: &btf.Struct{}},
			},
			{
				Size:   1,
				Offset: 1,
				Type: &btf.Var{
					Name: "a",
					Type: &btf.Typedef{
						Name: "a",
						Type: &btf.Int{},
					},
				},
			},
		},
	}

	s := btf.NewSpec()
	id, err := s.Add(ds)
	if err != nil {
		exit(err)
	}
	fmt.Println("Datasec added with id", id)

	h, err := btf.NewHandle(s)
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		fmt.Printf("%+v\n", ve)
		os.Exit(1)
	}
	if err != nil {
		exit(err)
	}
	h.Close()

	fmt.Println("BTF loaded successfully")
}

func exit(err error) {
	fmt.Println(err)
	os.Exit(1)
}
