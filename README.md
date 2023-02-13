# BTF datasec/var resolution error

Round-trip marshaling vmlinux BTF started failing after introducing
shuffling of the order types appear in in the BTF blob. For vmlinux,
the BTF verifier tripped over cpu_l2c_shared_map in the .data..percpu datasec.

BTF generated by this tool will be written to /tmp/btf for maunual loading
or inspection using bpftool.

The reproducer in this repo fails as follows:

```
λ  ~/documents/sandbox/ebpf  go run -exec sudo main.go
Datasec added with id 1
written btf blob to /tmp/btf
load btf: invalid argument:
	magic: 0xeb9f
	version: 1
	flags: 0x0
	hdr_len: 24
	type_off: 0
	type_len: 108
	str_off: 108
	str_len: 3
	btf_total_size: 135
	[1] DATASEC a size=2 vlen=2
		 type_id=6 offset=0 size=1
		 type_id=4 offset=1 size=1
	[2] INT (anon) size=0 bits_offset=0 nr_bits=0 encoding=(none)
	[3] TYPEDEF a type_id=2
	[4] VAR a type_id=3 linkage=0
	[5] STRUCT (anon) size=0 vlen=0
	[6] VAR a type_id=5 linkage=0
	[1] DATASEC a size=2 vlen=2
		 type_id=4 offset=1 size=1 Invalid type
exit status 1
```

Some observations:
- There seems to be an issue with typedef members (of any kind) appearing
  anywhere after a composite type like a &Struct or a &Union.
- If all types pointed to by the datasec appear in the BTF blob before the
  datasec, the verifier resolves them properly and everything is fine.
