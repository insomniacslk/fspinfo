package main

import (
	"flag"
	"fmt"
	"io/ioutil"

	fsp "github.com/insomniacslk/fspinfo/pkg/fsp"
	"github.com/linuxboot/fiano/pkg/uefi"
)

func main() {
	flag.Parse()

	if flag.Arg(0) == "" {
		panic("missing filename")
	}
	data, err := ioutil.ReadFile(flag.Arg(0))
	if err != nil {
		panic(err)
	}

	fv, err := uefi.NewFirmwareVolume(data, 0, false)
	if err != nil {
		panic(err)
	}
	if len(fv.Files) < 1 {
		panic("at least one file is required")
	}
	file := fv.Files[0]
	// FIXME why does FSPH start at +4?
	hdr, err := fsp.FromBytes(file.Buf()[file.DataOffset+4 : file.DataOffset+4+fsp.CurrentHeaderLength])
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signature                   : %s\n", hdr.Signature)
	fmt.Printf("Header Length               : %d\n", hdr.HeaderLength)
	fmt.Printf("Reserved1                   : %#04x\n", hdr.Reserved1)
	fmt.Printf("Spec Version                : %s\n", hdr.SpecVersion)
	fmt.Printf("Header Revision             : %d\n", hdr.HeaderRevision)
	fmt.Printf("Image Revision              : %s\n", hdr.ImageRevision)
	fmt.Printf("Image ID                    : %s\n", hdr.ImageID)
	fmt.Printf("Image Size                  : %#08x %d\n", hdr.ImageSize, hdr.ImageSize)
	fmt.Printf("Image Base                  : %#08x %d\n", hdr.ImageBase, hdr.ImageBase)
	fmt.Printf("Image Attribute             : %s\n", hdr.ImageAttribute)
	fmt.Printf("Component Attribute         : %s\n", hdr.ComponentAttribute)
	fmt.Printf("Cfg Region Offset           : %#08x %d\n", hdr.CfgRegionOffset, hdr.CfgRegionOffset)
	fmt.Printf("Cfg Region Size             : %#08x %d\n", hdr.CfgRegionSize, hdr.CfgRegionSize)
	fmt.Printf("Reserved2                   : %#08x\n", hdr.Reserved2)
	fmt.Printf("TempRAMInit Entry Offset    : %#08x %d\n", hdr.TempRAMInitEntryOffset, hdr.TempRAMInitEntryOffset)
	fmt.Printf("Reserved3                   : %#08x\n", hdr.Reserved3)
	fmt.Printf("NotifyPhase Entry Offset    : %#08x %d\n", hdr.NotifyPhaseEntryOffset, hdr.NotifyPhaseEntryOffset)
	fmt.Printf("FSPMemoryInit Entry Offset  : %#08x %d\n", hdr.FSPMemoryInitEntryOffset, hdr.FSPMemoryInitEntryOffset)
	fmt.Printf("TempRAMExit Entry Offset    : %#08x %d\n", hdr.TempRAMExitEntryOffset, hdr.TempRAMExitEntryOffset)
	fmt.Printf("FSPSiliconInit Entry Offset : %#08x %d\n", hdr.FSPSiliconInitEntryOffset, hdr.FSPSiliconInitEntryOffset)
}
