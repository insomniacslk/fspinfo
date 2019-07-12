package fspinfo

import (
	"bytes"
	"fmt"
	"log"
	"strings"

	"github.com/u-root/u-root/pkg/uio"
)

// TODO support FSP versions < 2.0
// TODO implement FSP_INFO_EXTENDED_HEADER

// FSP 2.0 specification
// https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/fsp-architecture-spec-v2.pdf

// values from the FSP 2.0 spec
var (
	Signature = [4]byte{'F', 'S', 'P', 'H'}
)

// constants from the FSP 2.0 spec
const (
	CurrentHeaderLength = 72
	// FSP 2.0
	CurrentSpecVersion    = SpecVersion(0x20)
	CurrentHeaderRevision = 3
)

// FSPInfoHeaderRev3 represents the FSP_INFO_HEADER structure revision 3 (FSP
// 2.0) as defined by Intel.
type FSPInfoHeaderRev3 struct {
	Signature                 [4]byte
	HeaderLength              uint32
	Reserved1                 [2]uint8
	SpecVersion               SpecVersion
	HeaderRevision            uint8
	ImageRevision             ImageRevision
	ImageID                   [8]byte
	ImageSize                 uint32
	ImageBase                 uint32
	ImageAttribute            ImageAttribute
	ComponentAttribute        ComponentAttribute
	CfgRegionOffset           uint32
	CfgRegionSize             uint32
	Reserved2                 [4]byte
	TempRAMInitEntryOffset    uint32
	Reserved3                 [4]byte
	NotifyPhaseEntryOffset    uint32
	FSPMemoryInitEntryOffset  uint32
	TempRAMExitEntryOffset    uint32
	FSPSiliconInitEntryOffset uint32
}

// ImageRevision is the image revision fielf of the FSP info header.
type ImageRevision uint32

func (ir ImageRevision) String() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ir>>24)&0xff,
		(ir>>16)&0xff,
		(ir>>8)&0xff,
		ir&0xff,
	)
}

// SpecVersion represents the spec version as a packed BCD two-digit,
// dot-separated unsigned integer.
type SpecVersion uint8

func (sv SpecVersion) String() string {
	return fmt.Sprintf("%d.%d", (sv>>4)&0x0f, sv&0x0f)
}

// ImageAttribute represents the image attributes.
type ImageAttribute uint16

func (ia ImageAttribute) String() string {
	ret := fmt.Sprintf("%#04x GraphicsDisplaySupported", uint16(ia))
	if uint16(ia) & ^(uint16(1)) != 0 {
		ret += " (reserved bits are not zeroed)"
	}
	return ret
}

// ComponentAttribute represents the component attribute.
type ComponentAttribute uint16

func (ca ComponentAttribute) String() string {
	var attrs []string
	if uint16(ca)&0x01 == 1 {
		attrs = append(attrs, "ReleaseBuild")
	} else {
		attrs = append(attrs, "DebugBuild")
	}
	if uint16(ca)&0x03 == 1 {
		attrs = append(attrs, "OfficialRelease")
		attrs = append(attrs, "OfficialRelease")
	} else {
		attrs = append(attrs, "TestRelease")
	}
	switch uint16(ca) >> 12 {
	case 1:
		attrs = append(attrs, "TypeFSP-T")
	case 2:
		attrs = append(attrs, "TypeFSP-M")
	case 3:
		attrs = append(attrs, "TypeFSP-S")
	case 8:
		attrs = append(attrs, "TypeFSP-O")
	default:
		attrs = append(attrs, "TypeFSPReserved")
	}
	ret := fmt.Sprintf("%#04x %s", uint16(ca), strings.Join(attrs, "|"))
	// bits 2:12 are reserved
	if uint16(ca)&0x0ffe != 0 {
		ret += " (reserved bits are not zeroed)"
	}
	return ret
}

// FromBytes parses an FSP_INFO_HEADER from a byte buffer.
func FromBytes(b []byte) (*FSPInfoHeaderRev3, error) {
	var f FSPInfoHeaderRev3
	buf := uio.NewLittleEndianBuffer(b)
	f.Signature[0] = buf.Read8()
	f.Signature[1] = buf.Read8()
	f.Signature[2] = buf.Read8()
	f.Signature[3] = buf.Read8()
	f.HeaderLength = buf.Read32()
	f.Reserved1[0] = buf.Read8()
	f.Reserved1[1] = buf.Read8()
	f.SpecVersion = SpecVersion(buf.Read8())
	f.HeaderRevision = buf.Read8()
	f.ImageRevision = ImageRevision(buf.Read32())
	f.ImageID[0] = buf.Read8()
	f.ImageID[1] = buf.Read8()
	f.ImageID[2] = buf.Read8()
	f.ImageID[3] = buf.Read8()
	f.ImageID[4] = buf.Read8()
	f.ImageID[5] = buf.Read8()
	f.ImageID[6] = buf.Read8()
	f.ImageID[7] = buf.Read8()
	f.ImageSize = buf.Read32()
	f.ImageBase = buf.Read32()
	f.ImageAttribute = ImageAttribute(buf.Read16())
	f.ComponentAttribute = ComponentAttribute(buf.Read16())
	f.CfgRegionOffset = buf.Read32()
	f.CfgRegionSize = buf.Read32()
	f.Reserved2[0] = buf.Read8()
	f.Reserved2[1] = buf.Read8()
	f.Reserved2[2] = buf.Read8()
	f.Reserved2[3] = buf.Read8()
	f.TempRAMInitEntryOffset = buf.Read32()
	f.Reserved3[0] = buf.Read8()
	f.Reserved3[1] = buf.Read8()
	f.Reserved3[2] = buf.Read8()
	f.Reserved3[3] = buf.Read8()
	f.NotifyPhaseEntryOffset = buf.Read32()
	f.FSPMemoryInitEntryOffset = buf.Read32()
	f.TempRAMExitEntryOffset = buf.Read32()
	f.FSPSiliconInitEntryOffset = buf.Read32()
	if err := buf.FinError(); err != nil {
		return nil, err
	}
	if !bytes.Equal(f.Signature[:], Signature[:]) {
		return nil, fmt.Errorf("invalid signature %v; want %v", f.Signature, Signature)
	}
	if f.HeaderLength != CurrentHeaderLength {
		return nil, fmt.Errorf("invalid header length %d; want %d", f.HeaderLength, CurrentHeaderLength)
	}
	if !bytes.Equal(f.Reserved1[:], []byte{0, 0}) {
		log.Printf("warning: reserved bytes must be zero, got %v", f.Reserved1)
	}
	if f.SpecVersion != 0 {
		if f.SpecVersion != CurrentSpecVersion {
			return nil, fmt.Errorf("cannot handle spec version %s; want %s", f.SpecVersion, CurrentSpecVersion)
		}
	}
	if f.HeaderRevision != CurrentHeaderRevision {
		return nil, fmt.Errorf("cannot handle header revision %d; want %d", f.HeaderRevision, CurrentHeaderRevision)
	}
	return &f, nil
}
