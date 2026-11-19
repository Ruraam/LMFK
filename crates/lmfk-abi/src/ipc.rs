//! Pointer-free IPC wire protocol for isolated userspace drivers.
//!
//! Unlike the native ABI, this protocol never contains function pointers or
//! process-local addresses. Every field has a fixed width and an explicit
//! little-endian encoding, so a 32-bit host and a 64-bit host exchange the
//! exact same bytes. Handles remain opaque `u64` tokens issued by the
//! framework; buffers travel as length-prefixed byte arrays after the header.

use core::convert::TryInto;

pub const IPC_MAGIC: u32 = 0x4c_4d_46_50; // "LMFP"
pub const IPC_VERSION: u16 = 1;
pub const IPC_HEADER_SIZE: usize = 32;

/// Fixed 32-byte message header. The payload follows immediately after it.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpcMessageHeader {
    pub magic: u32,
    pub version: u16,
    pub opcode: u16,
    pub request_id: u64,
    pub handle_count: u32,
    pub payload_len: u32,
    pub flags: u32,
    pub reserved: u32,
}

fn u16le(bytes: &[u8]) -> u16 {
    u16::from_le_bytes(bytes[..2].try_into().unwrap())
}

fn u32le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().unwrap())
}

fn u64le(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[..8].try_into().unwrap())
}

impl IpcMessageHeader {
    pub fn new(opcode: u16, request_id: u64, payload_len: u32, handle_count: u32) -> Self {
        Self {
            magic: IPC_MAGIC,
            version: IPC_VERSION,
            opcode,
            request_id,
            handle_count,
            payload_len,
            flags: 0,
            reserved: 0,
        }
    }

    /// Decode from exactly `IPC_HEADER_SIZE` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < IPC_HEADER_SIZE {
            return None;
        }
        let header = Self {
            magic: u32le(&bytes[0..]),
            version: u16le(&bytes[4..]),
            opcode: u16le(&bytes[6..]),
            request_id: u64le(&bytes[8..]),
            handle_count: u32le(&bytes[16..]),
            payload_len: u32le(&bytes[20..]),
            flags: u32le(&bytes[24..]),
            reserved: u32le(&bytes[28..]),
        };
        (header.magic == IPC_MAGIC && header.version == IPC_VERSION).then_some(header)
    }

    /// Encode into a caller-owned 32-byte buffer.
    pub fn to_bytes(&self, out: &mut [u8]) {
        assert!(out.len() >= IPC_HEADER_SIZE);
        out[..IPC_HEADER_SIZE].fill(0);
        out[0..4].copy_from_slice(&self.magic.to_le_bytes());
        out[4..6].copy_from_slice(&self.version.to_le_bytes());
        out[6..8].copy_from_slice(&self.opcode.to_le_bytes());
        out[8..16].copy_from_slice(&self.request_id.to_le_bytes());
        out[16..20].copy_from_slice(&self.handle_count.to_le_bytes());
        out[20..24].copy_from_slice(&self.payload_len.to_le_bytes());
        out[24..28].copy_from_slice(&self.flags.to_le_bytes());
        out[28..32].copy_from_slice(&self.reserved.to_le_bytes());
    }

    /// Total frame size, checked for overflow.
    pub fn frame_len(&self) -> Option<usize> {
        (self.handle_count as usize)
            .checked_mul(8)?
            .checked_add(self.payload_len as usize)?
            .checked_add(IPC_HEADER_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_layout_is_pointer_width_independent() {
        assert_eq!(core::mem::size_of::<IpcMessageHeader>(), 32);
        let header = IpcMessageHeader::new(7, 0x1122_3344_5566_7788, 64, 3);
        let mut bytes = [0u8; IPC_HEADER_SIZE];
        header.to_bytes(&mut bytes);
        assert_eq!(IpcMessageHeader::from_bytes(&bytes), Some(header));
        assert_eq!(header.frame_len(), Some(32 + 24 + 64));
    }

    #[test]
    fn rejects_bad_magic_and_short_frames() {
        let header = IpcMessageHeader::new(1, 1, 0, 0);
        let mut bytes = [0u8; IPC_HEADER_SIZE];
        header.to_bytes(&mut bytes);
        bytes[0] ^= 0xff;
        assert!(IpcMessageHeader::from_bytes(&bytes).is_none());
        assert!(IpcMessageHeader::from_bytes(&bytes[..31]).is_none());
    }
}
