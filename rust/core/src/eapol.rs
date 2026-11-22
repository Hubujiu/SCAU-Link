#[repr(C)]
pub struct FrameHeader {
    payload_offset: usize,
    payload_length: usize,
    version: u8,
    packet_type: u8,
    code: u8,
    identifier: u8,
    method: u8,
}

fn be16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        bytes.get(offset..)?.first_chunk::<2>().copied()?,
    ))
}

fn parse(packet: &[u8]) -> Option<FrameHeader> {
    if packet.len() < 18 {
        return None;
    }
    let mut protocol = be16(packet, 12)?;
    let mut ethernet_length = 14;
    while matches!(protocol, 0x8100 | 0x88a8 | 0x9100) {
        protocol = be16(packet.get(ethernet_length..)?, 2)?;
        ethernet_length += 4;
    }
    if protocol != 0x888e {
        return None;
    }
    let eapol = packet.get(ethernet_length..)?;
    let length = usize::from(be16(eapol, 2)?);
    let eap = eapol.get(4..4 + length)?;
    let mut header = FrameHeader {
        payload_offset: ethernet_length + 4,
        payload_length: length,
        version: eapol[0],
        packet_type: eapol[1],
        code: 0,
        identifier: 0,
        method: 0,
    };
    if header.packet_type == 0 {
        let eap_length = usize::from(be16(eap, 2)?);
        if !(4..=eap.len()).contains(&eap_length) {
            return None;
        }
        header.code = eap[0];
        header.identifier = eap[1];
        if matches!(header.code, 1 | 2) {
            let declared = &eap[..eap_length];
            header.method = *declared.get(4)?;
            if header.method == 4 && usize::from(*declared.get(5)?) > eap_length - 6 {
                return None;
            }
        }
    }
    Some(header)
}

// The caller supplies a readable packet and one writable result for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn scau_parse_eapol(
    packet: *const u8,
    length: usize,
    result: *mut FrameHeader,
) -> bool {
    if packet.is_null() || result.is_null() || length > isize::MAX as usize {
        return false;
    }
    // Rust borrows the original buffer. C++ constructs the retained spans.
    let packet = unsafe { std::slice::from_raw_parts(packet, length) };
    let Some(header) = parse(packet) else {
        return false;
    };
    unsafe { result.write(header) };
    true
}
