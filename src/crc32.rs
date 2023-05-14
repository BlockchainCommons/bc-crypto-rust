pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

pub fn crc32_data_opt(data: &[u8], little_endian: bool) -> Vec<u8> {
    let checksum = crc32(data);
    let mut buf = Vec::new();
    if little_endian {
        buf.push((checksum & 0xff) as u8);
        buf.push(((checksum >> 8) & 0xff) as u8);
        buf.push(((checksum >> 16) & 0xff) as u8);
        buf.push(((checksum >> 24) & 0xff) as u8);
    } else {
        buf.push(((checksum >> 24) & 0xff) as u8);
        buf.push(((checksum >> 16) & 0xff) as u8);
        buf.push(((checksum >> 8) & 0xff) as u8);
        buf.push((checksum & 0xff) as u8);
    }
    buf
}

pub fn crc32_data(data: &[u8]) -> Vec<u8> {
    crc32_data_opt(data, false)
}

#[cfg(test)]
mod tests {
    use crate::{crc32, crc32_data, crc32_data_opt};

    #[test]
    fn test_crc32() {
        let input = "Hello, world!".as_bytes();
        assert_eq!(crc32(input), 0xebe6c6e6);
        assert_eq!(crc32_data(input), hex_literal::hex!("ebe6c6e6"));
        assert_eq!(crc32_data_opt(input, true), hex_literal::hex!("e6c6e6eb"));
    }
}
