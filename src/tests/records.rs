use std::io::Cursor;

use super::{RecordHeader, read_record_bounded};

#[test]
fn bounded_record_read_rejects_payload_len_before_allocation() {
    let header = RecordHeader {
        rtype: 7,
        rflags: 0,
        header_ext: Vec::new(),
        payload_len: 1 << 40,
    }
    .pack()
    .unwrap();
    let mut reader = Cursor::new(header);

    let err = read_record_bounded(&mut reader, None, 1024).unwrap_err();

    assert!(
        err.to_string()
            .contains("record payload length 1099511627776 exceeds expected bound 1024")
    );
}
