#![no_main]

use libfuzzer_sys::fuzz_target;
use paranoid::id::{SORTABLE_ID_SIZE, SortableId};

fuzz_target!(|data: &[u8]| {
    let _ = SortableId::from_bytes(data);

    if data.len() >= SORTABLE_ID_SIZE {
        let id = SortableId::from_bytes(&data[..SORTABLE_ID_SIZE]).expect("fixed-size fuzz ID");
        let text = id.to_text();
        let upper_text = text.to_uppercase();

        assert_eq!(text.len(), 26);
        assert_eq!(SortableId::parse(&text).expect("parse encoded ID"), id);
        assert_eq!(
            SortableId::parse(&upper_text).expect("parse uppercase ID"),
            id
        );
        assert_eq!(text, id.to_string());

        let timestamp = id.to_unix_micros();
        assert!(SortableId::min_at_unix_micros(timestamp) <= id);
        assert!(id <= SortableId::max_at_unix_micros(timestamp));
    }

    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(id) = SortableId::parse(text)
    {
        assert_eq!(text.len(), 26);
        assert_eq!(
            SortableId::parse(&id.to_text()).expect("round-trip parsed ID"),
            id
        );
    }
});
