use super::{ContainerReader, ReadProgress, Result, withheld};

/// Where [`str::replace`] replaces `value` in `text`, in characters.
pub(super) fn replace_nonempty_with_reader(
    text: &str,
    value: &str,
    tag: &str,
    reader: &ContainerReader,
    scan_bytes: usize,
) -> Result<Option<String>> {
    let mut out = None;
    let mut position = 0;
    while let Some(offset) = crate::graph_fs::find_literal(
        &text.as_bytes()[position..],
        value,
        scan_bytes.max(1),
        || {
            reader
                .pacing
                .checkpoint(ReadProgress::Member)
                .map_err(withheld)
        },
    )? {
        reader
            .pacing
            .checkpoint(ReadProgress::Member)
            .map_err(withheld)?;
        let start = position + offset;
        let output = out.get_or_insert_with(|| String::with_capacity(text.len()));
        push_masked_part(output, &text[position..start], reader, scan_bytes)?;
        push_masked_part(output, tag, reader, scan_bytes)?;
        position = start + value.len();
    }
    if let Some(output) = &mut out {
        push_masked_part(output, &text[position..], reader, scan_bytes)?;
    }
    Ok(out)
}

pub(super) fn push_masked_part(
    out: &mut String,
    text: &str,
    reader: &ContainerReader,
    scan_bytes: usize,
) -> Result<()> {
    let quantum = scan_bytes.max(char::MAX.len_utf8());
    let mut start = 0;
    while start < text.len() {
        reader
            .pacing
            .checkpoint(ReadProgress::Member)
            .map_err(withheld)?;
        let mut end = start.saturating_add(quantum).min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        out.push_str(&text[start..end]);
        start = end;
    }
    Ok(())
}
