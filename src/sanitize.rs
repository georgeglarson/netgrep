/// Replace dangerous control characters with U+FFFD (replacement character).
///
/// Preserves tabs (0x09), newlines (0x0A), and carriage returns (0x0D) since
/// those are expected in text payloads. All other C0 control chars (0x00-0x08,
/// 0x0B-0x0C, 0x0E-0x1F) and DEL (0x7F) are replaced to prevent terminal
/// escape sequence injection from crafted packet payloads.
pub fn sanitize_control_chars(s: &str) -> String {
    s.chars()
        .map(|c| {
            match c {
                // Preserve tab, newline, carriage return
                '\t' | '\n' | '\r' => c,
                // Replace C0 control chars and DEL
                '\x00'..='\x08' | '\x0B'..='\x0C' | '\x0E'..='\x1F' | '\x7F' => '\u{FFFD}',
                // M2: Replace C1 control chars (U+0080-U+009F) which some terminals
                // interpret as ANSI-like escape sequences (e.g. CSI = U+009B).
                '\u{0080}'..='\u{009F}' => '\u{FFFD}',
                // All printable ASCII and unicode pass through
                _ => c,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_printable_ascii() {
        let input = "Hello, world! 123 @#$%";
        assert_eq!(sanitize_control_chars(input), input);
    }

    #[test]
    fn preserves_tabs_newlines_cr() {
        let input = "line1\tfield\nline2\r\nline3";
        assert_eq!(sanitize_control_chars(input), input);
    }

    #[test]
    fn replaces_null_byte() {
        assert_eq!(sanitize_control_chars("a\x00b"), "a\u{FFFD}b");
    }

    #[test]
    fn replaces_escape_sequence() {
        // ESC (0x1B) is the start of ANSI escape sequences
        let input = "before\x1b[31mred\x1b[0mafter";
        let result = sanitize_control_chars(input);
        assert!(!result.contains('\x1b'));
        assert!(result.contains('\u{FFFD}'));
        assert_eq!(result, "before\u{FFFD}[31mred\u{FFFD}[0mafter");
    }

    #[test]
    fn replaces_bell_and_backspace() {
        let input = "a\x07b\x08c";
        assert_eq!(sanitize_control_chars(input), "a\u{FFFD}b\u{FFFD}c");
    }

    #[test]
    fn replaces_del() {
        assert_eq!(sanitize_control_chars("a\x7Fb"), "a\u{FFFD}b");
    }

    #[test]
    fn preserves_unicode() {
        let input = "caf\u{00E9} \u{1F600} \u{4E16}\u{754C}";
        assert_eq!(sanitize_control_chars(input), input);
    }

    #[test]
    fn replaces_form_feed_and_vertical_tab() {
        let input = "a\x0Bb\x0Cc";
        assert_eq!(sanitize_control_chars(input), "a\u{FFFD}b\u{FFFD}c");
    }

    #[test]
    fn empty_string() {
        assert_eq!(sanitize_control_chars(""), "");
    }

    #[test]
    fn replaces_c1_control_chars() {
        // M2: C1 controls (U+0080-U+009F) can be used for terminal injection.
        // CSI (U+009B) is equivalent to ESC[ on many terminals.
        let input = "before\u{009B}31mred\u{009B}0mafter";
        let result = sanitize_control_chars(input);
        assert!(!result.contains('\u{009B}'));
        assert!(result.contains('\u{FFFD}'));
    }

    #[test]
    fn all_c1_control_chars_replaced() {
        for cp in 0x80u32..=0x9F {
            let c = char::from_u32(cp).unwrap();
            let input = format!("x{}y", c);
            let result = sanitize_control_chars(&input);
            assert_eq!(result, format!("x\u{FFFD}y"), "U+{:04X} not replaced", cp);
        }
    }

    #[test]
    fn preserves_latin1_above_c1() {
        // U+00A0 (NBSP) and above should pass through
        let input = "caf\u{00E9} \u{00A0}test";
        assert_eq!(sanitize_control_chars(input), input);
    }

    #[test]
    fn all_control_chars_replaced() {
        // Test every C0 control char that should be replaced
        for byte in (0x00..=0x08).chain(0x0B..=0x0C).chain(0x0E..=0x1F) {
            let c = char::from(byte);
            let input = format!("x{}y", c);
            let result = sanitize_control_chars(&input);
            assert_eq!(
                result,
                format!("x\u{FFFD}y"),
                "byte 0x{:02X} not replaced",
                byte
            );
        }
        // DEL
        let input = format!("x{}y", '\x7F');
        assert_eq!(sanitize_control_chars(&input), "x\u{FFFD}y");
    }
}
