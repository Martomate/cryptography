use std::{fmt::Display, str::FromStr};

use base64::prelude::*;

pub struct PEM {
    pub label: String,
    pub data: Vec<u8>,
}

impl FromStr for PEM {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        decode_pem(s)
    }
}

impl Display for PEM {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "-----BEGIN {}-----", self.label)?;

        let data_base64 = BASE64_STANDARD.encode(&self.data);
        let mut line = String::with_capacity(64);
        for (i, c) in data_base64.chars().enumerate() {
            if i % 64 == 0 && i != 0 {
                writeln!(f, "{}", line)?;
                line.clear();
            }
            line.push(c);
        }
        writeln!(f, "{}", line)?;

        write!(f, "-----END {}-----", self.label)?;

        Ok(())
    }
}

fn decode_pem(s: &str) -> Result<PEM, String> {
    let mut begin_label: Option<&str> = None;
    let mut data_lines: Vec<&str> = Vec::new();
    let mut end_label: Option<&str> = None;

    for l in s.lines() {
        let l = l.trim();
        if let Some(l) = l.strip_prefix("-----BEGIN ") {
            if begin_label.is_some() {
                return Err("multiple BEGIN lines".to_string());
            }
            if let Some(l) = l.strip_suffix("-----") {
                begin_label = Some(l);
            } else {
                return Err("invalid BEGIN line".to_string());
            }
        } else if let Some(l) = l.strip_prefix("-----END ") {
            if begin_label.is_none() {
                return Err("found END line before the BEGIN line".to_string())
            }
            if end_label.is_some() {
                return Err("multiple END lines".to_string());
            }
            if let Some(l) = l.strip_suffix("-----") {
                end_label = Some(l);
            } else {
                return Err("invalid END line".to_string());
            }
        } else if begin_label.is_some() && end_label.is_none() {
            data_lines.push(l);
        } else {
            // we are before the BEGIN line or after the END line => ignore the line
        }
    }

    let Some(label) = begin_label else {
        return Err("BEGIN line is missing".to_string());
    };
    let Some(end_label) = end_label else {
        return Err("END line is missing".to_string());
    };
    if end_label != label {
        return Err("label mismatch".to_string())
    }

    let data_base64 = data_lines.join("");
    let data = BASE64_STANDARD
        .decode(data_base64.as_bytes())
        .map_err(|e| e.to_string())?;

    Ok(PEM {
        label: label.to_string(),
        data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_simple_label() {
        let res = PEM::from_str(
            "\
-----BEGIN ABC-----
c29tZSBkYXRh
-----END ABC-----",
        )
        .unwrap();
        assert_eq!(res.label, "ABC");
    }

    #[test]
    fn decode_multi_word_label() {
        let res = PEM::from_str(
            "\
-----BEGIN ABC DEF-----
c29tZSBkYXRh
-----END ABC DEF-----",
        )
        .unwrap();
        assert_eq!(res.label, "ABC DEF");
    }

    #[test]
    fn decode_single_line() {
        let res = PEM::from_str(
            "\
-----BEGIN ABC-----
c29tZSBkYXRh
-----END ABC-----",
        )
        .unwrap();
        assert_eq!(res.data, b"some data".to_vec());
    }

    #[test]
    fn decode_multiple_lines() {
        let res = PEM::from_str(
            "\
-----BEGIN ABC-----
c29t
ZSBkYX
Rh
-----END ABC-----",
        )
        .unwrap();
        assert_eq!(res.data, b"some data".to_vec());
    }

    #[test]
    fn decode_trims_leading_and_trailing_whitespace() {
        let res = PEM::from_str(
            "

        -----BEGIN ABC-----     
            c29tZS
    BkYXRh      
                -----END ABC-----   
                ",
        )
        .unwrap();
        assert_eq!(res.data, b"some data".to_vec());
    }

    #[test]
    fn decode_ignores_lines_before_the_begin_line() {
        let res = PEM::from_str(
            "
some info
more stuff

hello

-----BEGIN ABC-----
c29tZSBkYXRh
-----END ABC-----",
        )
        .unwrap();
        assert_eq!(res.data, b"some data".to_vec());
    }

    #[test]
    fn decode_ignores_lines_after_the_end_line() {
        let res = PEM::from_str(
            "
-----BEGIN ABC-----
c29tZSBkYXRh
-----END ABC-----

some info
more stuff

hello
",
        )
        .unwrap();
        assert_eq!(res.data, b"some data".to_vec());
    }

    #[test]
    fn decode_detects_missing_begin_line() {
        assert!(PEM::from_str(
            "
c29tZSBkYXRh
-----END ABC-----
",
        ).is_err());
    }

    #[test]
    fn decode_detects_missing_end_line() {
        assert!(PEM::from_str(
            "
-----BEGIN ABC-----
c29tZSBkYXRh
",
        ).is_err());
    }

    #[test]
    fn decode_detects_duplicate_begin_lines() {
        assert!(PEM::from_str(
            "
-----BEGIN ABC-----
-----BEGIN ABC-----
c29tZSBkYXRh
-----END ABC-----
",
        ).is_err());
    }

    #[test]
    fn decode_detects_duplicate_end_lines() {
        assert!(PEM::from_str(
            "
-----BEGIN ABC-----
c29tZSBkYXRh
-----END ABC-----
-----END ABC-----
",
        ).is_err());
    }

    #[test]
    fn decode_detects_end_line_before_begin() {
        assert!(PEM::from_str(
            "
-----END ABC-----
c29tZSBkYXRh
-----BEGIN ABC-----
",
        ).is_err());
    }

    #[test]
    fn decode_detects_label_mismatch() {
        // Note: this is not strictly required by the spec
        assert!(PEM::from_str(
            "
-----BEGIN ABC-----
c29tZSBkYXRh
-----END DEF-----
",
        ).is_err());
    }

    #[test]
    fn decode_big_data() {
        let data = b"\
some data 1
some data 2
some data 3
some data 4
some data 5
some data 6";

        let res = PEM::from_str(
            "\
-----BEGIN ABC-----
c29tZSBkYXRhIDEKc29tZSBkYXRhIDIKc29tZSBkYXRhIDMKc29tZSBkYXRhIDQKc29tZSBkYXRhIDUKc29tZSBkYXRhIDY=
-----END ABC-----",
        )
        .unwrap();

        assert_eq!(res.data, data.to_vec());
    }

    #[test]
    fn encode_big_data() {
        let data = b"\
some data 1
some data 2
some data 3
some data 4
some data 5
some data 6";

        let res = &PEM {
            label: "ABC DEF".to_string(),
            data: data.to_vec(),
        }.to_string();

        // The output must wrap at 64 characters per line
        let expected_string = "\
-----BEGIN ABC DEF-----
c29tZSBkYXRhIDEKc29tZSBkYXRhIDIKc29tZSBkYXRhIDMKc29tZSBkYXRhIDQK
c29tZSBkYXRhIDUKc29tZSBkYXRhIDY=
-----END ABC DEF-----";

        assert_eq!(res, expected_string);
    }

    #[test]
    fn encode_big_data_with_full_lines() {
        let data = b"\
some data 1
some data 2
some data 3
some data 4
some data 1
some data 2
some data 3
some data 4
";

        let res = &PEM {
            label: "ABC DEF".to_string(),
            data: data.to_vec(),
        }.to_string();

        // The output must wrap at 64 characters per line
        let expected_string = "\
-----BEGIN ABC DEF-----
c29tZSBkYXRhIDEKc29tZSBkYXRhIDIKc29tZSBkYXRhIDMKc29tZSBkYXRhIDQK
c29tZSBkYXRhIDEKc29tZSBkYXRhIDIKc29tZSBkYXRhIDMKc29tZSBkYXRhIDQK
-----END ABC DEF-----";

        assert_eq!(res, expected_string);
    }
}
