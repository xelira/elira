//! Turn the CGI header stream produced by FastCGI into a [`Response`].

use std::fmt::Write as _;

use crate::{Error, Response};

/// Parse the concatenated STDOUT records and attach the captured STDERR.
///
/// FastCGI wraps CGI, not HTTP: the first part of STDOUT is a header block
/// separated from the body by an empty line. The only status forms a CGI
/// application is allowed to use are `Status: 200 OK` and an implicit 200 or
/// 302, so anything else is rejected rather than guessed at.
pub(crate) fn parse(
    stdout: &[u8],
    stderr_bytes: &[u8],
    app_status: u32,
) -> Result<Response, Error> {
    let (header_block, body) = split(stdout)?;

    let mut status = None;
    let mut saw_location = false;
    let mut headers = Vec::new();

    for line in header_block.split(|byte| *byte == b'\n') {
        let line = strip_cr(line);
        if line.is_empty() {
            continue;
        }

        let text = String::from_utf8_lossy(line);
        let Some((name, value)) = text.split_once(':') else {
            return Err(invalid(format!("header line {text:?} has no colon")));
        };
        let name = name.trim();
        let value = value.trim();
        if name.is_empty() {
            return Err(invalid("a header line has an empty name"));
        }

        if name.eq_ignore_ascii_case("Status") {
            status = Some(parse_status(value)?);
            continue;
        }

        if name.eq_ignore_ascii_case("Location") {
            saw_location = true;
        }
        headers.push((name.to_owned(), value.to_owned()));
    }

    // A redirect without Status is the one implicit status CGI defines.
    let status = status.unwrap_or(if saw_location { 302 } else { 200 });

    Ok(Response {
        status,
        headers,
        body: body.to_vec(),
        stderr: attach_app_status(
            String::from_utf8_lossy(stderr_bytes).into_owned(),
            app_status,
        ),
    })
}

fn split(stdout: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let crlf = find(stdout, b"\r\n\r\n").map(|index| (index, 4));
    let lf = find(stdout, b"\n\n").map(|index| (index, 2));

    let (index, separator_len) = match (crlf, lf) {
        (Some(left), Some(right)) => {
            if left.0 <= right.0 {
                left
            } else {
                right
            }
        }
        (Some(found), None) | (None, Some(found)) => found,
        (None, None) => {
            return Err(invalid(
                "STDOUT has no blank line between the CGI headers and the body",
            ))
        }
    };

    Ok((&stdout[..index], &stdout[index + separator_len..]))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn strip_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn parse_status(value: &str) -> Result<u16, Error> {
    let code = value.split_whitespace().next().unwrap_or_default();
    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid(format!(
            "malformed Status header {value:?}; expected a three-digit code such as 200 OK"
        )));
    }

    let code: u16 = code
        .parse()
        .map_err(|_| invalid(format!("malformed Status header {value:?}")))?;
    if !(100..=599).contains(&code) {
        return Err(invalid(format!(
            "Status header {value:?} is outside the HTTP range 100..=599"
        )));
    }
    Ok(code)
}

fn attach_app_status(mut stderr: String, app_status: u32) -> String {
    if app_status == 0 {
        return stderr;
    }

    // APP_STATUS is how PHP-FPM reports `exit(1)` after it has already sent a
    // valid response. The response is still usable; the exit code belongs in
    // the log, not in the proxy's error path.
    if !stderr.is_empty() && !stderr.ends_with('\n') {
        stderr.push('\n');
    }
    let _ = writeln!(
        stderr,
        "fastcgi: application exited with status {app_status}"
    );
    stderr
}

fn invalid(message: impl Into<String>) -> Error {
    Error::Response(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_stdout(stdout: &[u8]) -> Result<Response, Error> {
        parse(stdout, b"", 0)
    }

    #[test]
    fn default_status_is_200() {
        let response = parse_stdout(b"Content-Type: text/plain\r\n\r\nhello").unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            response.headers,
            vec![("Content-Type".to_owned(), "text/plain".to_owned())]
        );
        assert_eq!(response.body, b"hello");
        assert!(response.stderr.is_empty());
    }

    #[test]
    fn explicit_status_is_parsed_and_excluded_from_headers() {
        let response = parse_stdout(b"Status: 201 Created\r\nX-A: one\r\n\r\nbody").unwrap();
        assert_eq!(response.status, 201);
        assert_eq!(response.headers, vec![("X-A".to_owned(), "one".to_owned())]);
    }

    #[test]
    fn location_without_status_is_a_redirect() {
        let response = parse_stdout(b"Location: /login\r\n\r\n").unwrap();
        assert_eq!(response.status, 302);
        assert_eq!(
            response.headers,
            vec![("Location".to_owned(), "/login".to_owned())]
        );
        assert!(response.body.is_empty());
    }

    #[test]
    fn explicit_status_beats_location() {
        let response =
            parse_stdout(b"Status: 404 Not Found\r\nLocation: /missing\r\n\r\n").unwrap();
        assert_eq!(response.status, 404);
    }

    #[test]
    fn repeated_headers_keep_order_and_case() {
        let response =
            parse_stdout(b"Set-Cookie: a=1\r\nX-Thing: one\r\nset-cookie: b=2\r\n\r\n").unwrap();
        assert_eq!(
            response.headers,
            vec![
                ("Set-Cookie".to_owned(), "a=1".to_owned()),
                ("X-Thing".to_owned(), "one".to_owned()),
                ("set-cookie".to_owned(), "b=2".to_owned()),
            ]
        );
    }

    #[test]
    fn lf_only_headers_are_accepted() {
        let response = parse_stdout(b"Status: 200 OK\nX-A: one\n\nbody").unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"body");
    }

    #[test]
    fn malformed_status_is_rejected() {
        for line in [
            b"Status: banana\r\n\r\n".as_slice(),
            b"Status: 20 OK\r\n\r\n".as_slice(),
            b"Status: 2000 OK\r\n\r\n".as_slice(),
            b"Status: 700 Nope\r\n\r\n".as_slice(),
            b"Status:\r\n\r\n".as_slice(),
        ] {
            let error = parse_stdout(line).unwrap_err();
            assert!(
                matches!(error, Error::Response(ref message) if message.contains("Status")),
                "{line:?} produced {error:?}"
            );
        }
    }

    #[test]
    fn missing_header_terminator_is_rejected() {
        let error = parse_stdout(b"Status: 200 OK\r\nContent-Type: text/plain").unwrap_err();
        assert!(matches!(error, Error::Response(message) if message.contains("blank line")));
    }

    #[test]
    fn header_without_colon_is_rejected() {
        let error = parse_stdout(b"Just a line\r\n\r\n").unwrap_err();
        assert!(matches!(error, Error::Response(message) if message.contains("colon")));
    }

    #[test]
    fn app_status_is_appended_to_stderr() {
        let response = parse(b"Status: 200 OK\r\n\r\nok", b"warn", 3).unwrap();
        assert!(response.stderr.starts_with("warn\n"));
        assert!(response.stderr.contains("status 3"));
    }

    #[test]
    fn stderr_without_app_status_is_preserved() {
        let response = parse(b"Status: 200 OK\r\n\r\nok", b"line one\nline two\n", 0).unwrap();
        assert_eq!(response.stderr, "line one\nline two\n");
    }

    #[test]
    fn somewhat_arbitrary_input_never_panics() {
        let inputs: [&[u8]; 8] = [
            b"",
            b"\r\n",
            b"\r\n\r\n",
            b":\r\n\r\n",
            b"Status: 200 OK\r\nX: \xff\xfe\r\n\r\n\x00\xff",
            b"Status: 200 OK\n\n",
            b"Status: 99 Low\r\n\r\n",
            b"Status: abc\r\n\r\n",
        ];

        for input in inputs {
            let _ = parse(input, b"\xff\xfe", u32::MAX);
        }
    }
}
