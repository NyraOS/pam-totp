// SPDX-License-Identifier: MIT
//! User names and uids from the local user list (`/etc/passwd`), the only source both the `2fa`
//! command and the PAM module use, so they always agree on which state file belongs to whom.

/// The local user list on a Nyra OS server.
pub const PASSWD: &str = "/etc/passwd";

/// The name and uid of each well-formed line of a passwd file, in file order. Lines that do not
/// parse are skipped.
pub fn entries(text: &str) -> impl Iterator<Item = (&str, u32)> {
    text.lines().filter_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let uid = fields.nth(1)?.parse::<u32>().ok()?;
        Some((name, uid))
    })
}

/// The uid of the first entry named `name`, as the C library would find it.
pub fn uid_of(text: &str, name: &str) -> Option<u32> {
    entries(text).find(|&(n, _)| n == name).map(|(_, uid)| uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_first_entry() {
        let text = "root:x:0:0::/root:/bin/sh\nbroken\nmaria:x:1000:1000::/h:/bin/sh\n\
                    bad:x:notanumber:1::/:/bin/sh\nmaria:x:2000:2000::/h:/bin/sh\n";
        assert_eq!(uid_of(text, "root"), Some(0));
        assert_eq!(uid_of(text, "maria"), Some(1000));
        assert_eq!(uid_of(text, "bad"), None);
        assert_eq!(uid_of(text, "broken"), None);
        assert_eq!(uid_of(text, "nobody"), None);
        assert_eq!(uid_of(text, ""), None);
        assert_eq!(entries(text).count(), 3);
    }
}
