use crate::md::md2::*;

#[test]
fn md2_example_1() {
    assert_eq!(md2("".as_bytes()), 0x_8350e5a3e24c153df2275c9f80692773_u128.to_be_bytes());
}

#[test]
fn md2_example_2() {
    assert_eq!(md2("The quick brown fox jumps over the lazy dog".as_bytes()), 0x_03d85a0d629d2c442e987525319fc471_u128.to_be_bytes());
}

#[test]
fn md2_example_3() {
    assert_eq!(md2("The quick brown fox jumps over the lazy cog".as_bytes()), 0x_6b890c9292668cdbbfda00a4ebf31f05_u128.to_be_bytes());
}
