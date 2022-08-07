/// A marker type that represents correspond data has been successfully verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Verified;

/// A marker type that represents correspond data has not been verified yet.
///
/// Don't believe, verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Yet;
