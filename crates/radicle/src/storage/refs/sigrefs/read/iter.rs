use radicle_oid::Oid;

use crate::storage::refs::sigrefs::git::object;

use super::{Commit, CommitReader, Spending, error};

pub(super) struct Walk<'a, 's, R> {
    repository: &'a R,
    cursor: Option<Oid>,
    spending: &'s Spending,
}

impl<'a, 's, R> Walk<'a, 's, R> {
    pub fn new(head: Oid, repository: &'a R, spending: &'s Spending) -> Self {
        Self {
            repository,
            cursor: Some(head),
            spending,
        }
    }
}

impl<'a, 's, R: object::Reader> Iterator for Walk<'a, 's, R> {
    type Item = Result<Commit, error::Commit>;

    fn next(&mut self) -> Option<Self::Item> {
        match self
            .cursor
            .map(|commit| CommitReader::new(commit, self.repository, self.spending).read())
        {
            None => None,
            Some(Ok(commit)) => {
                self.cursor = commit.parent;
                Some(Ok(commit))
            }
            Some(Err(err)) => Some(Err(err)),
        }
    }
}
