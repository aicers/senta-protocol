//! The store of each entry, which the test implements itself: it keeps the
//! trait's contract (an atomic `write`, records and loss records only
//! added, `has_lost_on_reset`), and lets the test take its contents as a
//! snapshot, put a snapshot back, empty it, and fail the next write. Every
//! write that succeeds is logged apart from the contents, so restoring the
//! contents does not shorten what was committed.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::rc::Rc;

use senta_protocol::telemetry::{
    ReceiverChange, ReceiverEntryState, ReceiverFlowKey, ReceiverFlowState, ReceiverLoss,
    ReceiverLossReason, ReceiverRecord, ReceiverStore, SeqRange,
};
use uuid::Uuid;

/// What an entry's store holds.
#[derive(Debug, Clone, Default)]
pub struct Contents {
    pub flows: BTreeMap<ReceiverFlowKey, ReceiverFlowState>,
    pub records: Vec<ReceiverRecord>,
    pub losses: Vec<ReceiverLoss>,
    lost_on_reset: BTreeSet<(Uuid, Uuid, u64, u64)>,
}

impl Contents {
    /// The `lost_on_reset` loss records of `stream`, in the order written.
    pub fn lost_on_reset(&self, endpoint_id: Uuid, stream: Uuid) -> Vec<(u64, u64)> {
        self.losses
            .iter()
            .filter(|loss| {
                loss.endpoint_id == endpoint_id
                    && loss.stream == stream
                    && loss.reason == ReceiverLossReason::LostOnReset
            })
            .map(|loss| (loss.range.from, loss.range.to))
            .collect()
    }
}

#[derive(Debug, Default)]
struct Inner {
    contents: Contents,
    fail_next: bool,
    /// Makes every write drop the records it holds: a store that loses
    /// what it acknowledges. Only a mutation test turns it on.
    drop_records: bool,
    log: Vec<Vec<ReceiverChange>>,
}

/// The injected failure of a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Injected;

impl fmt::Display for Injected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("injected write failure")
    }
}

/// A handle to one entry's store.
#[derive(Debug, Clone)]
pub struct TestStore {
    entry: Uuid,
    inner: Rc<RefCell<Inner>>,
}

impl TestStore {
    pub fn new(entry: Uuid) -> Self {
        Self {
            entry,
            inner: Rc::default(),
        }
    }

    pub fn contents(&self) -> Contents {
        self.inner.borrow().contents.clone()
    }

    pub fn set_contents(&self, contents: Contents) {
        self.inner.borrow_mut().contents = contents;
    }

    pub fn lost_on_reset(&self, endpoint_id: Uuid, stream: Uuid) -> Vec<(u64, u64)> {
        self.inner
            .borrow()
            .contents
            .lost_on_reset(endpoint_id, stream)
    }

    pub fn fail_next_write(&self, fail: bool) {
        self.inner.borrow_mut().fail_next = fail;
    }

    pub fn armed(&self) -> bool {
        self.inner.borrow().fail_next
    }

    pub fn drop_records(&self, drop: bool) {
        self.inner.borrow_mut().drop_records = drop;
    }

    /// Takes the writes that succeeded since the last call.
    pub fn take_log(&self) -> Vec<Vec<ReceiverChange>> {
        std::mem::take(&mut self.inner.borrow_mut().log)
    }
}

impl ReceiverStore for TestStore {
    type Error = Injected;

    fn load(&self, entry_id: Uuid) -> Result<ReceiverEntryState, Injected> {
        assert_eq!(entry_id, self.entry, "an entry reads another's store");
        Ok(ReceiverEntryState {
            flows: self.inner.borrow().contents.flows.clone(),
        })
    }

    fn has_lost_on_reset(
        &self,
        entry_id: Uuid,
        endpoint_id: Uuid,
        stream: Uuid,
        range: SeqRange,
    ) -> Result<bool, Injected> {
        assert_eq!(entry_id, self.entry, "an entry reads another's store");
        Ok(self.inner.borrow().contents.lost_on_reset.contains(&(
            endpoint_id,
            stream,
            range.from,
            range.to,
        )))
    }

    fn write(&mut self, entry_id: Uuid, changes: Vec<ReceiverChange>) -> Result<(), Injected> {
        assert_eq!(entry_id, self.entry, "an entry writes another's store");
        let mut inner = self.inner.borrow_mut();
        if inner.fail_next {
            inner.fail_next = false;
            return Err(Injected);
        }
        let changes: Vec<ReceiverChange> = if inner.drop_records {
            changes
                .into_iter()
                .filter(|change| !matches!(change, ReceiverChange::AppendRecord(_)))
                .collect()
        } else {
            changes
        };
        let contents = &mut inner.contents;
        for change in &changes {
            match change {
                ReceiverChange::SetFlow { key, state } => {
                    contents.flows.insert(*key, *state);
                }
                ReceiverChange::RemoveFlow(key) => {
                    contents.flows.remove(key);
                }
                ReceiverChange::AppendRecord(record) => contents.records.push(record.clone()),
                ReceiverChange::AppendLoss(loss) => {
                    if loss.reason == ReceiverLossReason::LostOnReset {
                        contents.lost_on_reset.insert((
                            loss.endpoint_id,
                            loss.stream,
                            loss.range.from,
                            loss.range.to,
                        ));
                    }
                    contents.losses.push(loss.clone());
                }
            }
        }
        inner.log.push(changes);
        Ok(())
    }
}
