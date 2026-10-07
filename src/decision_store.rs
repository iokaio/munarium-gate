// SPDX-License-Identifier: Apache-2.0
//! Durable recording intent. It never contains an execution grant or dispatch instruction.
use crate::decision::Error;
use rusqlite::{Connection, OptionalExtension};
use std::{
    fs::{File, OpenOptions},
    path::Path,
};

pub struct Stored {
    pub receipt: Vec<u8>,
    pub events: Vec<String>,
    pub complete: bool,
}
pub struct Store {
    connection: Connection,
    _custody: File,
}
fn failure(_: rusqlite::Error) -> Error {
    Error::Recording
}
impl Store {
    pub fn open(path: &Path) -> Result<Self, Error> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .map_err(|_| Error::Recording)?;
        let mut lock = path
            .canonicalize()
            .map_err(|_| Error::Recording)?
            .into_os_string();
        lock.push(".lock");
        let custody = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(std::path::PathBuf::from(lock))
            .map_err(|_| Error::Recording)?;
        custody.try_lock().map_err(|_| Error::Recording)?;
        drop(file);
        let connection = Connection::open(path).map_err(failure)?;
        connection
            .busy_timeout(std::time::Duration::from_millis(500))
            .map_err(failure)?;
        connection.execute_batch("PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS decisions(tenant TEXT NOT NULL, operation TEXT NOT NULL, request BLOB NOT NULL,
                receipt BLOB NOT NULL, events TEXT NOT NULL, complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN(0,1)),
                PRIMARY KEY(tenant,operation));
            CREATE TRIGGER IF NOT EXISTS decisions_no_delete BEFORE DELETE ON decisions BEGIN SELECT RAISE(ABORT,'immutable decision'); END;
            CREATE TRIGGER IF NOT EXISTS decisions_no_change BEFORE UPDATE ON decisions
                WHEN NEW.tenant!=OLD.tenant OR NEW.operation!=OLD.operation OR NEW.request!=OLD.request OR NEW.receipt!=OLD.receipt OR NEW.events!=OLD.events
                     OR NEW.complete<OLD.complete BEGIN SELECT RAISE(ABORT,'immutable decision'); END;")
            .map_err(failure)?;
        Ok(Self {
            connection,
            _custody: custody,
        })
    }
    pub fn lookup(&self, tenant: &str, operation: &str) -> Result<Option<Stored>, Error> {
        let row: Option<(Vec<u8>, String, bool)> = self
            .connection
            .query_row(
                "SELECT receipt,events,complete FROM decisions WHERE tenant=?1 AND operation=?2",
                [tenant, operation],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(failure)?;
        row.map(|(receipt, events, complete)| {
            Ok(Stored {
                receipt,
                events: serde_json::from_str(&events).map_err(|_| Error::Recording)?,
                complete,
            })
        })
        .transpose()
    }
    pub fn pending(&self) -> Result<bool, Error> {
        self.connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM decisions WHERE complete=0)",
                [],
                |r| r.get(0),
            )
            .map_err(failure)
    }
    pub fn prepare(
        &self,
        tenant: &str,
        operation: &str,
        request: &[u8],
        receipt: &[u8],
        events: &[String],
    ) -> Result<(), Error> {
        if self.pending()? {
            return Err(Error::Recording);
        }
        let events = serde_json::to_string(events).map_err(|_| Error::Recording)?;
        self.connection.execute("INSERT INTO decisions(tenant,operation,request,receipt,events) VALUES(?1,?2,?3,?4,?5)",
            rusqlite::params![tenant,operation,request,receipt,events]).map_err(failure)?;
        Ok(())
    }
    pub fn complete(&self, tenant: &str, operation: &str) -> Result<(), Error> {
        if self
            .connection
            .execute(
                "UPDATE decisions SET complete=1 WHERE tenant=?1 AND operation=?2",
                [tenant, operation],
            )
            .map_err(failure)?
            != 1
        {
            return Err(Error::Recording);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn intent_survives_restart_and_blocks_new_work_until_acknowledged() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("decisions.sqlite");
        let store = Store::open(&path).unwrap();
        assert!(Store::open(&path).is_err());
        store
            .prepare(
                "alpha",
                "operation",
                b"request",
                b"receipt",
                &["event".into()],
            )
            .unwrap();
        assert!(
            store
                .prepare("alpha", "other", b"other", b"other", &[])
                .is_err()
        );
        drop(store);
        let store = Store::open(&path).unwrap();
        let record = store.lookup("alpha", "operation").unwrap().unwrap();
        assert_eq!(record.receipt, b"receipt");
        assert_eq!(record.events, ["event"]);
        assert!(!record.complete);
        assert!(store.lookup("beta", "operation").unwrap().is_none());
        assert!(
            store
                .connection
                .execute("DELETE FROM decisions", [])
                .is_err()
        );
        assert!(
            store
                .connection
                .execute("UPDATE decisions SET receipt=x'00'", [])
                .is_err()
        );
        store.complete("alpha", "operation").unwrap();
        assert!(!store.pending().unwrap());
        assert!(
            store
                .connection
                .execute("UPDATE decisions SET complete=0", [])
                .is_err()
        );
        store
            .prepare("alpha", "other", b"other", b"other", &[])
            .unwrap();
    }
}
