//! A project's asks queue (ARCH-0067 tasks and asks). An ask on a TASK goes
//! to the project whose task list holds it: that placement is the project's
//! own row, never the ask's text, and the project's current leader and board
//! answer it at once. The ask is the ordinary TASK ask; the list is content
//! and the route is a record, never an authority grant.
use super::*;

const PROJECT_ASKS: SideTable<EntityId, ProjectAsk, Named> =
    SideTable::new(&side_table::PROJECT_ASK);

fn unplaced() -> Error {
    RecordError::InvalidProjectBody("task is not placed in a project that serves authority").into()
}

/// Where one project ask went: the project, the TASK that placed it there and
/// the ask's handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectAsk {
    pub project: EntityId,
    pub task: EntityId,
    pub ask: EntityId,
}

impl Vault {
    /// The served project whose task list holds `task` in this snapshot, if
    /// any. A TASK on two served projects' lists is refused, never guessed.
    pub(crate) fn task_served_project_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        task: EntityId,
    ) -> Result<Option<EntityId>> {
        let Some(reader) = ProjectReader::new(&self.store, txn, self.privacy_posture())? else {
            return Ok(None);
        };
        let task = task.to_hex();
        let mut placed = None;
        for (id, record, verdict) in reader.all()? {
            if verdict != ProjectVerdict::Visible || !record.tasks.contains(&task) {
                continue;
            }
            if placed.replace(id).is_some() {
                return Err(RecordError::InvalidProjectBody(
                    "task is placed in more than one project",
                )
                .into());
            }
        }
        match placed {
            Some(id) if reader.effective(id)?.is_some() => Ok(Some(id)),
            _ => Ok(None),
        }
    }

    /// The project `task` is placed in, and who an ask on it goes to: that
    /// project's effective leader and board, as its signed history folds
    /// them in this snapshot. A TASK on no served project's list, or on two,
    /// routes nowhere.
    pub(crate) fn project_ask_route_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        task: EntityId,
    ) -> Result<(EntityId, BTreeSet<EntityId>)> {
        let project = self
            .task_served_project_in_txn(txn, task)?
            .ok_or_else(unplaced)?;
        let (_, effective) = self
            .effective_project_in_txn(txn, project)?
            .ok_or_else(unplaced)?;
        let holders = std::iter::once(&effective.leader)
            .chain(&effective.board)
            .map(|id| EntityId::from_hex(id))
            .collect::<Result<BTreeSet<_>>>()?;
        Ok((project, holders))
    }

    /// Appends the ask to its project's list and records its route, inside
    /// the ask's own admission transaction.
    pub(crate) fn append_project_ask_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        route: &ProjectAsk,
    ) -> Result<()> {
        let (mut project, _) = self
            .effective_project_in_txn(txn, route.project)?
            .ok_or_else(unplaced)?;
        PROJECT_ASKS.put(&self.store, txn, &route.ask, route)?;
        if !project.asks.contains(&route.ask.to_hex()) {
            project.asks.push(route.ask.to_hex());
        }
        let now = self.store.clock.now_recorded_at();
        self.batch_in()
            .put(
                &route.project,
                self.project_type_byte()?,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &encode(&project)?,
            )
            .apply(txn)?;
        Ok(())
    }

    /// A project's asks list with its effective view, which decides who may
    /// read the list; `None` when the project serves no authority.
    pub(crate) fn project_asks_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        project: EntityId,
    ) -> Result<Option<(ProjectEffective, Vec<EntityId>)>> {
        let Some((record, effective)) = self.effective_project_in_txn(txn, project)? else {
            return Ok(None);
        };
        let asks = record
            .asks
            .iter()
            .map(|ask| EntityId::from_hex(ask))
            .collect::<Result<Vec<_>>>()?;
        Ok(Some((effective, asks)))
    }

    /// The route of a project ask, not an authority grant.
    pub fn project_ask_route(&self, ask: EntityId) -> Result<Option<ProjectAsk>> {
        let txn = self.store.env.read_txn()?;
        PROJECT_ASKS.get(&self.store, &txn, &ask)
    }
}
