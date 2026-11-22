//! The direction table for every role answer and role in force.

use oneiron_authority::authority::Direction::{Narrows, Widens};
use oneiron_authority::authority::MachineRole::{
    ExecutionNode, HostedNode, Owned, Removed, Unanswered,
};
use oneiron_authority::authority::{Direction, MachineOwnership, MachineRole};

const YOURS: MachineRole = Owned(MachineOwnership::Yours);
const WORK_SCHOOL: MachineRole = Owned(MachineOwnership::WorkSchool);
const RENTED: MachineRole = Owned(MachineOwnership::Rented);

const TABLE: [(MachineRole, Option<MachineRole>, Direction); 56] = [
    (YOURS, Some(YOURS), Narrows),
    (YOURS, Some(WORK_SCHOOL), Widens),
    (YOURS, Some(RENTED), Widens),
    (YOURS, Some(HostedNode), Widens),
    (YOURS, Some(ExecutionNode), Widens),
    (YOURS, Some(Removed), Widens),
    (YOURS, Some(Unanswered), Widens),
    (YOURS, None, Widens),
    (WORK_SCHOOL, Some(YOURS), Narrows),
    (WORK_SCHOOL, Some(WORK_SCHOOL), Narrows),
    (WORK_SCHOOL, Some(RENTED), Widens),
    (WORK_SCHOOL, Some(HostedNode), Widens),
    (WORK_SCHOOL, Some(ExecutionNode), Widens),
    (WORK_SCHOOL, Some(Removed), Widens),
    (WORK_SCHOOL, Some(Unanswered), Widens),
    (WORK_SCHOOL, None, Widens),
    (RENTED, Some(YOURS), Narrows),
    (RENTED, Some(WORK_SCHOOL), Widens),
    (RENTED, Some(RENTED), Narrows),
    (RENTED, Some(HostedNode), Widens),
    (RENTED, Some(ExecutionNode), Widens),
    (RENTED, Some(Removed), Widens),
    (RENTED, Some(Unanswered), Widens),
    (RENTED, None, Widens),
    (HostedNode, Some(YOURS), Narrows),
    (HostedNode, Some(WORK_SCHOOL), Widens),
    (HostedNode, Some(RENTED), Widens),
    (HostedNode, Some(HostedNode), Narrows),
    (HostedNode, Some(ExecutionNode), Widens),
    (HostedNode, Some(Removed), Widens),
    (HostedNode, Some(Unanswered), Widens),
    (HostedNode, None, Widens),
    (ExecutionNode, Some(YOURS), Narrows),
    (ExecutionNode, Some(WORK_SCHOOL), Widens),
    (ExecutionNode, Some(RENTED), Widens),
    (ExecutionNode, Some(HostedNode), Widens),
    (ExecutionNode, Some(ExecutionNode), Narrows),
    (ExecutionNode, Some(Removed), Widens),
    (ExecutionNode, Some(Unanswered), Widens),
    (ExecutionNode, None, Widens),
    (Removed, Some(YOURS), Narrows),
    (Removed, Some(WORK_SCHOOL), Narrows),
    (Removed, Some(RENTED), Narrows),
    (Removed, Some(HostedNode), Narrows),
    (Removed, Some(ExecutionNode), Narrows),
    (Removed, Some(Removed), Narrows),
    (Removed, Some(Unanswered), Narrows),
    (Removed, None, Narrows),
    (Unanswered, Some(YOURS), Narrows),
    (Unanswered, Some(WORK_SCHOOL), Narrows),
    (Unanswered, Some(RENTED), Narrows),
    (Unanswered, Some(HostedNode), Narrows),
    (Unanswered, Some(ExecutionNode), Narrows),
    (Unanswered, Some(Removed), Narrows),
    (Unanswered, Some(Unanswered), Narrows),
    (Unanswered, None, Narrows),
];

/// Every new role is compared with each standing role and with no agreed role.
#[test]
fn each_role_change_has_the_direction_the_table_gives() {
    for (role, standing, expected) in TABLE {
        assert_eq!(
            role.direction_from(standing),
            expected,
            "{standing:?} to {role:?}"
        );
    }
}
