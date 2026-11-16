//! The authority rule's table (`oneiron_authority::authority::Permitted`): what each reading
//! admits, the lesser of two readings, and the witness of an admitted move. A changed cell
//! here is a change of the rule, and raises `AUTHORITY_RULE_VERSION` with it.

use oneiron_authority::authority::{AUTHORITY_RULE_VERSION, Admitted, Direction, Permitted};

/// The scale, least first.
const SCALE: [Permitted; 4] = [
    Permitted::Nothing,
    Permitted::NarrowingOnly,
    Permitted::NoWidening,
    Permitted::AnyMove,
];

const DIRECTIONS: [Direction; 3] = [Direction::Narrows, Direction::Neutral, Direction::Widens];

/// The twelve cells: per reading, whether it admits a narrowing, a neutral change, a widening.
const TABLE: [(Permitted, [bool; 3]); 4] = [
    (Permitted::Nothing, [false, false, false]),
    (Permitted::NarrowingOnly, [true, false, false]),
    (Permitted::NoWidening, [true, true, false]),
    (Permitted::AnyMove, [true, true, true]),
];

#[test]
fn each_reading_admits_its_directions_and_no_other() {
    assert_eq!(
        AUTHORITY_RULE_VERSION, 1,
        "a changed cell raises the rule's version"
    );
    for (reading, cells) in TABLE {
        for (direction, admitted) in DIRECTIONS.into_iter().zip(cells) {
            assert_eq!(
                reading.admits(direction),
                admitted,
                "{reading:?} on a move that {direction:?}"
            );
        }
    }
}

#[test]
fn an_act_may_do_the_lesser_of_its_actors_reading_and_its_entrys() {
    for (actor_rank, actor) in SCALE.into_iter().enumerate() {
        for (entry_rank, entry) in SCALE.into_iter().enumerate() {
            assert_eq!(
                actor.limited_by(entry),
                SCALE[actor_rank.min(entry_rank)],
                "an actor's {actor:?} limited by an entry's {entry:?}"
            );
        }
    }
}

#[test]
fn only_an_admitted_move_gets_the_witness_and_it_names_the_direction() {
    for (reading, cells) in TABLE {
        for (direction, admitted) in DIRECTIONS.into_iter().zip(cells) {
            let witness = reading.admit(direction);
            assert_eq!(
                witness.as_ref().map(Admitted::direction),
                admitted.then_some(direction),
                "{reading:?} asked for a move that {direction:?}"
            );
        }
    }
}
