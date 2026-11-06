use nom::{
    branch::alt,
    bytes::complete::{is_not, tag, take_while1},
    character::complete::{char, multispace0},
    combinator::{cut, map, not, opt, peek},
    multi::{many0, many1},
    sequence::{delimited, preceded, terminated},
    IResult, Parser,
};

use super::selector::{AttrOperator, AttrValue, Attribute, Combinator, MiniSelector};

fn parse_name(input: &str) -> IResult<&str, &str> {
    map(
        take_while1(|c: char| c.is_ascii_alphanumeric() || c == '-'),
        |s| s,
    )
    .parse(input)
}

fn parse_id(input: &str) -> IResult<&str, &str> {
    preceded(
        char('#'),
        map(
            take_while1(|c: char| c.is_ascii_alphanumeric() || c == '-'),
            |s| s,
        ),
    )
    .parse(input)
}

fn parse_classes(input: &str) -> IResult<&str, Vec<&str>> {
    many1(preceded(
        char('.'),
        map(
            take_while1(|c: char| c.is_ascii_alphanumeric() || c == '-'),
            |s| s,
        ),
    ))
    .parse(input)
}

fn parse_attr_key(input: &str) -> IResult<&str, &str> {
    take_while1(|c: char| c.is_ascii_alphanumeric() || c == '-').parse(input)
}

fn parse_attr_operator(input: &str) -> IResult<&str, AttrOperator> {
    delimited(
        multispace0,
        alt((
            map(tag("~="), |_| AttrOperator::Includes),
            map(tag("|="), |_| AttrOperator::DashMatch),
            map(tag("^="), |_| AttrOperator::Prefix),
            map(tag("$="), |_| AttrOperator::Suffix),
            map(tag("*="), |_| AttrOperator::Substring),
            map(tag("="), |_| AttrOperator::Equals),
        )),
        multispace0,
    )
    .parse(input)
}

fn parse_attr_value(input: &str) -> IResult<&str, AttrValue<'_>> {
    let (input, op) = parse_attr_operator(input)?;
    let (input, value) = alt((
        preceded(char('"'), cut(terminated(is_not("\""), char('"')))),
        preceded(char('\''), cut(terminated(is_not("\'"), char('\'')))),
        take_while1(|c: char| c != ']'),
    ))
    .parse(input)?;
    Ok((input, AttrValue { op, value }))
}

fn parse_attr(input: &str) -> IResult<&str, Attribute<'_>> {
    let (input, (key, value)) = delimited(
        char('['),
        (parse_attr_key, opt(parse_attr_value)),
        char(']'),
    )
    .parse(input)?;

    Ok((input, Attribute { key, value }))
}

fn parse_attrs(input: &str) -> IResult<&str, Vec<Attribute<'_>>> {
    many1(terminated(parse_attr, peek(not(char(']'))))).parse(input)
}

fn parse_combinator(input: &str) -> IResult<&str, Combinator> {
    delimited(
        multispace0,
        alt((
            map(tag(">"), |_| Combinator::Child),
            map(tag("+"), |_| Combinator::Adjacent),
            map(tag("~"), |_| Combinator::Sibling),
        )),
        multispace0,
    )
    .parse(input)
}

/// Parses a [`MiniSelector`] from the input.
///
/// # Errors
///
/// Returns an [`nom::Err`] if the function was failed to create a [`MiniSelector`] from the string.
pub fn parse_mini_selector(input: &str) -> IResult<&str, MiniSelector<'_>> {
    let (input, combinator) = opt(parse_combinator).parse(input)?;
    let (input, name) = opt(parse_name).parse(input)?;
    let (input, id) = opt(parse_id).parse(input)?;
    let (input, classes) = opt(parse_classes).parse(input)?;
    let (input, attrs) = opt(parse_attrs).parse(input)?;

    if name.is_none()
        && id.is_none()
        && classes.is_none()
        && attrs.is_none()
        && combinator.is_none()
    {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Fail,
        )));
    }

    let combinator = combinator.unwrap_or(Combinator::Descendant);

    let sel = MiniSelector {
        name,
        id,
        classes,
        attrs,
        combinator,
    };
    Ok((input, sel))
}

/// Parses a selector list. A selector list is a sequence of selectors separated by commas.
/// Each selector can be a simple path or a compound path (e.g., `div > a[href="example"] + span.class-1.class-2`).
///
/// # Errors
///
/// Returns an [`nom::Err`] if the function was failed to create a selector list from the string.
pub fn parse_selector_list(input: &str) -> IResult<&str, Vec<MiniSelector<'_>>> {
    let mut parser = many0(delimited(multispace0, parse_mini_selector, multispace0));
    let (input, selectors) = parser.parse(input)?;
    Ok((input, selectors))
}
