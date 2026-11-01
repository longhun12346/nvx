//! The command-line parser of `nvx-rs`: long options that take one value or none, and
//! positionals that take exactly one value or at most one.
//!
//! - Each argument before the first `--` is classified on its own: a known option, as `--option`
//!   or `--option=VALUE`, is an option; an argument that does not start with `-`, a lone `-`, one
//!   that starts like a negative number in ASCII digits, such as `-1` or `-.5`, and one that
//!   contains a space are positionals; and any other argument that starts with `-` is an unknown
//!   option. The first `--` ends the options: it is no argument itself, and every argument after
//!   it is a positional.
//! - The arguments are consumed from left to right. An option takes its value after `=`, or else
//!   the next argument if that is a positional, so a value that starts with `-` needs the
//!   `--option=VALUE` form. The positionals of the parser take the positional arguments in order,
//!   and an optional positional that none is left for takes no value.
//! - Each value is handed to the caller as it is consumed, so conversion and choice errors
//!   surface in command-line order, as `argument NAME: MESSAGE`, and end the parse.
//! - Unknown options, and positional arguments beyond those that the parser takes, are returned
//!   for the caller to report last, as `unrecognized arguments: ...`.
//! - `-h` and `--help` stop the parse for the help as soon as they are consumed.
//!
//! Option names are never abbreviated, so `--dry` is an unknown option rather than `--dry-run`.
//!
//! [`Syntax`] holds what a parser's usage and help show. The usage is one line, which names the
//! parser's few options, or `[OPTIONS]` for many, and the help lists every option.

use std::fmt;
use std::ops::RangeInclusive;
use std::str::FromStr;

use crate::ErrorCode;
use crate::host::sandbox::parse_decimal;

/// The name of the program in usage and error messages.
const PROGRAM: &str = "nvx-rs";
/// What usage messages start with.
const USAGE_PREFIX: &str = "usage: ";

/// What the usage and help of a parser show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Syntax {
    /// The command of the parser after the program's name, such as `sandbox`, or nothing for the
    /// top-level parser.
    pub(crate) command: &'static str,
    /// What the usage shows after the parser's name: its options, such as `[-h] [--root PATH]`,
    /// or `[OPTIONS]` for a parser with many, and its positionals, such as `PATH`.
    pub(crate) arguments: &'static str,
    /// The help after the usage and its blank line: the description and the sections of the
    /// arguments, without a final line end.
    pub(crate) help: &'static str,
}

impl Syntax {
    /// Returns the parser's name, such as `nvx-rs sandbox`, which starts its usage errors.
    pub(crate) fn prog(&self) -> String {
        if self.command.is_empty() {
            PROGRAM.to_owned()
        } else {
            format!("{PROGRAM} {}", self.command)
        }
    }

    /// Returns the usage, `usage: PROG ARGUMENTS`, on one line without a line end.
    pub(crate) fn usage(&self) -> String {
        format!("{USAGE_PREFIX}{} {}", self.prog(), self.arguments)
    }

    /// Returns the help: the usage, a blank line, and the rest.
    pub(crate) fn help(&self) -> String {
        format!("{}\n\n{}", self.usage(), self.help)
    }

    /// Asserts that the help lists `-h, --help` and each of `options`, and no other option: the
    /// options that the help describes on lines of their own, indented by two spaces.
    #[cfg(test)]
    pub(crate) fn assert_lists(&self, options: &[Spec]) {
        let mut listed: Vec<&str> = self
            .help
            .lines()
            .filter(|line| line.starts_with("  -"))
            .filter_map(|line| line.split_whitespace().find(|word| word.starts_with("--")))
            .collect();
        let mut expected: Vec<&str> = std::iter::once("--help")
            .chain(options.iter().map(|option| option.name))
            .collect();
        listed.sort_unstable();
        expected.sort_unstable();
        assert_eq!(listed, expected, "{}", self.prog());
    }
}

/// How a parse ends early: with a usage error, or with the help that `-h` asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Stop {
    /// `PROG: error[CODE]: MESSAGE` after the parser's usage, with status 2: the code, one of the
    /// `argument-*` codes, and the message.
    Usage(ErrorCode, String),
    /// The help text, on standard output, with status 0.
    Help,
}

/// How many values an option or positional takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arity {
    /// No value: a flag.
    Flag,
    /// Exactly one value.
    One,
    /// At most one value: an optional positional.
    Optional,
}

/// An argument that the parser recognizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Spec {
    /// The option string, such as `--layer`, or the name with which messages refer to a
    /// positional, such as `sandbox_operation`.
    pub(crate) name: &'static str,
    /// How many values it takes.
    pub(crate) arity: Arity,
}

impl Spec {
    /// An option that takes no value.
    pub(crate) const fn flag(name: &'static str) -> Self {
        Self {
            name,
            arity: Arity::Flag,
        }
    }

    /// An option or positional that takes exactly one value.
    pub(crate) const fn one(name: &'static str) -> Self {
        Self {
            name,
            arity: Arity::One,
        }
    }

    /// A positional that takes at most one value.
    pub(crate) const fn optional(name: &'static str) -> Self {
        Self {
            name,
            arity: Arity::Optional,
        }
    }

    /// Consumes this option, given `attached`, the value after `=` if any, and `next`, the
    /// argument after the option if it is a positional: hands the option's value to `receiver`,
    /// and returns how many arguments the option and its value take. `-h` and `--help` stop the
    /// parse for the help, and messages call them `-h/--help`.
    fn consume(
        self,
        attached: Option<&str>,
        next: Option<&str>,
        receiver: &mut dyn Receiver,
    ) -> Result<usize, Stop> {
        let help = self.name == "-h" || self.name == "--help";
        let label = if help { "-h/--help" } else { self.name };
        let mut take = |value: Option<&str>| take(receiver, self.name, label, value);
        match (self.arity, attached) {
            (Arity::Flag, Some(value)) => Err(Stop::Usage(
                ErrorCode::ArgumentInvalid,
                format!("argument {label}: ignored explicit argument {value:?}"),
            )),
            (Arity::Flag, None) if help => Err(Stop::Help),
            (Arity::Flag, None) => take(None).map(|()| 1),
            (_, Some(value)) => take(Some(value)).map(|()| 1),
            (_, None) => match next {
                Some(value) => take(Some(value)).map(|()| 2),
                None => Err(Stop::Usage(
                    ErrorCode::ArgumentMissing,
                    format!("argument {label}: expected one argument"),
                )),
            },
        }
    }
}

/// Receives each argument as the parser consumes it, in command-line order.
pub(crate) trait Receiver {
    /// Takes `value` for the option or positional `name`: `None` for a flag, and for an optional
    /// positional that received no value, which then takes its default. An error message ends
    /// the parse as `argument NAME: MESSAGE`.
    fn take(&mut self, name: &'static str, value: Option<&str>) -> Result<(), String>;
}

impl<F: FnMut(&'static str, Option<&str>) -> Result<(), String>> Receiver for F {
    fn take(&mut self, name: &'static str, value: Option<&str>) -> Result<(), String> {
        self(name, value)
    }
}

/// Hands `value` to `receiver` for the option or positional `name`, turning its error into the
/// usage error `argument LABEL: MESSAGE`.
fn take(
    receiver: &mut dyn Receiver,
    name: &'static str,
    label: &str,
    value: Option<&str>,
) -> Result<(), Stop> {
    receiver.take(name, value).map_err(|message| {
        Stop::Usage(
            ErrorCode::ArgumentInvalid,
            format!("argument {label}: {message}"),
        )
    })
}

/// A parser of options and positionals.
pub(crate) struct Parser {
    /// The options, such as `--layer`, and `-h` and `--help`, which every parser has.
    options: Vec<Spec>,
    /// The positionals, in order.
    positionals: Vec<Spec>,
}

/// What an argument is to a parser, as [`Parser::token`] classifies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token<'a> {
    /// A known option, with the value attached after `=`, if any.
    Option(Spec, Option<&'a str>),
    /// An option-like argument that the parser does not know.
    Unknown,
    /// A positional value.
    Positional,
    /// The `--` that ends the options.
    End,
}

impl Parser {
    /// Returns the parser of `options` and `positionals`, which also knows `-h` and `--help`.
    pub(crate) fn new(options: &[Spec], positionals: &[Spec]) -> Self {
        let mut all = vec![Spec::flag("-h"), Spec::flag("--help")];
        all.extend_from_slice(options);
        Self {
            options: all,
            positionals: positionals.to_vec(),
        }
    }

    /// Classifies one argument before the options end, as the [module](self) describes.
    fn token<'a>(&self, argument: &'a str) -> Token<'a> {
        if argument == "--" {
            return Token::End;
        }
        if !argument.starts_with('-') || argument == "-" {
            return Token::Positional;
        }
        if let Some(spec) = self.option(argument) {
            return Token::Option(spec, None);
        }
        if let Some((name, value)) = argument.split_once('=')
            && let Some(spec) = self.option(name)
        {
            return Token::Option(spec, Some(value));
        }
        if looks_like_negative_number(argument) || argument.contains(' ') {
            return Token::Positional;
        }
        Token::Unknown
    }

    /// Returns the option whose string is `name`.
    fn option(&self, name: &str) -> Option<Spec> {
        self.options.iter().find(|spec| spec.name == name).copied()
    }

    /// Returns `argument`, the argument after an option, if the option may take it as its value:
    /// if it is a positional.
    fn value<'a>(&self, argument: Option<&'a String>) -> Option<&'a str> {
        argument
            .map(String::as_str)
            .filter(|&value| self.token(value) == Token::Positional)
    }

    /// Walks `arguments` up to the command that the parser's last positional names, for a parser
    /// whose command takes all the arguments after it: the options before the command go to
    /// `receiver`, unknown ones are collected, and the arguments from the command on are the
    /// command's. Returns the index of the command, which `--` may precede, and the unknown
    /// arguments.
    pub(crate) fn split_command(
        &self,
        arguments: &[String],
        receiver: &mut dyn Receiver,
    ) -> Result<(usize, Vec<String>), Stop> {
        let command = self.positionals.last().map_or("command", |spec| spec.name);
        let missing = || {
            Stop::Usage(
                ErrorCode::ArgumentMissing,
                format!("the following arguments are required: {command}"),
            )
        };
        let mut extras = Vec::new();
        let mut index = 0;
        loop {
            let argument = arguments.get(index).ok_or_else(missing)?;
            match self.token(argument) {
                Token::End => {
                    return if index + 1 < arguments.len() {
                        Ok((index + 1, extras))
                    } else {
                        Err(missing())
                    };
                }
                Token::Positional => return Ok((index, extras)),
                Token::Unknown => {
                    extras.push(argument.clone());
                    index += 1;
                }
                Token::Option(spec, attached) => {
                    let next = self.value(arguments.get(index + 1));
                    index += spec.consume(attached, next, receiver)?;
                }
            }
        }
    }

    /// Parses `arguments`, handing each value to `receiver` as the [module](self) describes, and
    /// returns the arguments that the parser does not recognize, for the caller to report.
    pub(crate) fn parse(
        &self,
        arguments: &[String],
        receiver: &mut dyn Receiver,
    ) -> Result<Vec<String>, Stop> {
        let mut extras = Vec::new();
        let mut positionals = self.positionals.iter();
        let mut ended = false;
        let mut index = 0;
        while let Some(argument) = arguments.get(index) {
            let token = if ended {
                Token::Positional
            } else {
                self.token(argument)
            };
            index += match token {
                Token::End => {
                    ended = true;
                    1
                }
                Token::Option(spec, attached) => {
                    spec.consume(attached, self.value(arguments.get(index + 1)), receiver)?
                }
                Token::Unknown => {
                    extras.push(argument.clone());
                    1
                }
                Token::Positional => {
                    match positionals.next() {
                        Some(spec) => take(receiver, spec.name, spec.name, Some(argument))?,
                        None => extras.push(argument.clone()),
                    }
                    1
                }
            };
        }
        let mut missing = Vec::new();
        for spec in positionals {
            match spec.arity {
                Arity::One => missing.push(spec.name),
                Arity::Optional | Arity::Flag => take(receiver, spec.name, spec.name, None)?,
            }
        }
        if !missing.is_empty() {
            return Err(Stop::Usage(
                ErrorCode::ArgumentMissing,
                format!(
                    "the following arguments are required: {}",
                    missing.join(", ")
                ),
            ));
        }
        Ok(extras)
    }
}

/// Returns whether `argument` starts like a negative number: `-` and an ASCII digit, or `-.` and
/// an ASCII digit.
fn looks_like_negative_number(argument: &str) -> bool {
    let rest = argument.strip_prefix('-').unwrap_or(argument);
    let rest = rest.strip_prefix('.').unwrap_or(rest);
    rest.starts_with(|character: char| character.is_ascii_digit())
}

/// Returns the message for `value` that is not one of `choices`, each quoted with Rust's debug
/// formatting, such as `invalid choice: "x" (choose from "auto", "whp")`.
pub(crate) fn invalid_choice(value: &str, choices: &[&str]) -> String {
    let listed: Vec<String> = choices.iter().map(|choice| format!("{choice:?}")).collect();
    format!(
        "invalid choice: {value:?} (choose from {})",
        listed.join(", ")
    )
}

/// Returns the choice that `value` names among `choices`, which it must equal.
pub(crate) fn choice(
    value: &str,
    choices: &[&'static str],
) -> std::result::Result<&'static str, String> {
    choices
        .iter()
        .find(|choice| **choice == value)
        .copied()
        .ok_or_else(|| invalid_choice(value, choices))
}

/// Returns the integer that `value` spells in ASCII decimal digits, if it lies in `range`.
///
/// `value` holds one or more ASCII digits, leading zeros included, and nothing else: no sign,
/// whitespace, underscore, or digit of another script. Fails with `expected an ASCII decimal
/// integer between MIN and MAX, not "VALUE"`, whose bounds are those of `range`.
pub(crate) fn integer<T>(value: &str, range: RangeInclusive<T>) -> std::result::Result<T, String>
where
    T: FromStr + PartialOrd + fmt::Display,
{
    parse_decimal(value)
        .filter(|number| range.contains(number))
        .ok_or_else(|| {
            format!(
                "expected an ASCII decimal integer between {} and {}, not {value:?}",
                range.start(),
                range.end()
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records what the parser hands over, refusing the value `bad`.
    #[derive(Default)]
    struct Recorder(Vec<(&'static str, Option<String>)>);

    impl Receiver for Recorder {
        fn take(&mut self, name: &'static str, value: Option<&str>) -> Result<(), String> {
            if value == Some("bad") {
                return Err("refused \"bad\"".to_owned());
            }
            self.0.push((name, value.map(str::to_owned)));
            Ok(())
        }
    }

    type Events = Vec<(&'static str, Option<String>)>;

    fn parse_with(parser: &Parser, arguments: &[&str]) -> (Result<Vec<String>, Stop>, Events) {
        let arguments: Vec<String> = arguments.iter().map(|&a| a.to_owned()).collect();
        let mut recorder = Recorder::default();
        let result = parser.parse(&arguments, &mut recorder);
        (result, recorder.0)
    }

    fn parse(arguments: &[&str]) -> (Result<Vec<String>, Stop>, Events) {
        let parser = Parser::new(
            &[Spec::one("--layer"), Spec::flag("--dry-run")],
            &[Spec::optional("operation")],
        );
        parse_with(&parser, arguments)
    }

    fn taken(pairs: &[(&'static str, Option<&str>)]) -> Events {
        pairs
            .iter()
            .map(|&(name, value)| (name, value.map(str::to_owned)))
            .collect()
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|&value| value.to_owned()).collect()
    }

    fn usage(code: ErrorCode, message: &str) -> Result<Vec<String>, Stop> {
        Err(Stop::Usage(code, message.to_owned()))
    }

    #[test]
    fn options_and_positionals_are_consumed_in_order() {
        let (result, events) = parse(&["--layer", "a", "start", "--dry-run", "--layer=-b"]);
        assert_eq!(result, Ok(Vec::new()));
        assert_eq!(
            events,
            taken(&[
                ("--layer", Some("a")),
                ("operation", Some("start")),
                ("--dry-run", None),
                ("--layer", Some("-b")),
            ])
        );
        let (result, events) = parse(&["--dry-run"]);
        assert_eq!(result, Ok(Vec::new()));
        assert_eq!(events, taken(&[("--dry-run", None), ("operation", None)]));
        let (_, events) = parse(&["--layer=a=b", "--layer="]);
        assert_eq!(
            events[..2],
            taken(&[("--layer", Some("a=b")), ("--layer", Some(""))])
        );
    }

    #[test]
    fn values_that_look_like_options_need_the_attached_form() {
        let expected = usage(
            ErrorCode::ArgumentMissing,
            "argument --layer: expected one argument",
        );
        assert_eq!(parse(&["--layer", "-c"]).0, expected);
        assert_eq!(parse(&["--layer", "--", "x"]).0, expected);
        assert_eq!(parse(&["--layer"]).0, expected);
        assert_eq!(parse(&["--layer", "--dry-run"]).0, expected);
        for value in ["-1abc", "-.5x", "-", "-a b", ""] {
            let (result, events) = parse(&["--layer", value]);
            assert_eq!(result, Ok(Vec::new()), "{value:?}");
            assert_eq!(events[0], ("--layer", Some(value.to_owned())));
        }
        // Only ASCII digits start a negative number: the digits of other scripts, superscripts,
        // and Roman numerals do not, so such a value needs the attached form.
        for value in [
            "-\u{661}",
            "-.\u{665}",
            "-\u{ff15}0",
            "-\u{b2}",
            "-\u{216b}",
            "-.x",
        ] {
            assert_eq!(parse(&["--layer", value]).0, expected, "{value:?}");
            let (result, events) = parse(&[&format!("--layer={value}")]);
            assert_eq!(result, Ok(Vec::new()), "{value:?}");
            assert_eq!(events[0], ("--layer", Some(value.to_owned())));
        }
    }

    #[test]
    fn unknown_arguments_are_returned_for_the_caller() {
        let (result, events) = parse(&["--bogus", "run", "extra", "-x"]);
        assert_eq!(result, Ok(strings(&["--bogus", "extra", "-x"])));
        assert_eq!(events, taken(&[("operation", Some("run"))]));
        // A prefix of an option is unknown: options are not abbreviated.
        assert_eq!(parse(&["--dry"]).0, Ok(strings(&["--dry"])));
        let (result, events) = parse(&["run", "start", "--dry-run"]);
        assert_eq!(result, Ok(strings(&["start"])));
        assert_eq!(
            events,
            taken(&[("operation", Some("run")), ("--dry-run", None)])
        );
    }

    #[test]
    fn errors_end_the_parse_where_they_occur() {
        let invalid = |message| usage(ErrorCode::ArgumentInvalid, message);
        let (result, events) = parse(&["--layer", "a", "--layer", "bad", "--layer", "c"]);
        assert_eq!(result, invalid("argument --layer: refused \"bad\""));
        assert_eq!(events, taken(&[("--layer", Some("a"))]));
        assert_eq!(
            parse(&["--dry-run=1"]).0,
            invalid("argument --dry-run: ignored explicit argument \"1\"")
        );
        assert_eq!(
            parse(&["--help=x"]).0,
            invalid("argument -h/--help: ignored explicit argument \"x\"")
        );
        assert_eq!(
            parse(&["--layer", "a", "-h", "--layer", "bad"]).0,
            Err(Stop::Help)
        );
        assert_eq!(
            parse(&["--layer", "bad", "--help"]).0,
            invalid("argument --layer: refused \"bad\"")
        );
        // An unknown option before a positional leaves the positional to its parser.
        let (result, events) = parse(&["--bogus", "bad"]);
        assert_eq!(result, invalid("argument operation: refused \"bad\""));
        assert!(events.is_empty());
    }

    #[test]
    fn double_dashes_end_the_options() {
        let (result, events) = parse(&["--", "--layer"]);
        assert_eq!(result, Ok(Vec::new()));
        assert_eq!(events, taken(&[("operation", Some("--layer"))]));
        let (result, events) = parse(&["run", "--", "start"]);
        assert_eq!(result, Ok(strings(&["start"])));
        assert_eq!(events, taken(&[("operation", Some("run"))]));
        let (result, events) = parse(&["--layer=1", "--", "a", "--", "b"]);
        assert_eq!(result, Ok(strings(&["--", "b"])));
        assert_eq!(
            events,
            taken(&[("--layer", Some("1")), ("operation", Some("a"))])
        );
        let (result, events) = parse(&["--dry-run", "--"]);
        assert_eq!(result, Ok(Vec::new()));
        assert_eq!(events, taken(&[("--dry-run", None), ("operation", None)]));
        // The first `--` is no argument itself, wherever it is.
        let (result, _) = parse(&["run", "--dry-run", "--", "start"]);
        assert_eq!(result, Ok(strings(&["start"])));
    }

    #[test]
    fn required_positionals_must_be_given() {
        let parser = Parser::new(&[], &[Spec::one("PATH")]);
        let missing = usage(
            ErrorCode::ArgumentMissing,
            "the following arguments are required: PATH",
        );
        assert_eq!(parse_with(&parser, &[]).0, missing);
        let (result, events) = parse_with(&parser, &["policy.json", "more"]);
        assert_eq!(result, Ok(strings(&["more"])));
        assert_eq!(events, taken(&[("PATH", Some("policy.json"))]));
        assert_eq!(parse_with(&parser, &["-x"]).0, missing);
    }

    #[test]
    fn commands_split_after_the_options_before_them() {
        let parser = Parser::new(&[Spec::one("--root")], &[Spec::one("command")]);
        let split = |arguments: &[&str]| {
            let mut recorder = Recorder::default();
            let result = parser.split_command(&strings(arguments), &mut recorder);
            (result, recorder.0)
        };
        let (result, events) = split(&["--root", "/r", "--x", "sandbox", "--root", "y"]);
        assert_eq!(result, Ok((3, strings(&["--x"]))));
        assert_eq!(events, taken(&[("--root", Some("/r"))]));
        assert_eq!(split(&["--root=-r", "--", "-x"]).0, Ok((2, Vec::new())));
        let stop = |code, message: &str| Err(Stop::Usage(code, message.to_owned()));
        let expected_one = stop(
            ErrorCode::ArgumentMissing,
            "argument --root: expected one argument",
        );
        assert_eq!(split(&["--root", "-x", "sandbox"]).0, expected_one);
        assert_eq!(split(&["--root"]).0, expected_one);
        assert_eq!(
            split(&["--help=x", "sandbox"]).0,
            stop(
                ErrorCode::ArgumentInvalid,
                "argument -h/--help: ignored explicit argument \"x\""
            )
        );
        let required = stop(
            ErrorCode::ArgumentMissing,
            "the following arguments are required: command",
        );
        assert_eq!(split(&["--root", "/r"]).0, required);
        assert_eq!(split(&["--"]).0, required);
        assert_eq!(split(&["-h", "sandbox"]).0, Err(Stop::Help));
        assert_eq!(
            split(&["--root", "bad"]).0,
            stop(
                ErrorCode::ArgumentInvalid,
                "argument --root: refused \"bad\""
            )
        );
    }

    #[test]
    fn choices_are_quoted_with_rust_debug_formatting() {
        assert_eq!(
            invalid_choice("x", &["auto", "whp"]),
            "invalid choice: \"x\" (choose from \"auto\", \"whp\")"
        );
        assert_eq!(choice("whp", &["auto", "whp"]), Ok("whp"));
        assert!(choice("WHP", &["auto", "whp"]).is_err());
    }

    #[test]
    fn integers_are_ascii_decimal_digits_in_their_range() {
        assert_eq!(integer::<u32>("8", 1..=8), Ok(8));
        assert_eq!(integer::<u32>("0008", 1..=8), Ok(8));
        assert_eq!(integer::<u64>("0", 0..=u64::MAX), Ok(0));
        assert_eq!(
            integer::<u64>("18446744073709551615", 1..=u64::MAX),
            Ok(u64::MAX)
        );
        for value in [
            "",
            "9",
            "0",
            "+1",
            "-1",
            " 1",
            "1 ",
            "1_0",
            "1.0",
            "1e1",
            "0x1",
            "\u{661}",
            "\u{ff11}",
            "99999999999999999999",
        ] {
            assert_eq!(
                integer::<u32>(value, 1..=8),
                Err(format!(
                    "expected an ASCII decimal integer between 1 and 8, not {value:?}"
                )),
                "{value:?}"
            );
        }
    }

    #[test]
    fn usages_name_the_parser_on_one_line() {
        let compile = Syntax {
            command: "egress compile",
            arguments: "[-h] PATH",
            help: "options:\n  -h, --help  show this help message and exit",
        };
        assert_eq!(compile.prog(), "nvx-rs egress compile");
        assert_eq!(compile.usage(), "usage: nvx-rs egress compile [-h] PATH");
        assert_eq!(
            compile.help(),
            "usage: nvx-rs egress compile [-h] PATH\n\noptions:\n  -h, --help  show this help \
             message and exit"
        );
        compile.assert_lists(&[]);
        let top = Syntax {
            command: "",
            arguments: "[OPTIONS]",
            ..compile
        };
        assert_eq!(top.prog(), "nvx-rs");
        assert_eq!(top.usage(), "usage: nvx-rs [OPTIONS]");
    }
}
