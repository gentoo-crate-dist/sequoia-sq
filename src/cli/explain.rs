//! Command-line parser for `sq explain`.

use clap::Parser;

#[derive(Debug, Parser)]
#[clap(
    name = "explain",
    about = "A dictionary that explains Sequoia terminology",
    long_about = "A dictionary that explains Sequoia terminology

Users who are unfamiliar with terms used by Sequoia in its \
documentation or command-line interface can use this command to find \
out more about these terms.
",
    subcommand_required = false,
    arg_required_else_help = true,
    disable_help_subcommand = true
)]
pub struct Command {
    #[clap(
        value_name = "TERMS",
        help = "Search the dictionary for these TERMS"
    )]
    pub explain_terms: Vec<String>
}
