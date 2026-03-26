use sequoia::openpgp::Result;

use sequoia::types::TrustThreshold;

use crate::Sq;
use crate::cli::key::approvals;
use crate::cli;
use crate::common::password;

pub fn dispatch(sq: Sq, command: approvals::Command)
                -> Result<()>
{
    match command {
        approvals::Command::List(c) => list(sq, c),
        approvals::Command::Update(c) => update(sq, c),
    }
}

fn list(sq: Sq, cmd: approvals::ListCommand) -> Result<()> {
    let o = &mut std::io::stdout();

    let cert =
        sq.resolve_cert(&cmd.cert, TrustThreshold::Full)?.0;
    let vcert = cert.with_policy(sq.policy(), sq.time())?;
    let userids = cmd.userids.resolve(&vcert)?
        .iter()
        .map(|u| u.userid().clone())
        .collect::<Vec<_>>();

    sq.sequoia.key_approvals_list()
        .userids(userids)
        .pending(cmd.pending)
        .list(cert, o)
}

fn update(
    sq: Sq,
    command: cli::key::approvals::UpdateCommand,
) -> Result<()> {

    let key = sq.resolve_cert(&command.cert, TrustThreshold::Full)?.0;
    let vcert = key.with_policy(sq.policy(), sq.time())?;
    let userids = command.userids.resolve(&vcert)?;

    let prompt = password::Prompt::new(&sq, true);

    let output = if let Some(sink) = command.output {
        let path = sink.path().map(Clone::clone);
        Some((sink.for_secrets().create_safe(&sq)?, path))
    } else {
        None
    };

    sequoia::key::approvals::update::update(
        &sq.sequoia,
        &vcert,
        userids.into_iter()
            .map(|u| u.userid().clone())
            .collect::<Vec<_>>(),
        command.add_by,
        command.add_authenticated,
        command.remove_all,
        command.remove_by,
        command.add_all,
        prompt,
        output
    )
}
