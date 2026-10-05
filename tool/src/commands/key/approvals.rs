use sqz::openpgp::Result;

use sqz::types::TrustThreshold;

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
    cmd: cli::key::approvals::UpdateCommand,
) -> Result<()> {

    let cert = sq.resolve_cert(&cmd.cert, TrustThreshold::Full)?.0;
    let vcert = cert.with_policy(sq.policy(), sq.time())?;
    let userids = cmd.userids.resolve(&vcert)?
        .iter()
        .map(|u| u.userid().clone())
        .collect::<Vec<_>>();


    let output = if let Some(sink) = cmd.output {
        let path = sink.path().map(Clone::clone);
        Some((sink.for_secrets().create_safe(&sq)?, path))
    } else {
        None
    };

    let sequoia = &sq.sequoia;
    let prompt = password::PromptFactory::new(&sq, true);
    sequoia.key_approvals_update()
        .prompt(prompt)
        .userids(userids)
        .add_by(cmd.add_by)
        .remove_by(cmd.remove_by)
        .add_all(cmd.add_all)
        .add_authenticated(cmd.add_authenticated)
        .remove_all(cmd.remove_all)
        .update(
            cert,
            output)
}
